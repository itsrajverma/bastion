# Architecture

Bastion is two processes and one trust boundary.

```
laptop (untrusted network, trusted human)          server (trusted host, untrusted inputs)

bastion CLI ──── ssh -L 8710:localhost:8710 ────▶ bastion-executor  127.0.0.1:8710
   │                                                    │
   ├─ cli/main.py     Typer commands                    ├─ executor/main.py   FastAPI routes
   ├─ cli/ui.py       Rich panels / JSON events         ├─ executor/auth.py   bearer tokens, roles
   ├─ cli/config.py   ~/.bastion/config.yaml (600)      ├─ executor/config.py /etc/bastion/config.yaml
   ├─ agent/loop.py   tool-use loop, limits, approval   ├─ tools/            @tool registry
   ├─ agent/client.py executor HTTP client              │   ├─ system.py     psutil, /proc
   ├─ agent/prompts.py system prompt + playbooks        │   ├─ services.py   systemctl, journalctl
   └─ agent/providers anthropic | openai | ollama       │   ├─ web.py        nginx -t, certbot
            │                                           │   ├─ packages.py   closed apt catalog, install-only
            ▼                                           │   ├─ postgres.py   pg_stat_activity only
      LLM HTTPS API                                     │   ├─ process.py    SIGTERM + guard
                                                        │   └─ virtual.py    ask_user
                                                        └─ core/
                                                            ├─ policy.py     roles × risks, default deny
                                                            ├─ audit.py      hash-chained JSONL
                                                            ├─ redact.py     PII/secret patterns, fence
                                                            └─ errors.py     structured errors
```

## Request flow: `bastion ask "server is slow"`

1. **CLI** loads `~/.bastion/config.yaml`, builds a provider (`make_provider`) and an `ExecutorClient`.
2. **Loop** calls `GET /tools`. The executor returns only the tools the token's role may use *and* whose risk is in `enabled_risks` (default `[read]`). The tool list is converted to the provider's schema. `ask_user` is included as a virtual tool.
3. **LLM** receives the system prompt (rules + diagnosis playbook), the user prompt, and the tool schemas. It replies with text and zero or more tool calls.
4. For each tool call the loop:
   - rejects unknown tools (returned to the model as an error, never executed);
   - answers `ask_user` by prompting the operator;
   - for `approve=True` tools calls `POST /plan`, shows the exact command/SQL in a **Proposed action** panel, and asks `y/N/explain`. `explain` makes one tool-less LLM call for a justification, then re-asks. `--dry-run` shows the plan and returns a "not executed" result to the model;
   - calls `POST /run` (with `approved_plan_hash` for approved tools);
   - redacts, truncates, and fences the result before appending it as a tool result;
   - after a successful write, re-runs the tool's `verify_with` read tool and prints `✔ load 14.2 → 3.1`.
5. The loop stops on final text, `max_calls` (10), `max_seconds` (120), or Ctrl-C. The final text is rendered in the **Diagnosis** panel (or as a `final` JSON event).

## Executor request handling

```
request ─▶ auth (hmac.compare_digest over all tokens) ─▶ policy.check(role, risk, enabled_risks)
        ─▶ role ∈ spec.roles ─▶ spec.validate(args)  [pydantic extra=forbid + validators]
        ─▶ plan = spec.plan(kwargs)
        ─▶ /plan: return plan + sha256(plan)           (never executes)
        ─▶ /run:  approve ⇒ approved_plan_hash == sha256(plan) else 403
                  spec.run(kwargs) ─▶ redact ─▶ truncate ─▶ audit.append ─▶ response
```

Every error is a structured JSON body (`error`, `message`, optional `detail`); tracebacks never leave the process.

## The tool registry

`@tool(risk=..., approve=..., plan=..., verify_with=...)` turns a typed function into a `ToolSpec`:

- a Pydantic input model generated from the signature (`extra="forbid"`), with descriptions from the Google-style docstring;
- a JSON schema for providers;
- `plan(args)` rendering the exact command/SQL (a format string or a callable);
- `validators` that run after Pydantic on both `plan()` and `run()` (PID existence, protected targets, domain labels);
- roles derived from risk unless narrowed.

`bastion/tools/_exec.py:run_cmd` is the only process spawner: list-form argv, no shell, minimal environment, timeouts, `sudo -n` prefix when a rule exists. `bastion/tools/postgres.py:query` is the only SQL runner: four fixed statements, `%s` parameters, `statement_timeout`.

`bastion/tools/packages.py` is the only thing that changes installed software: a `CATALOG` dict (key -> fixed apt package tuple), `package_status` (dpkg-query, read) and `install_package` (admin). The install argv is `systemd-run --wait --pipe --collect --quiet --setenv=DEBIAN_FRONTEND=noninteractive --unit=bastion-apt-install-<key> /usr/bin/apt-get install -y <pkgs>`, preceded by an `apt-get update -q` under the same wrapper; PID 1 runs it outside the executor's read-only sandbox and the executor relays output and exit status. The same module renders the matching sudoers block (`--sudoers-apt`). See [INSTALLING_SOFTWARE.md](INSTALLING_SOFTWARE.md).

## Trust boundaries

| Boundary | Enforced by |
|---|---|
| LLM → loop | provider-neutral parsing; unknown tools refused; arguments passed through untouched to the executor for validation |
| loop → executor | bearer token + role; policy; validation; approval hash; audit |
| executor → host | `bastion` nologin user; systemd sandbox; literal-command sudoers (apt block generated from the catalog); `CAP_KILL`; guards in code and SQL; apt via `systemd-run` transient units |
| host → LLM | redaction + fence; no rows, no files |

## Configuration

- Server: `/etc/bastion/config.yaml` (`bind`, `enabled_risks`, `tokens`, `postgres_dsn`, `certbot_email`, `audit_path`, `allow_non_loopback_bind`). Unknown keys are rejected.
- Laptop: `~/.bastion/config.yaml` (`provider`, `model`, `api_key_env`, `base_url`, `default_server`, `servers`, `max_calls`, `max_seconds`), mode 600.

## Testing strategy

- Unit: policy matrix, redaction patterns, audit chain tamper cases, registry schema rules, process guard table.
- API: the real FastAPI app through `TestClient` for auth, default deny, validation, approval hash, guards, structured errors.
- Loop: a `ScriptedProvider` replaying recorded turns (`tests/fixtures/*.json`) against a `FakeExecutor` and against the real executor, including the full "install redis" flow (`tests/test_install_flow.py`).
- Providers: `httpx.MockTransport` wire-format assertions for all three providers, retries, and error sanitisation.
- Adversarial: 38 scenarios in `tests/adversarial/` with a worst-case operator; global invariants checked after every scenario, including that every `systemd-run` argv reaching sudo is one of the catalog's exact argvs.
- Deploy: `deploy/sudoers.bastion` is pinned to the catalog renderer, the installer embeds the unit verbatim, and no remove/purge rule can appear.
- CI: ruff, mypy `--strict` on `core` and `tools`, pytest on 3.10/3.11/3.12, a standalone `shell=True` grep job, and a stale-`docs/TOOLS.md` check.
