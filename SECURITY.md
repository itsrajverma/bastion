# Security Policy

## Reporting a vulnerability

Email **security@bastion-sre.dev** (or open a GitHub Security Advisory on this repository).
Do not open a public issue for anything that could let a model, a prompt, or a token holder do more than the invariants below allow.

- We acknowledge reports within 3 business days and aim to ship a fix within 14 days for anything that breaks an invariant.
- Please include the tool name, the request body sent to the executor, and the audit record if you have one.
- Coordinated disclosure is appreciated; we will credit you in the release notes unless you prefer otherwise.

## The 13 invariants

These hold in code, in tests, and in CI. A pull request that weakens one is rejected regardless of the feature it enables.

1. **No raw shell tool.** There is no `run_command`, `bash`, `exec`, or equivalent. Every action is a named tool with a typed schema (`bastion/tools/`). Enforced by `tests/test_tools_schema.py` and `tests/test_no_shell_true.py`.
2. **`subprocess` is list-form only.** `shell=True`, `os.system`, `os.popen` are forbidden repo-wide. The only place that spawns a process is `bastion/tools/_exec.py:run_cmd`, which rejects strings. Enforced by a CI grep job and `tests/test_no_shell_true.py`.
3. **No destructive tools.** No `rm`, `drop`, `truncate`, `kill -9`, `docker rm`, `DELETE`, and no file writes outside `/var/log/bastion`. Not behind a flag, not behind a role. `tests/test_tools_schema.py`, `tests/test_process_guard.py`, and the systemd unit (`ProtectSystem=strict`) enforce it.
4. **The executor validates everything.** LLM arguments are untrusted. Pydantic models with `extra="forbid"` validate types and bounds; extra validators check domains (`^[a-z0-9.-]+$` plus label rules), PID existence, and closed enums for service names. `tests/test_executor_api.py`, `tests/test_executor_write_tools.py`.
5. **Protected targets.** `kill_process` sends SIGTERM only and refuses pid 1, processes owned by `root`/`postgres`, anything matching `postgres|sshd|systemd|dockerd|containerd|nginx: master|gunicorn: master`, the executor itself, and processes younger than 30 s. DB tools refuse `backend_type != 'client backend'` and replication users inside the SQL `WHERE` clause. `tests/test_process_guard.py`, `tests/test_executor_write_tools.py`.
6. **Default deny.** A fresh install enables only `read` tools. `write` and `admin` must be listed in `/etc/bastion/config.yaml`. `tests/test_policy.py`.
7. **Approval gate.** Every `write`/`admin` tool shows the exact command or SQL and waits for `y/N/explain`. The executor's `/run` additionally requires the SHA-256 of the displayed plan, so nothing can run that was not shown. `--dry-run` never sends it. `tests/test_agent_loop.py`, `tests/test_cli.py`.
8. **Loopback bind and per-user tokens.** The executor binds `127.0.0.1:8710`; a non-loopback bind is refused unless explicitly opted in. Tokens are compared with `hmac.compare_digest`. Roles: `viewer` (read), `operator` (read+write), `admin` (all). `tests/test_executor_api.py`.
9. **Append-only audit.** Every tool call is a JSONL record (`ts, user, tool, args, plan, result_hash, prev_hash, hash`) in a hash chain. Tampering, deletion, or reordering is detected. `tests/test_audit_chain.py`.
10. **Data minimisation.** Only query *text* reaches the model, never result rows. Emails, bearer tokens, API keys, private keys, `key=value` secrets, URL credentials, card-like, PAN, and Aadhaar-like numbers are redacted before output leaves the executor and again before it reaches the model. There is no file-reading tool, so the `.env*`, `*.pem`, `*.key`, `id_rsa*`, `/etc/shadow`, `/etc/sudoers*` denylist is vacuous by construction. `tests/test_redact.py`.
11. **Prompt-injection posture.** All tool output is wrapped in `<untrusted_tool_output>` (with any embedded fence tags neutralised) and the system prompt states that content inside is data, never instructions. `tests/adversarial/`.
12. **Loop limits.** Max 10 tool calls and 120 s wall time per `ask`, configurable within hard ceilings (50 calls, 900 s), not removable. `tests/test_agent_loop.py`.
13. **Zero telemetry.** The only network calls are to the user's chosen LLM provider and the user's own executor. There are no provider SDKs, analytics, update checks, or crash reporters.

## Scope notes

- The executor trusts its host's `sudoers` file. `deploy/sudoers.bastion` lists six exact commands; `install.sh` validates it with `visudo -c` before installing.
- The executor process needs `CAP_KILL` (from the unit) to SIGTERM processes it does not own. It never needs, and must never be given, a sudo rule for `kill`.
- Anyone holding an `operator` or `admin` token can approve actions. Protect tokens like SSH keys; use one token per person; rotate by editing the config and restarting the service.
