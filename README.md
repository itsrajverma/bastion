# Bastion

**An AI SRE that can't break production.**

Type plain English. An LLM turns it into calls to a fixed set of typed, sandboxed tools.
Read-only tools run freely; write tools show the exact command and wait for your `y`; destructive tools do not exist.
The LLM decides *intent*; the OS and the policy engine decide *capability*.

```
$ bastion ask "server is slow, find out why"
◆ bastion · prod · claude-sonnet-4-6
• load_avg  ✔ load: 1m=14.20 5m=9.80 15m=4.11 (cpus=4, per-cpu-1m=3.55)  (0.1s)
• top_processes  limit=5  ✔ PID USER CPU% MEM% ELAPSED COMMAND  (0.6s)
postgres is the top consumer; looking at active queries.
• db_active_queries  limit=10  ✔ pid user state wait age query  (0.2s)
Root cause: pid 4242 has been running a full-table report query for 14 minutes.
I will cancel that query (gentlest option).
╭─────────────────────────── Proposed action ───────────────────────────╮
│ SELECT pg_cancel_backend(a.pid) AS done, a.pid, a.usename, a.state,    │
│        left(regexp_replace(a.query, '\s+', ' ', 'g'), 120) AS query    │
│ FROM pg_stat_activity a                                                │
│ WHERE a.pid = 4242                                                     │
│   AND a.backend_type = 'client backend'                                │
│   AND a.pid <> pg_backend_pid()                                        │
│   AND a.usename IS NOT NULL                                            │
│   AND a.usename NOT IN (SELECT rolname FROM pg_roles WHERE rolreplication) │
╰──────────────────────────────────── risk: WRITE · needs approval ─────╯
Approve? [y/N/explain] (n): y
• db_cancel_query  pid=4242  ✔ cancelled: True  (0.1s)
✔ load 14.20 → 3.10
╭──────────────────────────────── Diagnosis ─────────────────────────────╮
│ A 14-minute report query (pid 4242, user app) was saturating all four  │
│ CPUs. Cancelled it with pg_cancel_backend; 1-minute load fell from     │
│ 14.20 to 3.10. Consider a statement_timeout for the reporting role.    │
╰────────────────────────────────────────────────────────────────────────╯
```

`explain` at the prompt asks the model for a one-paragraph justification, then asks again.
`--dry-run` shows every plan and executes nothing. `--json` emits an event stream for scripts.

## 60-second install

**Server** (Ubuntu/Debian with systemd; runs as an unprivileged `bastion` user bound to `127.0.0.1:8710`):

```bash
curl -fsSL https://raw.githubusercontent.com/bastion-sre/bastion/main/scripts/install.sh | sudo bash
```

The installer prints a one-time admin token. The executor starts with `enabled_risks: [read]`.
To allow approval-gated actions, edit `/etc/bastion/config.yaml` (`enabled_risks: [read, write]`) and restart the service.

**Laptop:**

```bash
pipx install bastion-sre
ssh -L 8710:localhost:8710 user@server      # keep the tunnel open
export ANTHROPIC_API_KEY=...                # or OPENAI_API_KEY, or nothing for ollama
bastion init                                # provider, model, server url + token -> ~/.bastion/config.yaml (600)
bastion doctor
bastion ask "what's using the most CPU?"
```

## What it CAN do

| Tool | Risk | Approval | What runs |
|---|---|---|---|
| `load_avg`, `memory`, `disk_usage`, `top_processes`, `process_detail`, `io_top`, `connections` | read | no | `/proc`, `psutil`, `ss -s` |
| `service_status`, `service_logs` | read | no | `systemctl is-active/show`, `journalctl -u <svc> -n <lines>` |
| `nginx_test` | read | no | `sudo nginx -t` |
| `db_active_queries`, `db_locks` | read | no | `pg_stat_activity` metadata and query text, never rows |
| `restart_service(nginx\|gunicorn\|celery\|postgresql)` | write | **yes** | `sudo systemctl restart <svc>` |
| `install_ssl(domain)`, `renew_ssl` | write | **yes** | `sudo certbot --nginx -d <domain> ...`, `sudo certbot renew` |
| `db_cancel_query(pid)` | write | **yes** | `pg_cancel_backend` with guards baked into the SQL |
| `kill_process(pid)` | write | **yes** | SIGTERM only, protected-process list |
| `db_terminate_query(pid)` | admin | **yes** | `pg_terminate_backend` with guards baked into the SQL |
| `ask_user(question)` | virtual | n/a | asks you instead of guessing |

Full reference with every plan string: [docs/TOOLS.md](docs/TOOLS.md) (generated from the registry).

## What it can NEVER do

| Never | Why it is impossible, not just disabled |
|---|---|
| Run a shell command | There is no `bash`/`exec`/`run_command` tool; `shell=True` is banned by CI and a unit test |
| Delete, truncate, or overwrite files | No tool writes anywhere except the audit log in `/var/log/bastion` (systemd `ProtectSystem=strict`) |
| `kill -9`, signal root/postgres processes, sshd, systemd, dockerd, nginx/gunicorn masters, or anything younger than 30s | The guard is code, evaluated on `plan()` and `run()`; there is no SIGKILL path |
| `DROP`, `TRUNCATE`, `DELETE`, or read table rows | Only four fixed statements against `pg_stat_activity` exist; `%s` parameters, never string interpolation |
| Terminate replication or non-client backends | The `WHERE` clause refuses them; the LLM never sees the SQL until it is fixed |
| Read `.env*`, `*.pem`, `*.key`, `id_rsa*`, `/etc/shadow`, `/etc/sudoers*` | There is no file-reading tool at all |
| Run a write without a human | Executor `/run` demands the SHA-256 of the plan the CLI displayed; `--dry-run` never sends it |
| Reach the network | Only your LLM provider and your executor; zero telemetry |

`bastion tools --denied` prints this list from the code.

## Architecture

```
 laptop                                              server (127.0.0.1:8710 only)
 ┌───────────────────────────────┐                   ┌──────────────────────────────────┐
 │ bastion ask "..."             │                   │ bastion-executor (FastAPI)       │
 │  ├─ Rich / --json UI          │   ssh -L tunnel   │  ├─ bearer tokens, roles         │
 │  ├─ agent loop (≤10 calls,    │ ────────────────▶ │  ├─ policy: role × enabled_risks │
 │  │   ≤120 s, approval gate)   │  GET  /tools      │  ├─ pydantic validation + guards │
 │  └─ provider (anthropic |     │  POST /plan       │  ├─ tools: list-form subprocess, │
 │      openai | ollama, httpx)  │  POST /run        │  │   psutil, psycopg             │
 └───────────────┬───────────────┘  GET  /audit      │  ├─ redaction                    │
                 │                                   │  └─ hash-chained audit.jsonl     │
                 ▼                                   └──────────────┬───────────────────┘
        LLM API (query text and                                     │ user=bastion (nologin)
        redacted, fenced tool output only)                          │ sudoers: 6 exact commands
                                                                    ▼ systemd: ProtectSystem=strict
```

Tool output is redacted (emails, tokens, keys, card/PAN/Aadhaar-like numbers) and wrapped in
`<untrusted_tool_output>` before the model sees it. The system prompt says content inside the fence is data, never instructions.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Providers

| Provider | Default model | Key |
|---|---|---|
| `anthropic` (default) | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` |
| `openai` | `gpt-4o` | `OPENAI_API_KEY` |
| `ollama` | `llama3.1` | none (`base_url` in config, default `http://127.0.0.1:11434`) |

All three talk plain HTTPS through `httpx`; there are no provider SDKs and no telemetry.

## Security summary

Thirteen invariants hold in code, tests, and CI: no raw shell, list-form subprocess only, no destructive tools,
executor validates everything, protected targets, default deny, approval gate, loopback bind with per-user tokens,
append-only hash-chained audit, data minimisation, prompt-injection fencing, loop limits, zero telemetry.
They are enumerated in [SECURITY.md](SECURITY.md); the risk table is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
An adversarial suite (`tests/adversarial/`) replays 30+ hostile prompts and injected logs against the real executor
with an operator who approves everything, and asserts that only allow-listed programs ever run.

## Roadmap

- v0.2: `redis`, `docker ps/logs` read tools; per-server tool allow-lists in the CLI config.
- v0.3: multi-server incidents (`--server all`), Slack approval relay.
- Always: more read tools, never a shell.

## License

Apache-2.0. See [LICENSE](LICENSE).
