# Demo: a real executor session

Recorded on 2026-09-16 against a locally running `bastion-executor` (v0.1.0) installed with
`pip install -e ".[executor]"` and started with `enabled_risks: [read]`:

```yaml
bind: 127.0.0.1:8710
enabled_risks: [read]
tokens:
  admin: { token: "<64 hex chars>", role: admin }
postgres_dsn: null
certbot_email: null
audit_path: ./demo/audit.jsonl
```

Everything below (the executor, policy, validation, audit chain, redaction, the Rich UI) is real.
**No LLM API key was available on the build machine, so the `bastion ask` transcripts use the
recorded provider fixtures from `tests/fixtures/` in place of a live model** (the same mechanism
the offline test-suite uses). The tool results inside those transcripts come from the live host.

## Laptop setup

```text
$ bastion init --non-interactive --provider anthropic --server local --url http://127.0.0.1:8710 --token <token>
✔ wrote ~/.bastion/config.yaml (mode 600)
  next: bastion doctor

$ bastion doctor
✔ config: ~/.bastion/config.yaml
✔ config permissions are 600 (private)
✔ provider key: $ANTHROPIC_API_KEY is set
✔ provider: anthropic · model: claude-sonnet-4-6
✔ executor local reachable at http://127.0.0.1:8710 (v0.1.0)
✔ token accepted: user=admin role=admin enabled_risks=read tools=13
✔ audit chain verified (1 records)
```

## What the executor exposes with the default config

```text
$ bastion tools
                    tools for admin (admin) · enabled: read
┌───────────────────┬──────┬──────────┬───────────────────────────────────────┐
│ tool              │ risk │ approval │ summary                               │
├───────────────────┼──────┼──────────┼───────────────────────────────────────┤
│ ask_user          │ read │ no       │ Ask the human operator a clarifying   │
│                   │      │          │ question when the request is ambiguous│
│ connections       │ read │ no       │ Summarise TCP connection counts by    │
│                   │      │          │ state (established, time-wait, ...)   │
│ db_active_queries │ read │ no       │ List non-idle PostgreSQL backends:    │
│                   │      │          │ pid, user, state, wait event, age, …  │
│ db_locks          │ read │ no       │ Show PostgreSQL lock chains …         │
│ disk_usage        │ read │ no       │ Show used/free space and percent …    │
│ io_top            │ read │ no       │ List processes doing the most disk I/O│
│ load_avg          │ read │ no       │ Show 1/5/15-minute load average, CPU  │
│                   │      │          │ count, and memory/swap headroom       │
│ memory            │ read │ no       │ Show RAM and swap usage in detail …   │
│ nginx_test        │ read │ no       │ Validate the nginx configuration …    │
│ process_detail    │ read │ no       │ Show details for one process …        │
│ service_logs      │ read │ no       │ Fetch the most recent journal lines … │
│ service_status    │ read │ no       │ Show whether a systemd service is …   │
│ top_processes     │ read │ no       │ List the processes using the most CPU │
└───────────────────┴──────┴──────────┴───────────────────────────────────────┘
```

Even the `admin` token sees no write or admin tools until the server config says so (invariant 6).

```text
$ bastion tools --denied
Bastion will never:
  ✘ run an arbitrary shell command (no bash/exec/run_command tool exists)
  ✘ delete, move, or overwrite files (rm, mv, truncate, > redirection)
  ✘ write to any path outside /var/log/bastion (the audit log)
  ✘ read secrets: .env*, *.pem, *.key, id_rsa*, /etc/shadow, /etc/sudoers*
  ✘ kill -9 / SIGKILL any process (only SIGTERM, with a protected list)
  ✘ signal root- or postgres-owned processes, sshd, systemd, dockerd, nginx/gunicorn masters
  ✘ signal a process younger than 30 seconds
  ✘ terminate non-client PostgreSQL backends or replication connections
  ✘ DROP, TRUNCATE, DELETE, UPDATE, or read table rows in PostgreSQL
  ✘ docker rm / docker kill / docker system prune
  ✘ edit nginx, systemd, sudoers, firewall, or cron configuration
  ✘ reboot or shut down the host
  ✘ remove, purge, or downgrade packages (install is a closed catalog, admin-only, approved)
  ✘ install a package outside the fixed catalog, add a repository, or pass apt flags
  ✘ change users, passwords, SSH keys, or permissions
  ✘ execute any write or admin tool without a human typing 'y'
  ✘ call any network service other than the configured LLM provider and executor

These are not disabled features; the code paths do not exist.
```

## Raw executor API

A read tool runs and is audited:

```text
$ curl -s -H "Authorization: Bearer <token>" -H 'content-type: application/json' \
       -X POST localhost:8710/run -d '{"tool":"load_avg"}'
{"tool":"load_avg","risk":"read","plan":"cat /proc/loadavg; nproc; free -m",
 "result":"load: 1m=0.00 5m=0.00 15m=0.00 (cpus=8, per-cpu-1m=0.00)\nmemory: total=24299MB used=11802MB available=12497MB percent=48.6\nswap: total=1536MB used=61MB percent=4.0",
 "result_hash":"572ba13b0eb76fda25df5d7f60016a0d7e6372a72d0930e6f5b998b5f101544b",
 "audit_hash":"960a1b19f7945ceaa9db0c56655ad48fc26f9fa0657d0be3e0bab3aa58c1a6f6","elapsed_ms":0}
```

A write tool is refused by policy before validation or execution (the same token, same executor):

```text
$ curl -s -H "Authorization: Bearer <token>" -H 'content-type: application/json' \
       -X POST localhost:8710/run -d '{"tool":"restart_service","args":{"service":"nginx"}}'
{"error":"policy_denied","message":"risk level 'write' is not enabled on this executor (enabled_risks=['read'])"}
```

## Audit trail

```text
$ bastion audit tail -n 5
                          audit · last 5 of 2 records
┌─────────────────┬───────┬──────────┬────────┬────────────────┬──────────────┐
│ ts              │ user  │ tool     │ status │ plan           │ hash         │
├─────────────────┼───────┼──────────┼────────┼────────────────┼──────────────┤
│ 2026-09-16T03:… │ admin │ load_avg │ ok     │ cat            │ 40eb4a7812a7 │
│                 │       │          │        │ /proc/loadavg; │              │
│                 │       │          │        │ nproc; free -m │              │
│ 2026-09-16T03:… │ admin │ load_avg │ ok     │ cat            │ 960a1b19f794 │
│                 │       │          │        │ /proc/loadavg; │              │
│                 │       │          │        │ nproc; free -m │              │
└─────────────────┴───────┴──────────┴────────┴────────────────┴──────────────┘
✔ hash chain verified (2 records)
```

## `bastion ask` (recorded provider, live executor)

### Read-only question (real host data)

```text
$ bastion ask "what's using the most CPU?"
◆ bastion · local · claude-sonnet-4-6 (recorded)
• top_processes  limit=5  ✔ PID USER           CPU%   MEM%  ELAPSED  COMMAND  (2.0s)
┌───────────────────────────────────────── Diagnosis ──────────────────────────────────────────┐
│ Diagnosis: nothing is saturating the CPU; the top process is python at a few percent. Load   │
│ is well below the core count.                                                                │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Ambiguous request → `ask_user` → write refused by a read-only executor

```text
$ bastion ask "restart the app"
◆ bastion · local · claude-sonnet-4-6 (recorded)
┌────────────────────────────────────────── Question ──────────────────────────────────────────┐
│ Which service do you mean: gunicorn, celery, or nginx?                                       │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
Answer: gunicorn
I will restart gunicorn as you asked.
• restart_service  service=gunicorn  ✘ tool 'restart_service' is not available on this executor  (0.0s)
┌───────────────────────────────────────── Diagnosis ──────────────────────────────────────────┐
│ I could not restart gunicorn: this executor only enables read tools, so restart_service is   │
│ not available. An operator can add write to enabled_risks in /etc/bastion/config.yaml, or    │
│ run sudo systemctl restart gunicorn manually.                                                │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

The model never received `restart_service` in its tool list (the executor filtered it), so the
loop reported the call as unavailable and nothing ran. With `enabled_risks: [read, write]` the
same request would instead produce a **Proposed action** panel with `sudo systemctl restart gunicorn`
and wait for `y/N/explain`; see the transcript in [README.md](../README.md).

## Reproducing with a live model

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # or OPENAI_API_KEY / a local ollama
bastion init                               # provider, model, server url + token
bastion ask "what's using the most CPU?"
```
