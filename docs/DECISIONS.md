# Decisions

Choices made where the build spec was silent or where two requirements pulled in different directions.
Each entry states the decision and the reasoning so it can be revisited deliberately.

## D1. Providers speak raw HTTPS via `httpx`; no provider SDKs
The dependency list in the spec does not include `anthropic` or `openai` packages and asks that new
dependencies be discussed first. All three providers are implemented over `httpx` (already required),
which also keeps the zero-telemetry invariant trivially auditable and lets tests use `httpx.MockTransport`.
Trade-off: no SDK conveniences (retries are hand-rolled with bounded backoff; no streaming).
Revisit if the official SDK becomes a wanted dependency.

## D2. Default Anthropic model is `claude-sonnet-4-6`, as specified
The spec names it explicitly. Newer models exist; the model is a one-line config change (`bastion init`).
Requests omit the `thinking` parameter and forced `tool_choice`, which keeps the wire format valid across model generations.

## D3. `/run` requires the SHA-256 of the displayed plan for approval-gated tools
Invariant 7 is enforced in the CLI, but a CLI bug or a hand-written client could skip the prompt.
The executor therefore refuses `write`/`admin` runs unless `approved_plan_hash` equals `sha256(plan)`
for the *same* validated arguments. This binds "what the human saw" to "what runs" and costs one extra
`/plan` round-trip per action. `--dry-run` never sends the hash.

## D4. `kill_process` uses `os.kill(SIGTERM)` under `CAP_KILL`, not `sudo kill`
A sudoers rule such as `/bin/kill -TERM [0-9]*` is unsafe because sudoers globs match spaces
(`kill -TERM 1 -1`). Granting the unit `AmbientCapabilities=CAP_KILL` lets the guard in
`bastion/tools/process.py` be the only thing between a request and a signal, and leaves the sudoers
file with exactly six fixed commands. There is no SIGKILL code path.

## D5. sudoers uses regex argument rules (sudo >= 1.9.10) with a documented glob fallback
`certbot --nginx -d <domain> ...` needs a variable argument. Regex rules (`^...$`) prevent extra flags from
being appended. `install.sh` detects the sudo version; on older sudo it writes a glob and warns, relying on
the executor's `^[a-z0-9.-]+$` domain validation as the sole argument guard.

## D6. Non-loopback bind is refused unless `allow_non_loopback_bind: true`
Invariant 8 says loopback "by default". Silently accepting `0.0.0.0` in config would defeat the default,
so the executor refuses to start and points at the SSH-tunnel workflow unless the operator opts in explicitly.

## D7. Forbidden tool-name words are matched as underscore-separated segments
The spec forbids names matching `/(rm|delete|...)/i` and also requires `db_terminate_query`, which contains
the letters `rm`. The decorator and the test therefore match segments (`(^|_)(rm|delete|...)(_|$)`), which still
rejects `rm_files`, `exec_cmd`, `shell`, `run_command`, and adds `sudo`, `eval`, `purge`, `wipe`, `destroy`, `remove`.

## D8. Service names are a closed enum of four
`nginx`, `gunicorn`, `celery`, `postgresql` for `service_status`, `service_logs`, and `restart_service`.
A configurable list would be more flexible but would make the sudoers file dynamic. Extending the enum is a
one-line code change plus a sudoers line and a test, by design.

## D9. `load_avg` reads `/proc/loadavg`, `os.cpu_count()`, and `psutil` memory
Equivalent to `cat /proc/loadavg; nproc; free -m` (which the plan string shows) without spawning three processes,
and it degrades gracefully on non-Linux development machines. The first line is machine-parseable
(`load: 1m=… 5m=… 15m=…`) so the CLI can print `✔ load 14.2 → 3.1`.

## D10. Post-fix verification is declared per tool with `verify_with`
`restart_service → service_status`, `install_ssl`/`renew_ssl → nginx_test`, `kill_process`/`db_cancel_query`/
`db_terminate_query → load_avg`. The DB tools verify against load (the symptom the operator asked about) rather
than `db_active_queries`; the verification result is appended to the write tool's result so the model sees it too.
Verification counts toward the call budget.

## D11. Two small modules beyond the spec's layout
`bastion/agent/client.py` (executor HTTP client, shared by `ask`, `tools`, `audit`, `doctor`) and
`bastion/cli/config.py` (laptop config). Everything else follows the layout exactly.

## D12. Redaction happens twice
On the executor before the result leaves the host, and again in the loop before the fence. The second pass is
idempotent (markers are never re-redacted) and protects against a modified or older executor.

## D13. Audit records hash the *redacted* result and carry a `status` field
The spec lists `ts, user, tool, args, plan, result_hash, prev_hash`; `hash` (of the record) and `status`
(`ok`/`error`) are added. Failed runs are audited too. Result bodies are never stored.

## D14. `--json` approval and `ask_user` read one line from stdin
The JSON UI emits `approval_required` / `question` events and reads a line (`y`, `n`, `explain`, or the answer).
Empty or closed stdin means `n`, so unattended pipelines can never approve by accident.

## D15. Loop limits have hard ceilings
`max_calls` 1–50 and `max_seconds` 5–900 are enforced in `LoopConfig`; the defaults are 10 and 120.
Configurable, not removable (invariant 12).

## D16. PyPI distribution name is `bastion-sre`; the commands are `bastion` and `bastion-executor`
`bastion` is unlikely to be available on PyPI. The import package is still `bastion`.

## D17. `docs/TOOLS.md` renders plans with placeholders
Plans that embed executor config (`certbot_email`) are rendered with `<certbot_email>` so the generated file is
identical on every machine and CI can diff it.

## D18. Extra protected targets
Beyond the spec's list, `kill_process` also refuses pid 1, `containerd`, the executor's own pid, and process
*names* (not only command lines) that match. These are strictly more conservative.

## D19. Tool output is truncated at 20 000 characters (executor `max_result_chars`)
Keeps a 500-line journal or a wide process list inside the provider's context budget and bounds what a
hostile log can push into the conversation.

## D20. Tokens are at least 32 characters
The installer generates 64 hex characters; the config loader rejects shorter tokens so a weak hand-edited
token cannot be introduced by accident.
