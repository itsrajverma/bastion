# Contributing

Thanks for helping make Bastion useful without making it dangerous.

## Ground rules (policy, not preference)

- **Pull requests that add shell access, a generic command runner, or any destructive tool are rejected.** This includes "just for admins", "behind a flag", or "only in dev mode". See [SECURITY.md](SECURITY.md) for the 13 invariants; CI enforces several of them and reviewers enforce the rest.
- Adding a dependency needs a reason in the PR description. Provider SDKs are deliberately not used (plain `httpx`).
- Every tool must be typed, documented, have an explicit `plan()`, and be covered by tests. Read tools need a happy-path test; write tools need a guard test and an adversarial scenario.

## Development setup

```bash
git clone https://github.com/bastion-sre/bastion && cd bastion
uv venv && uv pip install -e ".[dev]"      # or: python -m venv .venv && pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy                                        # strict on bastion/core and bastion/tools
pytest                                      # offline; recorded LLM fixtures only
```

## Adding a tool

1. **Define it** in the right module under `bastion/tools/` with the `@tool` decorator:

   ```python
   from bastion.tools import tool
   from bastion.tools._exec import run_cmd
   from bastion.tools._types import Service


   @tool(risk="read", plan="systemctl list-timers --no-pager")
   def service_timers() -> str:
       """List systemd timers and when they fire next."""
       return run_cmd(["systemctl", "list-timers", "--no-pager"], timeout=10).render()
   ```

   - `risk` is `read`, `write`, or `admin`. Anything but `read` must set `approve=True`.
   - `plan` is a format string or a callable rendering the *exact* command/SQL. It is shown to the operator and hashed for approval.
   - Arguments must use constrained types from `bastion/tools/_types.py` (closed `Literal` enums, bounded ints, regex-constrained strings). Add a `.validator()` for checks that need host state (PID existence, protected targets).
   - Never call `subprocess` directly; use `run_cmd` with a list. Never build SQL with string formatting; use `%s` parameters.
   - Tool names must not contain `rm`, `delete`, `drop`, `truncate`, `exec`, `shell`, `command` (as segments); the decorator refuses them.

2. **sudoers** (only if the command needs root): add the exact command line to `deploy/sudoers.bastion` *and* to the generated block in `scripts/install.sh`. No wildcards in arguments; use sudo regex rules. Never add `kill`, `rm`, `sh`, or anything that takes a path.

3. **Tests**:
   - `tests/test_tools_schema.py` picks up the new tool automatically; make sure it passes.
   - Add a behaviour test (monkeypatch `run_cmd`/`query`).
   - For write tools, add an executor test (plan hash, guard) and at least one scenario in `tests/adversarial/test_injection_prompts.py` where the model misuses it.

4. **Docs**: regenerate and commit `docs/TOOLS.md`:

   ```bash
   python -m bastion.tools --docs > docs/TOOLS.md
   ```

   CI fails if the file is stale. Mention the tool in `README.md` if it changes what Bastion can or cannot do.

5. **Verification**: if the tool fixes something, set `verify_with="<read tool>"` so the CLI re-checks and prints a `✔ before → after` line.

## Adding a provider

Implement `bastion.agent.providers.base.Provider` over `HttpProvider`, convert to and from the neutral message types, add it to `make_provider`, and add a `httpx.MockTransport` test in `tests/test_providers.py`. No SDKs, no telemetry, no streaming of tool results outside the fence.

## Commit style

One logical change per commit; run `ruff`, `mypy`, and `pytest` before pushing. Security-relevant changes should explain which invariant they touch and why it still holds.
