"""``bastion`` command line: init, ask, tools, servers, audit, doctor.

Heavy modules (rich, httpx, the agent) are imported inside commands so that
``bastion --help`` stays fast.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import typer

from bastion import __version__

app = typer.Typer(
    name="bastion",
    help="An AI SRE that can't break production.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    # Plain click help/tracebacks: keeps `bastion --help` from importing rich (startup budget).
    rich_markup_mode=None,
    pretty_exceptions_enable=False,
)
servers_app = typer.Typer(
    help="Manage executor servers.", no_args_is_help=True, rich_markup_mode=None
)
audit_app = typer.Typer(
    help="Read the executor's audit log.", no_args_is_help=True, rich_markup_mode=None
)
app.add_typer(servers_app, name="servers")
app.add_typer(audit_app, name="audit")

PROVIDER_CHOICES = ("anthropic", "openai", "ollama")


def _utf8_streams() -> None:
    """Glyphs (✔ ✘ ◆) must never crash the CLI on a non-UTF-8 stdout (e.g. Windows pipes)."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or encoding == "utf8":
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - exotic streams
            pass


_utf8_streams()


def _version(value: bool) -> None:
    if value:
        typer.echo(f"bastion {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version, is_eager=True, help="Show version."
    ),
) -> None:
    """Bastion: plain English in, typed and approved actions out."""


def _fail(message: str, code: int = 1) -> None:
    typer.secho(f"✘ {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _console() -> Any:
    from rich.console import Console

    return Console()


# -- init ---------------------------------------------------------------------------------


@app.command()
def init(
    provider: str | None = typer.Option(None, help="anthropic | openai | ollama"),
    model: str | None = typer.Option(None, help="Model id (provider default if omitted)."),
    api_key_env: str | None = typer.Option(None, help="Env var holding the provider API key."),
    server: str | None = typer.Option(None, help="Name for the executor server, e.g. prod."),
    url: str | None = typer.Option(None, help="Executor URL, e.g. http://127.0.0.1:8710"),
    token: str | None = typer.Option(None, help="Executor token from install.sh."),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Never prompt."),
) -> None:
    """Create ~/.bastion/config.yaml (chmod 600) interactively."""
    from bastion.agent.providers import DEFAULT_KEY_ENV, DEFAULT_MODELS
    from bastion.cli.config import CliConfig, ServerEntry, config_path, load_config, save_config

    path = config_path()
    existing: CliConfig | None = None
    if path.exists():
        try:
            existing = load_config(path)
        except Exception:
            existing = None

    def ask(label: str, default: str | None, value: str | None, *, secret: bool = False) -> str:
        if value is not None:
            return value
        if non_interactive:
            if default is None:
                _fail(f"--{label.replace(' ', '-')} is required with --non-interactive")
            return default or ""
        return str(typer.prompt(label, default=default, hide_input=secret, show_default=not secret))

    provider = ask("provider", existing.provider if existing else "anthropic", provider).lower()
    if provider not in PROVIDER_CHOICES:
        _fail(f"provider must be one of {', '.join(PROVIDER_CHOICES)}")
    model = ask(
        "model",
        existing.model if existing and existing.provider == provider else DEFAULT_MODELS[provider],
        model,
    )
    key_env_default = existing.api_key_env if existing else DEFAULT_KEY_ENV[provider] or "NONE"
    api_key_env = ask("api key env var (NONE for ollama)", key_env_default, api_key_env)
    if api_key_env.upper() == "NONE":
        api_key_env = ""
    server = ask("server name", existing.default_server if existing else "prod", server)
    prev = existing.servers.get(server) if existing else None
    url = ask("executor url", prev.url if prev else "http://127.0.0.1:8710", url)
    token = ask("executor token", prev.token if prev else None, token, secret=True)

    servers = dict(existing.servers) if existing else {}
    servers[server] = ServerEntry(url=url, token=token)
    config = CliConfig(
        provider=provider,
        model=model,
        api_key_env=api_key_env,
        base_url=existing.base_url if existing else None,
        default_server=server,
        servers=servers,
        max_calls=existing.max_calls if existing else 10,
        max_seconds=existing.max_seconds if existing else 120,
    )
    written = save_config(config, path)
    typer.secho(f"✔ wrote {written} (mode 600)", fg=typer.colors.GREEN)
    if api_key_env and not os.environ.get(api_key_env):
        typer.secho(
            f"  note: ${api_key_env} is not set in this shell; export it before `bastion ask`.",
            fg=typer.colors.YELLOW,
        )
    typer.echo("  next: bastion doctor")


# -- ask ----------------------------------------------------------------------------------


@app.command()
def ask(
    prompt: str = typer.Argument(..., help="What you want to know or do, in plain English."),
    server: str | None = typer.Option(None, "--server", "-s", help="Server name from config."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show plans; never execute writes."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable event stream."),
    max_calls: int | None = typer.Option(None, "--max-calls", help="Tool-call budget (1-50)."),
    max_seconds: int | None = typer.Option(None, "--max-seconds", help="Wall-time budget (5-900)."),
) -> None:
    """Diagnose or act: read tools run freely, writes wait for your approval."""
    from bastion.agent.client import ExecutorClient
    from bastion.agent.loop import LoopConfig, run_ask
    from bastion.agent.providers import make_provider
    from bastion.cli.config import load_config
    from bastion.core.errors import BastionError

    try:
        config = load_config()
        name, entry = config.server(server)
        loop_config = LoopConfig(
            max_calls=max_calls or config.max_calls,
            max_seconds=float(max_seconds or config.max_seconds),
            dry_run=dry_run,
        )
    except (BastionError, ValueError) as exc:
        _fail(str(exc))
        return

    ui: Any
    if json_out:
        from bastion.cli.ui import JsonUI

        ui = JsonUI(name, config.model)
    else:
        from bastion.cli.ui import RichUI

        ui = RichUI(name, config.model)

    try:
        provider = make_provider(
            config.provider,
            config.model,
            api_key_env=config.api_key_env,
            base_url=config.base_url,
        )
        executor = ExecutorClient(entry.url, entry.token)
        result = run_ask(prompt, provider, executor, ui, loop_config)
    except BastionError as exc:
        ui.error(exc.message)
        raise typer.Exit(1) from None
    except KeyboardInterrupt:
        ui.error("cancelled")
        raise typer.Exit(130) from None

    ui.diagnosis(result.text)
    if json_out:
        ui.emit(
            "done",
            stop_reason=result.stop_reason,
            calls=[c.name for c in result.calls],
            elapsed=round(result.elapsed, 2),
        )
    raise typer.Exit(0 if result.stop_reason == "final" else 2)


# -- tools ----------------------------------------------------------------------------------


@app.command()
def tools(
    denied: bool = typer.Option(False, "--denied", help="List what Bastion can never do."),
    server: str | None = typer.Option(None, "--server", "-s"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """List the tools enabled for you on the executor."""
    import json

    from bastion.core.policy import NEVER_ACTIONS

    if denied:
        if json_out:
            typer.echo(json.dumps({"never": list(NEVER_ACTIONS)}, indent=2))
            return
        typer.secho("Bastion will never:", bold=True)
        for item in NEVER_ACTIONS:
            typer.echo(f"  ✘ {item}")
        typer.echo("\nThese are not disabled features; the code paths do not exist.")
        return

    from rich.table import Table

    from bastion.core.errors import BastionError
    from bastion.core.policy import RISK_COLORS

    try:
        catalog = _executor(server).tools()
    except BastionError as exc:
        _fail(exc.message)
        return
    if json_out:
        typer.echo(
            json.dumps(
                {
                    "user": catalog.user,
                    "role": catalog.role,
                    "enabled_risks": list(catalog.enabled_risks),
                    "tools": [
                        {
                            "name": t.name,
                            "risk": t.risk,
                            "approve": t.approve,
                            "description": t.description,
                        }
                        for t in catalog.tools
                    ],
                },
                indent=2,
            )
        )
        return
    table = Table(
        title=(
            f"tools for {catalog.user} ({catalog.role}) · "
            f"enabled: {', '.join(catalog.enabled_risks)}"
        ),
        show_lines=False,
    )
    table.add_column("tool", style="bold")
    table.add_column("risk")
    table.add_column("approval")
    table.add_column("summary")
    for t in catalog.tools:
        color = RISK_COLORS.get(t.risk, "white")
        table.add_row(
            t.name,
            f"[{color}]{t.risk}[/{color}]",
            "yes" if t.approve else "no",
            t.description.split(". ")[0][:80],
        )
    _console().print(table)


# -- servers ----------------------------------------------------------------------------------


@servers_app.command("list")
def servers_list() -> None:
    """Show configured servers."""
    from bastion.cli.config import load_config
    from bastion.core.errors import BastionError

    try:
        config = load_config()
    except BastionError as exc:
        _fail(exc.message)
        return
    for name, entry in config.servers.items():
        mark = "*" if name == config.default_server else " "
        typer.echo(f"{mark} {name:<16} {entry.url}")


@servers_app.command("add")
def servers_add(
    name: str = typer.Argument(...),
    url: str = typer.Option(..., "--url"),
    token: str = typer.Option(..., "--token"),
    default: bool = typer.Option(False, "--default", help="Make this the default server."),
) -> None:
    """Add or update a server."""
    from bastion.cli.config import CliConfig, ServerEntry, config_path, load_config, save_config
    from bastion.core.errors import BastionError

    path = config_path()
    try:
        config = load_config(path) if path.exists() else CliConfig()
    except BastionError as exc:
        _fail(exc.message)
        return
    config.servers[name] = ServerEntry(url=url, token=token)
    if default or config.default_server is None:
        config.default_server = name
    save_config(config, path)
    typer.secho(f"✔ saved server {name}", fg=typer.colors.GREEN)


@servers_app.command("remove")
def servers_remove(name: str = typer.Argument(...)) -> None:
    """Remove a server."""
    from bastion.cli.config import load_config, save_config
    from bastion.core.errors import BastionError

    try:
        config = load_config()
    except BastionError as exc:
        _fail(exc.message)
        return
    if name not in config.servers:
        _fail(f"unknown server {name!r}")
    del config.servers[name]
    if config.default_server == name:
        config.default_server = next(iter(config.servers), None)
    save_config(config)
    typer.secho(f"✔ removed server {name}", fg=typer.colors.GREEN)


# -- audit ------------------------------------------------------------------------------------


@audit_app.command("tail")
def audit_tail(
    n: int = typer.Option(20, "-n", "--lines", min=1, max=1000),
    server: str | None = typer.Option(None, "--server", "-s"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show the last N audit records from the executor and verify the hash chain."""
    import json

    from rich.table import Table

    from bastion.core.errors import BastionError

    try:
        data = _executor(server).audit(n)
    except BastionError as exc:
        _fail(exc.message)
        return
    if json_out:
        typer.echo(json.dumps(data, indent=2))
        return
    table = Table(title=f"audit · last {n} of {data.get('total', '?')} records")
    for col in ("ts", "user", "tool", "status", "plan", "hash"):
        table.add_column(col)
    for rec in data.get("records", []):
        status = str(rec.get("status", "ok"))
        table.add_row(
            str(rec.get("ts", ""))[:19],
            str(rec.get("user", "")),
            str(rec.get("tool", "")),
            f"[green]{status}[/green]" if status == "ok" else f"[red]{status}[/red]",
            str(rec.get("plan", ""))[:60],
            str(rec.get("hash", ""))[:12],
        )
    console = _console()
    console.print(table)
    if data.get("verified"):
        console.print(f"[green]✔ hash chain verified ({data.get('total', 0)} records)[/green]")
    else:
        console.print(f"[red]✘ hash chain BROKEN: {data.get('verify_reason', '')}[/red]")
        raise typer.Exit(3)


# -- doctor -------------------------------------------------------------------------------------


@app.command()
def doctor(server: str | None = typer.Option(None, "--server", "-s")) -> None:
    """Check config, provider key, executor reachability, and token role."""
    from bastion.agent.client import ExecutorClient
    from bastion.cli.config import config_path, load_config, permissions_ok
    from bastion.core.errors import BastionError

    ok = True

    def report(good: bool, message: str) -> None:
        nonlocal ok
        ok = ok and good
        typer.secho(("✔ " if good else "✘ ") + message, fg="green" if good else "red")

    path = config_path()
    try:
        config = load_config(path)
    except BastionError as exc:
        report(False, exc.message)
        raise typer.Exit(1) from None
    report(True, f"config: {path}")
    report(permissions_ok(path), "config permissions are 600 (private)")

    if config.api_key_env:
        report(
            bool(os.environ.get(config.api_key_env)), f"provider key: ${config.api_key_env} is set"
        )
    else:
        report(True, f"provider {config.provider} needs no API key")
    report(True, f"provider: {config.provider} · model: {config.model}")

    try:
        name, entry = config.server(server)
    except BastionError as exc:
        report(False, exc.message)
        raise typer.Exit(1) from None
    client = ExecutorClient(entry.url, entry.token, timeout=10)
    try:
        health = client.health()
        report(True, f"executor {name} reachable at {entry.url} (v{health.get('version', '?')})")
        if str(health.get("version")) != __version__:
            report(
                False, f"version mismatch: cli {__version__} vs executor {health.get('version')}"
            )
    except BastionError as exc:
        report(False, f"executor {name}: {exc.message}")
        raise typer.Exit(1) from None
    try:
        catalog = client.tools()
        report(
            True,
            f"token accepted: user={catalog.user} role={catalog.role} "
            f"enabled_risks={','.join(catalog.enabled_risks)} tools={len(catalog.tools)}",
        )
    except BastionError as exc:
        report(False, f"token rejected: {exc.message}")
    try:
        audit = client.audit(1)
        report(
            bool(audit.get("verified")), f"audit chain verified ({audit.get('total', 0)} records)"
        )
    except BastionError as exc:
        report(False, f"audit: {exc.message}")
    raise typer.Exit(0 if ok else 1)


# -- helpers --------------------------------------------------------------------------------------


def _executor(server: str | None) -> Any:
    from bastion.agent.client import ExecutorClient
    from bastion.cli.config import load_config

    config = load_config()
    _, entry = config.server(server)
    return ExecutorClient(entry.url, entry.token)


def main() -> None:  # pragma: no cover - console entry
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
