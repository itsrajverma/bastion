"""systemd service tools. Service names are a closed enum (invariant 4)."""

from __future__ import annotations

from bastion.tools import tool
from bastion.tools._exec import run_cmd
from bastion.tools._types import LogLines, Service

_SHOW_PROPS = "ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp,Result"


@tool(
    risk="read",
    plan=f"systemctl is-active {{service}}; systemctl show {{service}} -p {_SHOW_PROPS}",
)
def service_status(service: Service) -> str:
    """Show whether a systemd service is active, its main pid, restart count, and start time.

    Args:
        service: one of nginx, gunicorn, celery, postgresql.
    """
    active = run_cmd(["systemctl", "is-active", service], timeout=10)
    show = run_cmd(
        ["systemctl", "show", service, "-p", _SHOW_PROPS, "--no-pager"],
        timeout=10,
    )
    lines = [f"service: {service}", f"is-active: {active.output() or active.returncode}"]
    lines.extend(line for line in show.output().splitlines() if line.strip())
    return "\n".join(lines)


@tool(risk="read", plan="journalctl -u {service} -n {lines} --no-pager -o short-iso")
def service_logs(service: Service, lines: LogLines = 100) -> str:
    """Fetch the most recent journal lines for a systemd service.

    Args:
        service: one of nginx, gunicorn, celery, postgresql.
        lines: how many lines to fetch (1-500).
    """
    result = run_cmd(
        ["journalctl", "-u", service, "-n", str(lines), "--no-pager", "-o", "short-iso"],
        timeout=20,
    )
    return result.render()
