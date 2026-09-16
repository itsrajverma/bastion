"""nginx and certbot tools."""

from __future__ import annotations

from bastion.tools import tool
from bastion.tools._exec import run_cmd


@tool(risk="read", plan="sudo nginx -t")
def nginx_test() -> str:
    """Validate the nginx configuration (nginx -t) without reloading anything."""
    result = run_cmd(["nginx", "-t"], sudo=True, timeout=20)
    return result.render()
