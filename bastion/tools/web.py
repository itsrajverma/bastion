"""nginx and certbot tools."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from bastion.core.errors import ValidationFailed
from bastion.tools import tool
from bastion.tools._context import require_certbot_email
from bastion.tools._exec import run_cmd
from bastion.tools._types import Domain, validate_domain


@tool(risk="read", plan="sudo nginx -t")
def nginx_test() -> str:
    """Validate the nginx configuration (nginx -t) without reloading anything."""
    result = run_cmd(["nginx", "-t"], sudo=True, timeout=20)
    return result.render()


def _certbot_plan(domain: str) -> str:
    email = require_certbot_email()
    return f"sudo certbot --nginx -d {domain} --non-interactive --agree-tos -m {email}"


def _check_domain(kwargs: Mapping[str, Any]) -> None:
    try:
        validate_domain(str(kwargs["domain"]))
    except ValueError as exc:
        raise ValidationFailed(str(exc)) from None


@tool(risk="write", approve=True, plan=_certbot_plan, verify_with="nginx_test")
def install_ssl(domain: Domain) -> str:
    """Obtain and install a Let's Encrypt certificate for a domain via certbot's nginx plugin.

    The domain must already point at this host. Requires operator approval.

    Args:
        domain: fully qualified domain name, lowercase, e.g. app.example.com.
    """
    email = require_certbot_email()
    result = run_cmd(
        [
            "certbot",
            "--nginx",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "-m",
            email,
        ],
        sudo=True,
        timeout=180,
    )
    return result.render()


install_ssl.validator(_check_domain)


@tool(risk="write", approve=True, plan="sudo certbot renew", verify_with="nginx_test")
def renew_ssl() -> str:
    """Renew every certificate that is due (certbot renew). Requires operator approval."""
    result = run_cmd(["certbot", "renew"], sudo=True, timeout=300)
    return result.render()
