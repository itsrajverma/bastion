"""Runtime context injected by the executor (DSNs, emails). Tools read it via
:func:`get_context`; nothing here is ever taken from LLM arguments."""

from __future__ import annotations

from dataclasses import dataclass

from bastion.core.errors import ConfigError


@dataclass(frozen=True, slots=True)
class ToolContext:
    postgres_dsn: str | None = None
    certbot_email: str | None = None


_context = ToolContext()


def get_context() -> ToolContext:
    return _context


def set_context(ctx: ToolContext) -> None:
    global _context
    _context = ctx


def require_postgres_dsn() -> str:
    dsn = _context.postgres_dsn
    if not dsn:
        raise ConfigError("postgres_dsn is not configured on this executor")
    return dsn


def require_certbot_email() -> str:
    email = _context.certbot_email
    if not email:
        raise ConfigError("certbot_email is not configured on this executor")
    return email
