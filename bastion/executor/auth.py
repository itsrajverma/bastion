"""Per-user bearer tokens compared with ``hmac.compare_digest`` (invariant 8)."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from bastion.core.errors import AuthError
from bastion.executor.config import ExecutorSettings


@dataclass(frozen=True, slots=True)
class Principal:
    name: str
    role: str


def parse_bearer(header: str | None) -> str:
    if not header:
        raise AuthError("missing Authorization header")
    scheme, _, token = header.strip().partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError("Authorization header must be 'Bearer <token>'")
    return token.strip()


def authenticate(settings: ExecutorSettings, authorization: str | None) -> Principal:
    """Resolve a bearer token to a principal. Every configured token is compared
    (no early exit) so timing does not reveal which user matched."""
    presented = parse_bearer(authorization).encode("utf-8")
    matched: Principal | None = None
    for name, entry in settings.tokens.items():
        if hmac.compare_digest(presented, entry.token.encode("utf-8")) and matched is None:
            matched = Principal(name=name, role=entry.role)
    if matched is None:
        raise AuthError("invalid token")
    return matched
