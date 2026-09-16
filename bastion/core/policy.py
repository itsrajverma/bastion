"""Risk levels, roles, and the default-deny policy.

The LLM decides *intent*; this module decides *capability*. Both the executor
(authoritative) and the CLI (advisory, for UX) consult it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

Risk = Literal["read", "write", "admin"]
Role = Literal["viewer", "operator", "admin"]

RISKS: tuple[Risk, ...] = get_args(Risk)
ROLES: tuple[Role, ...] = get_args(Role)

RISK_ORDER: dict[str, int] = {"read": 0, "write": 1, "admin": 2}

#: Which risk levels each role may invoke. Roles are strictly nested.
ROLE_RISKS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read"}),
    "operator": frozenset({"read", "write"}),
    "admin": frozenset({"read", "write", "admin"}),
}

#: Invariant 6: a fresh install exposes read-only tools only.
DEFAULT_ENABLED_RISKS: tuple[Risk, ...] = ("read",)

RISK_COLORS: dict[str, str] = {"read": "green", "write": "yellow", "admin": "red"}

RiskSet = "tuple[str, ...] | list[str] | frozenset[str] | set[str]"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


def is_risk(value: str) -> bool:
    return value in RISK_ORDER


def is_role(value: str) -> bool:
    return value in ROLE_RISKS


def validate_enabled_risks(values: list[str] | tuple[str, ...]) -> tuple[Risk, ...]:
    """Normalise and validate an ``enabled_risks`` list from config."""
    out: list[Risk] = []
    for v in values:
        if not is_risk(v):
            raise ValueError(f"unknown risk level {v!r}; expected one of {list(RISKS)}")
        risk: Risk = v  # type: ignore[assignment]
        if risk not in out:
            out.append(risk)
    if "read" not in out:
        # read is always implied; a config that enables write but not read is a mistake
        out.insert(0, "read")
    return tuple(out)


def role_allows(role: str, risk: str) -> bool:
    """Does the ceiling of this role permit this risk level?"""
    return risk in ROLE_RISKS.get(role, frozenset())


def risk_enabled(
    risk: str, enabled_risks: tuple[str, ...] | list[str] | frozenset[str] | set[str]
) -> bool:
    return risk in enabled_risks


def check(
    role: str,
    risk: str,
    enabled_risks: tuple[str, ...] | list[str] | frozenset[str] | set[str],
) -> PolicyDecision:
    """Default-deny check: both the role *and* the server config must allow the risk."""
    if not is_risk(risk):
        return PolicyDecision(False, f"unknown risk level {risk!r}")
    if not is_role(role):
        return PolicyDecision(False, f"unknown role {role!r}")
    if not risk_enabled(risk, enabled_risks):
        shown = sorted(enabled_risks, key=lambda r: RISK_ORDER.get(r, 99))
        return PolicyDecision(
            False,
            f"risk level {risk!r} is not enabled on this executor (enabled_risks={shown})",
        )
    if not role_allows(role, risk):
        return PolicyDecision(False, f"role {role!r} may not invoke {risk!r} tools")
    return PolicyDecision(True, "allowed")
