"""Role x risk matrix and default-deny behaviour (invariants 6 and 8)."""

from __future__ import annotations

import pytest

from bastion.core import policy

MATRIX = [
    # role, risk, allowed
    ("viewer", "read", True),
    ("viewer", "write", False),
    ("viewer", "admin", False),
    ("operator", "read", True),
    ("operator", "write", True),
    ("operator", "admin", False),
    ("admin", "read", True),
    ("admin", "write", True),
    ("admin", "admin", True),
]


@pytest.mark.parametrize(("role", "risk", "allowed"), MATRIX)
def test_role_risk_matrix(role: str, risk: str, allowed: bool) -> None:
    assert policy.role_allows(role, risk) is allowed
    decision = policy.check(role, risk, ("read", "write", "admin"))
    assert decision.allowed is allowed
    assert bool(decision) is allowed


@pytest.mark.parametrize("role", policy.ROLES)
@pytest.mark.parametrize("risk", ["write", "admin"])
def test_default_config_denies_everything_but_read(role: str, risk: str) -> None:
    """Invariant 6: with the default enabled_risks only read tools are reachable,
    regardless of how powerful the role is."""
    decision = policy.check(role, risk, policy.DEFAULT_ENABLED_RISKS)
    assert not decision.allowed
    assert "not enabled" in decision.reason


def test_default_enabled_risks_is_read_only() -> None:
    assert policy.DEFAULT_ENABLED_RISKS == ("read",)


def test_unknown_role_and_risk_denied() -> None:
    assert not policy.check("superuser", "read", ("read",)).allowed
    assert not policy.check("admin", "nuke", ("read", "write", "admin")).allowed
    assert not policy.role_allows("", "read")


def test_enabled_but_role_too_low() -> None:
    d = policy.check("viewer", "write", ("read", "write"))
    assert not d.allowed
    assert "viewer" in d.reason


def test_validate_enabled_risks_normalises() -> None:
    assert policy.validate_enabled_risks(["write"]) == ("read", "write")
    assert policy.validate_enabled_risks(["read", "read", "admin"]) == ("read", "admin")
    with pytest.raises(ValueError, match="unknown risk level"):
        policy.validate_enabled_risks(["read", "shell"])


def test_risk_order_and_colors_cover_all_risks() -> None:
    for risk in policy.RISKS:
        assert risk in policy.RISK_ORDER
        assert risk in policy.RISK_COLORS
    assert policy.RISK_COLORS == {"read": "green", "write": "yellow", "admin": "red"}
