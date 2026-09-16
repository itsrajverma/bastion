"""Executor configuration: ``/etc/bastion/config.yaml`` (or ``$BASTION_CONFIG``)."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from bastion.core.errors import ConfigError
from bastion.core.policy import DEFAULT_ENABLED_RISKS, Risk, Role, validate_enabled_risks

DEFAULT_CONFIG_PATH = "/etc/bastion/config.yaml"
DEFAULT_BIND = "127.0.0.1:8710"
DEFAULT_AUDIT_PATH = "/var/log/bastion/audit.jsonl"
MIN_TOKEN_LENGTH = 32


class TokenEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=MIN_TOKEN_LENGTH, max_length=512)
    role: Role


class ExecutorSettings(BaseModel):
    """Validated executor settings. Unknown keys are rejected so typos cannot
    silently widen access."""

    model_config = ConfigDict(extra="forbid")

    bind: str = DEFAULT_BIND
    enabled_risks: tuple[Risk, ...] = DEFAULT_ENABLED_RISKS
    tokens: dict[str, TokenEntry] = Field(default_factory=dict)
    postgres_dsn: str | None = None
    certbot_email: str | None = None
    audit_path: str = DEFAULT_AUDIT_PATH
    #: Invariant 8: loopback only unless the operator explicitly opts out.
    allow_non_loopback_bind: bool = False
    max_result_chars: int = Field(default=20_000, ge=1_000, le=200_000)

    @field_validator("enabled_risks", mode="before")
    @classmethod
    def _risks(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return DEFAULT_ENABLED_RISKS
        if isinstance(value, str):
            value = [value]
        try:
            return validate_enabled_risks(list(value))
        except ValueError as exc:
            raise ValueError(str(exc)) from None

    @field_validator("tokens", mode="before")
    @classmethod
    def _tokens(cls, value: Any) -> Any:
        if value is None:
            return {}
        return value

    @field_validator("bind")
    @classmethod
    def _bind(cls, value: str) -> str:
        host, port = _split_bind(value)
        if not (0 < port < 65536):
            raise ValueError(f"port out of range in bind {value!r}")
        return f"{host}:{port}"

    @property
    def host(self) -> str:
        return _split_bind(self.bind)[0]

    @property
    def port(self) -> int:
        return _split_bind(self.bind)[1]

    @property
    def is_loopback(self) -> bool:
        host = self.host
        if host in ("localhost",):
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def check_bind_policy(self) -> None:
        if not self.is_loopback and not self.allow_non_loopback_bind:
            raise ConfigError(
                f"bind {self.bind!r} is not loopback; use an SSH tunnel "
                "(ssh -L 8710:localhost:8710 user@server) or set allow_non_loopback_bind: true"
            )


def _split_bind(value: str) -> tuple[str, int]:
    raw = value.strip()
    if raw.startswith("["):  # [::1]:8710
        host, _, rest = raw[1:].partition("]")
        port_str = rest.lstrip(":")
    else:
        host, _, port_str = raw.rpartition(":")
        if not host:
            raise ValueError(f"bind must be host:port, got {value!r}")
    try:
        return host, int(port_str)
    except ValueError:
        raise ValueError(f"bind must be host:port, got {value!r}") from None


def config_path() -> Path:
    return Path(os.environ.get("BASTION_CONFIG", DEFAULT_CONFIG_PATH))


def load_settings(path: str | Path | None = None) -> ExecutorSettings:
    """Load and validate settings. Raises :class:`ConfigError` with a clear message."""
    target = Path(path) if path is not None else config_path()
    if not target.exists():
        raise ConfigError(f"config file not found: {target}")
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {target} is not valid YAML: {exc}") from None
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {target} must be a YAML mapping")
    return settings_from_dict(raw)


def settings_from_dict(raw: dict[str, Any]) -> ExecutorSettings:
    try:
        settings = ExecutorSettings.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"invalid executor config: {problems}") from None
    settings.check_bind_policy()
    return settings


def render_config(
    *,
    admin_token: str,
    bind: str = DEFAULT_BIND,
    enabled_risks: tuple[str, ...] = DEFAULT_ENABLED_RISKS,
    audit_path: str = DEFAULT_AUDIT_PATH,
) -> str:
    """Render a fresh config file (used by the installer)."""
    doc = {
        "bind": bind,
        "enabled_risks": list(enabled_risks),
        "tokens": {"admin": {"token": admin_token, "role": "admin"}},
        "postgres_dsn": None,
        "certbot_email": None,
        "audit_path": audit_path,
    }
    header = (
        "# Bastion executor configuration.\n"
        "# enabled_risks: [read] is the safe default. Add 'write' and/or 'admin' to allow\n"
        "# approval-gated actions. Tokens: one per person, role = viewer|operator|admin.\n"
    )
    return header + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
