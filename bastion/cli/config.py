"""Laptop-side configuration: ``~/.bastion/config.yaml`` (mode 600)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from bastion.core.errors import ConfigError

CONFIG_ENV = "BASTION_CLI_CONFIG"


def config_path() -> Path:
    override = os.environ.get(CONFIG_ENV)
    if override:
        return Path(override)
    return Path.home() / ".bastion" / "config.yaml"


class ServerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8)
    token: str = Field(min_length=16)


class CliConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = "anthropic"
    model: str = "claude-sonnet-4-6"
    api_key_env: str = "ANTHROPIC_API_KEY"
    base_url: str | None = None
    default_server: str | None = None
    servers: dict[str, ServerEntry] = Field(default_factory=dict)
    max_calls: int = Field(default=10, ge=1, le=50)
    max_seconds: int = Field(default=120, ge=5, le=900)

    def server(self, name: str | None) -> tuple[str, ServerEntry]:
        if not self.servers:
            raise ConfigError("no servers configured; run `bastion init` or `bastion servers add`")
        chosen = name or self.default_server or next(iter(self.servers))
        entry = self.servers.get(chosen)
        if entry is None:
            raise ConfigError(
                f"unknown server {chosen!r}; known: {', '.join(sorted(self.servers))}"
            )
        return chosen, entry


def load_config(path: Path | None = None) -> CliConfig:
    target = path or config_path()
    if not target.exists():
        raise ConfigError(f"no config at {target}; run `bastion init` first")
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{target} is not valid YAML: {exc}") from None
    if not isinstance(raw, dict):
        raise ConfigError(f"{target} must be a YAML mapping")
    try:
        return CliConfig.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"invalid config {target}: {problems}") from None


def save_config(config: CliConfig, path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = config.model_dump(mode="json")
    text = "# Bastion CLI configuration. Keep this file private (mode 600): it holds tokens.\n"
    text += yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return target


def permissions_ok(path: Path) -> bool:
    """True when the file is not readable by group/others (POSIX only; True elsewhere)."""
    if os.name != "posix":
        return True
    mode = stat.S_IMODE(path.stat().st_mode)
    return mode & (stat.S_IRWXG | stat.S_IRWXO) == 0
