"""End-to-end "install redis" through the agent loop and the real executor.

A recorded model asks for package_status, then install_package (approval-gated,
admin-only), then service_status. The host is faked at the run_cmd chokepoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from bastion.agent.loop import LoopConfig, run_ask
from bastion.agent.prompts import SYSTEM_PROMPT
from bastion.agent.providers.base import ToolResultMessage
from bastion.tools import REGISTRY
from bastion.tools._exec import CmdResult
from tests.conftest import ADMIN_TOKEN, OPERATOR_TOKEN, RecordingUI, ScriptedProvider, real_executor

INSTALL_LINE = (
    "sudo systemd-run --wait --pipe --collect --quiet --setenv=DEBIAN_FRONTEND=noninteractive "
    "--unit=bastion-apt-install-redis /usr/bin/apt-get install -y redis-server"
)


def tool_results(provider: ScriptedProvider) -> list[str]:
    """Tool results in conversation order, as the model saw them on its last turn."""
    out: list[str] = []
    for m in provider.requests[-1]["messages"]:
        if isinstance(m, ToolResultMessage):
            out.extend(r.content for r in m.results)
    return out


@dataclass
class AptHost:
    installed: bool = False
    commands: list[list[str]] = field(default_factory=list)

    def run_cmd(self, argv: list[str], *, timeout: float = 30.0, sudo: bool = False) -> CmdResult:
        self.commands.append(list(argv))
        if argv[0] == "dpkg-query":
            assert not sudo
            if self.installed:
                return CmdResult(tuple(argv), 0, "redis-server\t5:7.0.15-1\tinstalled\n", "")
            return CmdResult(
                tuple(argv), 1, "", "dpkg-query: no packages found matching redis-server\n"
            )
        if argv[0] == "systemd-run":
            assert sudo
            if "install" in argv:
                self.installed = True
                return CmdResult(tuple(argv), 0, "Setting up redis-server (5:7.0.15-1) ...\n", "")
            return CmdResult(tuple(argv), 0, "Reading package lists...\n", "")
        if argv[0] == "systemctl":
            state = "active" if self.installed else "inactive"
            return CmdResult(tuple(argv), 0 if self.installed else 3, state, "")
        raise AssertionError(f"unexpected command {argv}")


@pytest.fixture
def apt_host(monkeypatch: pytest.MonkeyPatch) -> AptHost:
    host = AptHost()
    monkeypatch.setattr("bastion.tools.packages.run_cmd", host.run_cmd)
    monkeypatch.setattr("bastion.tools.services.run_cmd", host.run_cmd)
    return host


def test_install_redis_end_to_end(apt_host: AptHost, tmp_path: Path) -> None:
    executor, http = real_executor(tmp_path, enabled_risks=["read", "write", "admin"])
    provider = ScriptedProvider.from_fixture("install_redis")
    ui = RecordingUI(decisions=["y"])
    with http:
        result = run_ask("install redis", provider, executor, ui)
        audit = http.get("/audit?n=50", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}).json()

    assert result.stop_reason == "final"
    assert result.tools_called == [
        "package_status",
        "install_package",
        "package_status",  # verify_with
        "service_status",
    ]
    statuses = {c.name: c.status for c in result.calls}
    assert statuses["install_package"] == "ok"
    # the operator saw both exact commands and approved once
    approvals = [plan for kind, plan in ui.events if kind == "approve"]
    assert len(approvals) == 1
    assert approvals[0].splitlines()[-1] == INSTALL_LINE
    # what actually ran, in order: dpkg-query, apt update, apt install, dpkg-query x2, systemctl
    programs = [argv[0] for argv in apt_host.commands]
    assert programs == [
        "dpkg-query",
        "systemd-run",
        "systemd-run",
        "dpkg-query",
        "dpkg-query",
        "systemctl",
        "systemctl",
    ]
    assert apt_host.commands[2][-3:] == ["install", "-y", "redis-server"]
    # the model saw a before/after picture
    shown = tool_results(provider)
    assert "redis-server: not installed" in shown[0]
    assert "summary: all installed" in shown[1]
    assert "Verification via package_status" in shown[1]
    assert "is-active: active" in shown[2]
    assert "redis-server 5:7.0.15-1" in result.text
    # audited with the displayed plan
    rec = next(r for r in audit["records"] if r["tool"] == "install_package")
    assert rec["args"] == {"package": "redis"} and rec["plan"].splitlines()[-1] == INSTALL_LINE
    assert audit["verified"] is True


def test_install_declined_runs_nothing(apt_host: AptHost, tmp_path: Path) -> None:
    executor, http = real_executor(tmp_path, enabled_risks=["read", "write", "admin"])
    provider = ScriptedProvider.from_fixture("install_redis")
    ui = RecordingUI(decisions=["n"])
    with http:
        result = run_ask("install redis", provider, executor, ui)
    rec = next(c for c in result.calls if c.name == "install_package")
    assert rec.status == "declined"
    assert [argv[0] for argv in apt_host.commands if argv[0] == "systemd-run"] == []
    assert apt_host.installed is False
    assert "declined" in tool_results(provider)[1]


def test_install_dry_run_never_touches_apt(apt_host: AptHost, tmp_path: Path) -> None:
    executor, http = real_executor(tmp_path, enabled_risks=["read", "write", "admin"])
    provider = ScriptedProvider.from_fixture("install_redis")
    ui = RecordingUI(decisions=["y"])
    with http:
        result = run_ask("install redis", provider, executor, ui, LoopConfig(dry_run=True))
    rec = next(c for c in result.calls if c.name == "install_package")
    assert rec.status == "dry_run"
    assert rec.plan.splitlines()[-1] == INSTALL_LINE
    assert all(argv[0] != "systemd-run" for argv in apt_host.commands)


def test_operator_cannot_see_or_call_install(apt_host: AptHost, tmp_path: Path) -> None:
    executor, http = real_executor(
        tmp_path, token=OPERATOR_TOKEN, enabled_risks=["read", "write", "admin"]
    )
    provider = ScriptedProvider.from_fixture("install_redis")
    with http:
        catalog = executor.tools()
        assert catalog.get("install_package") is None
        assert catalog.get("package_status") is not None
        result = run_ask("install redis", provider, executor, RecordingUI(decisions=["y"]))
    rec = next(c for c in result.calls if c.name == "install_package")
    assert rec.status == "unknown"
    assert apt_host.installed is False


def test_install_outside_catalog_is_rejected_by_executor(apt_host: AptHost, tmp_path: Path) -> None:
    executor, http = real_executor(tmp_path, enabled_risks=["read", "write", "admin"])
    provider = ScriptedProvider(
        [
            {"text": "", "tool_calls": [{"name": "install_package", "args": {"package": "vim"}}]},
            {
                "text": "",
                "tool_calls": [
                    {"name": "install_package", "args": {"package": "nginx", "version": "1.0"}}
                ],
            },
            {"text": "vim is not in the catalog.", "tool_calls": []},
        ]
    )
    with http:
        result = run_ask("install vim", provider, executor, RecordingUI(decisions=["y", "y"]))
    assert [c.status for c in result.calls] == ["error", "error"]
    assert apt_host.commands == []
    assert all("validation_failed" in s for s in tool_results(provider))


def test_system_prompt_has_install_playbook() -> None:
    text = SYSTEM_PROMPT
    assert "## Install playbook" in text
    assert "`package_status`" in text and "`install_package`" in text
    for key in REGISTRY["install_package"].input_schema()["properties"]["package"]["enum"]:
        assert key in text, key
    assert "remove or purge packages" in text
    assert "outside the package catalog" in text
