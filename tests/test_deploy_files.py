"""Deploy artefacts keep their hardening; the installer embeds the canonical unit."""

from __future__ import annotations

import re
from pathlib import Path

from bastion.tools import REGISTRY, packages
from bastion.tools._types import PACKAGES, SERVICES

ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / "deploy" / "bastion-executor.service"
SUDOERS = ROOT / "deploy" / "sudoers.bastion"
INSTALL = ROOT / "scripts" / "install.sh"


def test_unit_hardening() -> None:
    text = UNIT.read_text(encoding="utf-8")
    for line in (
        "User=bastion",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "PrivateTmp=true",
        "ReadWritePaths=/var/log/bastion",
        "Restart=always",
        "AmbientCapabilities=CAP_KILL",
        "ExecStart=/opt/bastion/bin/bastion-executor",
    ):
        assert line in text, line
    assert "NoNewPrivileges=true" not in text  # sudo needs setuid
    # apt runs through systemd-run, never by widening the sandbox for the executor itself
    assert "ReadWritePaths=/var/lib" not in text and "ReadWritePaths=/usr" not in text


def test_installer_embeds_the_canonical_unit() -> None:
    unit = UNIT.read_text(encoding="utf-8").strip()
    install = INSTALL.read_text(encoding="utf-8")
    assert unit in install, "scripts/install.sh must embed deploy/bastion-executor.service verbatim"


def test_installer_is_strict_and_idempotent() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text
    assert "visudo -cf" in text
    assert "useradd --system --shell /usr/sbin/nologin" in text
    assert "enabled_risks: [read]" in text
    assert 'if [[ -f "${CONFIG}" ]]' in text  # never rotate an existing token
    assert "install -m 0440" in text
    assert "\r" not in text, "install.sh must use LF line endings"


def _rules(text: str) -> str:
    rules = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return "\n".join(rules)


def test_sudoers_lists_exact_commands_only() -> None:
    body = _rules(SUDOERS.read_text(encoding="utf-8"))
    assert "NOPASSWD" in body
    assert re.search(r"^bastion\s+ALL=\(root\)\s+NOPASSWD:", body, re.M)
    for banned in (
        "ALL=(ALL)",
        "NOPASSWD: ALL",
        "/bin/kill",
        "/usr/bin/kill",
        "/bin/sh",
        "/bin/bash",
        "rm ",
        "apt-get remove",
        "apt-get purge",
        "apt-get autoremove",
        "dpkg -r",
        "dpkg -P",
        "pip install",
    ):
        assert banned not in body, banned
    assert not re.search(r"(^|\s)-9(\s|$)", body), "a bare -9 signal argument must never appear"
    # the systemctl/nginx/certbot commands the service tools run: one exact line per service
    assert body.count("systemctl restart") == len(SERVICES)
    for svc in SERVICES:
        assert f"/usr/bin/systemctl restart {svc}" in body, svc
    assert "nginx -t" in body
    assert "certbot renew" in body
    assert "certbot ^--nginx -d [a-z0-9.-]+ --non-interactive --agree-tos -m [^ ]+$" in body
    # the apt block is granted, and only the apt block beyond the three above
    aliases = re.findall(r"^Cmnd_Alias\s+(\w+)", body, re.M)
    assert aliases == ["BASTION_NGINX", "BASTION_SYSTEMCTL", "BASTION_CERTBOT", "BASTION_APT"]
    grant = re.search(r"^bastion\s+ALL=\(root\)\s+NOPASSWD:\s*(.+)$", body, re.M)
    assert grant is not None
    assert [a.strip() for a in grant.group(1).split(",")] == aliases


def test_sudoers_apt_block_is_generated_from_the_catalog() -> None:
    text = SUDOERS.read_text(encoding="utf-8")
    block = packages.render_sudoers_apt()
    assert block in text, (
        "deploy/sudoers.bastion must contain `python -m bastion.tools --sudoers-apt`"
    )
    apt_lines = [ln for ln in block.splitlines()]
    assert len(apt_lines) == 1 + len(PACKAGES)  # apt-get update + one install per entry
    for line in apt_lines:
        assert "*" not in line and "?" not in line, "no wildcards in apt rules"
        assert "/usr/bin/systemd-run --wait --pipe --collect --quiet" in line
        assert "/usr/bin/apt-get update -q" in line or "/usr/bin/apt-get install -y " in line
    # every command install_package would run is covered, byte for byte (after sudoers escaping)
    for key in PACKAGES:
        plan = REGISTRY["install_package"].plan({"package": key})
        for shown in plan.splitlines():
            assert shown.startswith("sudo systemd-run ")
            argv = shown.removeprefix("sudo ").split(" ")
            assert packages.sudoers_command(argv) in block, shown


def test_sudoers_escaping_is_literal_only() -> None:
    cmd = packages.sudoers_command(["systemd-run", "--unit=x", "a,b", "c:d", "e\\f"])
    assert cmd == "/usr/bin/systemd-run --unit\\=x a\\,b c\\:d e\\\\f"
    custom = packages.render_sudoers_apt("/bin/systemd-run")
    assert custom.count("/bin/systemd-run ") == 1 + len(PACKAGES)
    assert "/usr/bin/systemd-run" not in custom


def test_installer_sudoers_matches_deploy_shape() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    for svc in SERVICES:
        assert f"${{SYSTEMCTL_BIN}} restart {svc}" in text, svc
    assert text.count("${SYSTEMCTL_BIN} restart ") == len(SERVICES)
    assert "kill" not in text.split("Cmnd_Alias BASTION_NGINX")[1].split("NOPASSWD")[0]
    assert 'python" -m bastion.tools --sudoers-apt "${SYSTEMD_RUN_BIN}"' in text
    assert "${APT_RULES}" in text
    assert "BASTION_CERTBOT, BASTION_APT" in text
    rules = _rules(text)
    assert "apt-get remove" not in rules and "apt-get purge" not in rules


def test_sudoers_apt_cli_renders_block(capsys: object) -> None:
    from bastion.tools.__main__ import main

    assert main(["--sudoers-apt", "/custom/systemd-run"]) == 0
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert out.strip() == packages.render_sudoers_apt("/custom/systemd-run")
    assert main(["--sudoers-apt"]) == 0
    assert capsys.readouterr().out.strip() == packages.render_sudoers_apt()  # type: ignore[attr-defined]
