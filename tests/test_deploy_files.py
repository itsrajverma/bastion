"""Deploy artefacts keep their hardening; the installer embeds the canonical unit."""

from __future__ import annotations

import re
from pathlib import Path

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


def test_sudoers_lists_exact_commands_only() -> None:
    text = SUDOERS.read_text(encoding="utf-8")
    rules = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    body = "\n".join(rules)
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
    ):
        assert banned not in body, banned
    assert not re.search(r"(^|\s)-9(\s|$)", body), "a bare -9 signal argument must never appear"
    # only the six commands the tools run
    assert body.count("systemctl restart") == 4
    assert "nginx -t" in body
    assert "certbot renew" in body
    assert "certbot ^--nginx -d [a-z0-9.-]+ --non-interactive --agree-tos -m [^ ]+$" in body


def test_installer_sudoers_matches_deploy_shape() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    assert text.count("restart nginx") >= 1 and text.count("restart postgresql") >= 1
    assert "kill" not in text.split("Cmnd_Alias BASTION_NGINX")[1].split("NOPASSWD")[0]
