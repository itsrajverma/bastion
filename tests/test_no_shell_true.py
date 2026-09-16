"""Invariant 1 & 2: no raw shell tool, no shell=True anywhere in the package.

This test greps the *source* of the `bastion` package. It intentionally scans
comments and docstrings too, so the forbidden spellings must never appear in
the package at all (not even in prose).
"""

from __future__ import annotations

import re
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "bastion"

FORBIDDEN = [
    re.compile(r"shell\s*=\s*True"),
    re.compile(r"\bos\.system\("),
    re.compile(r"\bos\.popen\("),
    re.compile(r"\bsubprocess\.getoutput\("),
    re.compile(r"\bsubprocess\.getstatusoutput\("),
    re.compile(r"\bpty\.spawn\("),
    re.compile(r"\bcommands\.getoutput\("),
]

FORBIDDEN_IMPORTS = [
    re.compile(r"^\s*import\s+pty\b", re.M),
    re.compile(r"^\s*from\s+pty\s+import", re.M),
]


def _package_sources() -> list[Path]:
    files = sorted(PACKAGE_DIR.rglob("*.py"))
    assert files, f"no python sources found under {PACKAGE_DIR}"
    return files


def test_no_shell_primitives_in_package() -> None:
    offenders: list[str] = []
    for path in _package_sources():
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN + FORBIDDEN_IMPORTS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                offenders.append(
                    f"{path.relative_to(PACKAGE_DIR.parent)}:{line_no}: {match.group(0)}"
                )
    assert not offenders, "forbidden shell primitives found:\n" + "\n".join(offenders)


def test_subprocess_calls_are_list_form() -> None:
    """Every subprocess.run/Popen/check_output call must pass a list literal or a
    variable named argv/cmd (never a string literal)."""
    string_call = re.compile(r"subprocess\.(run|Popen|call|check_call|check_output)\(\s*[\"'f]")
    offenders: list[str] = []
    for path in _package_sources():
        text = path.read_text(encoding="utf-8")
        for match in string_call.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{path.relative_to(PACKAGE_DIR.parent)}:{line_no}")
    assert not offenders, "subprocess called with a string command:\n" + "\n".join(offenders)


def test_no_raw_shell_tool_module() -> None:
    """There must be no module or symbol offering a generic command runner."""
    names = {p.stem for p in _package_sources()}
    for banned in ("shell", "exec", "run_command", "command", "bash"):
        assert banned not in names, f"module {banned!r} must not exist"
