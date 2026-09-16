"""The single chokepoint for running external programs (invariant 2).

Only list-form argument vectors are accepted. There is no way to pass a string
through a shell here, and no tool module may call ``subprocess`` directly.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from bastion.core.errors import ToolExecutionError

_SAFE_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

DEFAULT_TIMEOUT = 30.0


@dataclass(frozen=True, slots=True)
class CmdResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def output(self) -> str:
        parts = [p for p in (self.stdout.strip(), self.stderr.strip()) if p]
        return "\n".join(parts)

    def render(self) -> str:
        """Human/LLM friendly rendering with the exit code."""
        body = self.output() or "(no output)"
        return f"$ {' '.join(self.argv)}\n{body}\n[exit {self.returncode}]"


def _env() -> dict[str, str]:
    env = dict(_SAFE_ENV)
    if sys.platform == "win32":  # development/testing only; the executor targets Linux
        env["PATH"] = os.environ.get("PATH", "")
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    return env


def run_cmd(
    argv: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT, sudo: bool = False
) -> CmdResult:
    """Run ``argv`` without a shell and return its result.

    Args:
        argv: program and arguments as separate strings. Never a single string.
        timeout: seconds before the process is killed and an error is raised.
        sudo: prefix with ``sudo -n`` (non-interactive; sudoers must allow it).
    """
    if isinstance(argv, str | bytes):
        raise TypeError("argv must be a sequence of strings, never a single string")
    vector = list(argv)
    if not vector:
        raise ToolExecutionError("empty argument vector")
    for item in vector:
        if not isinstance(item, str):
            raise TypeError(f"argv items must be str, got {type(item).__name__}")
        if "\0" in item:
            raise ToolExecutionError("argument contains a NUL byte")
    if sudo:
        vector = ["sudo", "-n", *vector]
    try:
        completed = subprocess.run(
            vector,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
            env=_env(),
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ToolExecutionError(f"{vector[0]!r} is not installed on this host") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"{vector[0]!r} timed out after {timeout:.0f}s") from exc
    except PermissionError as exc:
        raise ToolExecutionError(f"not permitted to execute {vector[0]!r}") from exc
    return CmdResult(
        argv=tuple(vector),
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def render_argv(argv: Sequence[str], *, sudo: bool = False) -> str:
    """Render an argv the way ``plan()`` shows it to the operator."""
    vector = ["sudo", *argv] if sudo else list(argv)
    return " ".join(vector)
