"""Process signalling with a protected-target guard (invariant 5).

The guard lives here, in code, and is evaluated on both ``plan()`` and
``run()``; the LLM cannot bypass it with arguments.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

import psutil

from bastion.core.errors import ProtectedTarget, ValidationFailed

PROTECTED_USERS: frozenset[str] = frozenset({"root", "postgres"})
PROTECTED_CMD_RE = re.compile(
    r"postgres|sshd|systemd|dockerd|containerd|nginx: master|gunicorn: master|bastion-executor",
    re.IGNORECASE,
)
MIN_AGE_SECONDS = 30


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    name: str
    user: str
    cmdline: str
    age_seconds: int

    def summary(self) -> str:
        return f"pid={self.pid} name={self.name!r} user={self.user} age={self.age_seconds}s"


def inspect_process(pid: int) -> ProcessInfo:
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            try:
                user = proc.username()
            except (psutil.AccessDenied, OSError):
                user = "?"
            try:
                cmdline = " ".join(proc.cmdline()) or name
            except (psutil.AccessDenied, OSError):
                cmdline = name
            age = int(time.time() - proc.create_time())
    except psutil.NoSuchProcess as exc:
        raise ValidationFailed(f"no process with pid {pid}") from exc
    except psutil.ZombieProcess as exc:
        raise ValidationFailed(f"pid {pid} is a zombie; nothing to signal") from exc
    return ProcessInfo(pid=pid, name=name, user=user, cmdline=cmdline, age_seconds=age)


def protection_reason(info: ProcessInfo, *, now: float | None = None) -> str | None:
    """Why this process must not be signalled, or None if it may be."""
    if info.pid == 1:
        return "pid 1 (init) is protected"
    if info.pid == psutil.Process().pid:
        return "refusing to signal the executor itself"
    user = info.user.split("\\")[-1].lower()  # DOMAIN\\user on Windows dev boxes
    if user in PROTECTED_USERS:
        return f"process is owned by protected user {info.user!r}"
    if PROTECTED_CMD_RE.search(info.cmdline) or PROTECTED_CMD_RE.search(info.name):
        return f"process matches the protected command pattern ({info.name!r})"
    if info.age_seconds < MIN_AGE_SECONDS:
        return f"process is younger than {MIN_AGE_SECONDS}s ({info.age_seconds}s)"
    return None


def assert_signalable(pid: int) -> ProcessInfo:
    info = inspect_process(pid)
    reason = protection_reason(info)
    if reason:
        raise ProtectedTarget(f"refusing to signal {info.summary()}: {reason}")
    return info
