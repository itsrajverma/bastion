"""Invariant 5: the protected-process list is code, evaluated on plan and run."""

from __future__ import annotations

import os

import psutil
import pytest

from bastion.core.errors import ProtectedTarget, ValidationFailed
from bastion.tools import REGISTRY
from bastion.tools.process import (
    MIN_AGE_SECONDS,
    ProcessInfo,
    assert_signalable,
    inspect_process,
    protection_reason,
)


def info(**kw: object) -> ProcessInfo:
    base = {
        "pid": 4242,
        "name": "python",
        "user": "www-data",
        "cmdline": "python worker.py",
        "age_seconds": 600,
    }
    base.update(kw)
    return ProcessInfo(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("proc", "fragment"),
    [
        (info(pid=1, name="systemd", user="root", cmdline="/sbin/init"), "init"),
        (info(user="root"), "protected user"),
        (info(user="postgres"), "protected user"),
        (info(user="ROOT"), "protected user"),
        (info(user="DOMAIN\\root"), "protected user"),
        (info(name="sshd", cmdline="sshd: /usr/sbin/sshd -D"), "protected command"),
        (info(cmdline="/usr/lib/systemd/systemd-journald"), "protected command"),
        (info(cmdline="/usr/bin/dockerd -H fd://"), "protected command"),
        (info(cmdline="/usr/bin/containerd"), "protected command"),
        (info(cmdline="nginx: master process /usr/sbin/nginx"), "protected command"),
        (info(cmdline="gunicorn: master [app]"), "protected command"),
        (info(cmdline="postgres: app app 127.0.0.1(5555) idle"), "protected command"),
        (info(name="postgres", cmdline=""), "protected command"),
        (info(cmdline="/opt/bastion/bin/bastion-executor"), "protected command"),
        (info(user="mysql"), "protected user"),
        (info(user="redis"), "protected user"),
        (info(name="mysqld", cmdline="/usr/sbin/mysqld", user="app"), "protected command"),
        (info(cmdline="/usr/sbin/mariadbd", user="app"), "protected command"),
        (info(cmdline="/usr/bin/redis-server 127.0.0.1:6379", user="app"), "protected command"),
        (info(age_seconds=MIN_AGE_SECONDS - 1), "younger than"),
        (info(age_seconds=0), "younger than"),
    ],
)
def test_protected(proc: ProcessInfo, fragment: str) -> None:
    reason = protection_reason(proc)
    assert reason is not None and fragment in reason


@pytest.mark.parametrize(
    "proc",
    [
        info(),
        info(cmdline="gunicorn: worker [app]"),
        info(cmdline="nginx: worker process", user="www-data"),
        info(name="celery", cmdline="celery worker -A proj -l info", user="app"),
        info(name="apache2", cmdline="/usr/sbin/apache2 -k start", user="www-data"),
        info(name="php-fpm8.3", cmdline="php-fpm: pool www", user="www-data"),
        info(name="memcached", cmdline="/usr/bin/memcached -m 64", user="memcache"),
        info(age_seconds=MIN_AGE_SECONDS),
    ],
)
def test_allowed(proc: ProcessInfo) -> None:
    assert protection_reason(proc) is None


def test_executor_itself_is_protected() -> None:
    me = info(pid=os.getpid(), user="nobody")
    assert protection_reason(me) == "refusing to signal the executor itself"


def test_inspect_process_missing_pid() -> None:
    with pytest.raises(ValidationFailed):
        inspect_process(4_194_303)


def test_assert_signalable_real_process_is_young_or_self() -> None:
    """Our own process is protected (self); its parent may be too. Either way the
    guard raises rather than allowing a signal to a fresh test process."""
    with pytest.raises((ProtectedTarget, ValidationFailed)):
        assert_signalable(os.getpid())


def test_kill_process_plan_and_run_both_guarded(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = REGISTRY["kill_process"]
    assert spec.risk == "write" and spec.approve and spec.verify_with == "load_avg"
    from bastion.tools import process

    monkeypatch.setattr(
        process, "inspect_process", lambda pid: info(pid=pid, user="root", cmdline="sshd -D")
    )
    with pytest.raises(ProtectedTarget):
        spec.plan({"pid": 700})
    with pytest.raises(ProtectedTarget):
        spec.run({"pid": 700})


def test_kill_process_sends_sigterm_never_sigkill(monkeypatch: pytest.MonkeyPatch) -> None:
    from bastion.tools import process

    monkeypatch.setattr(process, "inspect_process", lambda pid: info(pid=pid))
    signals: list[str] = []

    class FakeProc:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def terminate(self) -> None:
            signals.append("TERM")

        def kill(self) -> None:  # pragma: no cover - must never be called
            signals.append("KILL")

        def wait(self, timeout: float = 0) -> None:
            raise psutil.TimeoutExpired(timeout)

    monkeypatch.setattr(process.psutil, "Process", FakeProc)
    out = REGISTRY["kill_process"].run({"pid": 4242})
    assert signals == ["TERM"]
    assert "still running" in out
    assert "KILL" not in out


def test_process_module_has_no_sigkill_path() -> None:
    import inspect

    from bastion.tools import process

    source = inspect.getsource(process)
    assert "SIGKILL" not in source.replace("Never SIGKILL", "")
    assert ".kill(" not in source
