"""Read-only host inspection tools (psutil + /proc)."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import psutil

from bastion.core.errors import ToolExecutionError, ValidationFailed
from bastion.tools import tool
from bastion.tools._exec import run_cmd
from bastion.tools._types import Pid, ProcessLimit

MB = 1024 * 1024


def _oneline(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _mb(n: float) -> str:
    return f"{n / MB:.0f}MB"


def _elapsed(create_time: float) -> str:
    seconds = max(0, int(time.time() - create_time))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d{hours:02d}h"
    if hours:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m{secs:02d}s"


def _read_loadavg() -> tuple[float, float, float]:
    try:
        with open("/proc/loadavg", encoding="ascii") as fh:
            parts = fh.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (OSError, ValueError, IndexError):
        pass
    try:
        one, five, fifteen = psutil.getloadavg()
        return one, five, fifteen
    except (AttributeError, OSError):
        return 0.0, 0.0, 0.0


def _require_pid(kwargs: Mapping[str, Any]) -> None:
    pid = int(kwargs["pid"])
    if not psutil.pid_exists(pid):
        raise ValidationFailed(f"no process with pid {pid}")


@tool(risk="read", plan="cat /proc/loadavg; nproc; free -m")
def load_avg() -> str:
    """Show 1/5/15-minute load average, CPU count, and memory/swap headroom.

    Start here for any "server is slow" question. Load above the CPU count means
    processes are queuing for CPU (or stuck in uninterruptible I/O wait).
    """
    one, five, fifteen = _read_loadavg()
    cpus = os.cpu_count() or 1
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    lines = [
        f"load: 1m={one:.2f} 5m={five:.2f} 15m={fifteen:.2f} "
        f"(cpus={cpus}, per-cpu-1m={one / cpus:.2f})",
        f"memory: total={_mb(vm.total)} used={_mb(vm.used)} available={_mb(vm.available)} "
        f"percent={vm.percent:.1f}",
        f"swap: total={_mb(sw.total)} used={_mb(sw.used)} percent={sw.percent:.1f}",
    ]
    return "\n".join(lines)


@tool(risk="read", plan="psutil.process_iter() sorted by cpu_percent desc, memory_percent desc")
def top_processes(limit: ProcessLimit = 10) -> str:
    """List the processes using the most CPU (then memory), like `top` sorted by CPU.

    Args:
        limit: how many processes to show (1-25).
    """
    attrs = ["pid", "name", "username", "memory_percent", "create_time", "cmdline"]
    procs: list[psutil.Process] = []
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
            procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    time.sleep(0.5)
    rows: list[tuple[float, float, dict[str, Any]]] = []
    for proc in procs:
        try:
            cpu = proc.cpu_percent(None)
            info = proc.as_dict(attrs=attrs)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        mem = float(info.get("memory_percent") or 0.0)
        rows.append((cpu, mem, info))
    rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
    out = [f"{'PID':>7} {'USER':<12} {'CPU%':>6} {'MEM%':>6} {'ELAPSED':>8}  COMMAND"]
    for cpu, mem, info in rows[:limit]:
        cmd = _oneline(" ".join(info.get("cmdline") or []) or str(info.get("name") or "?"))
        user = str(info.get("username") or "?")[:12]
        elapsed = _elapsed(float(info.get("create_time") or time.time()))
        out.append(f"{info['pid']:>7} {user:<12} {cpu:>6.1f} {mem:>6.1f} {elapsed:>8}  {cmd[:120]}")
    return "\n".join(out)


@tool(risk="read", plan="psutil.Process({pid}): cmdline, user, cwd, threads, open_files, etime")
def process_detail(pid: Pid) -> str:
    """Show details for one process: command line, user, cwd, threads, open files, uptime.

    Args:
        pid: the process id, as seen in top_processes output. Never guess a pid.
    """
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            user = _safe(proc.username)
            status = proc.status()
            cmdline = _oneline(" ".join(_safe(proc.cmdline, default=[]) or []) or name)
            cwd = _safe(proc.cwd, default="?")
            threads = proc.num_threads()
            created = proc.create_time()
            rss = proc.memory_info().rss
            ppid = proc.ppid()
        open_files = _safe(lambda: len(proc.open_files()), default="?")
        conns = _safe(lambda: len(proc.net_connections(kind="inet")), default="?")
        cpu = proc.cpu_percent(interval=0.2)
    except psutil.NoSuchProcess as exc:
        raise ValidationFailed(f"no process with pid {pid}") from exc
    except psutil.AccessDenied as exc:
        raise ToolExecutionError(f"access denied inspecting pid {pid}") from exc
    started = datetime.fromtimestamp(created, tz=timezone.utc).isoformat(timespec="seconds")
    return "\n".join(
        [
            f"pid: {pid}  ppid: {ppid}  name: {name}  status: {status}",
            f"user: {user}",
            f"cmdline: {cmdline[:500]}",
            f"cwd: {cwd}",
            f"threads: {threads}  open_files: {open_files}  connections: {conns}",
            f"cpu%: {cpu:.1f}  rss: {_mb(rss)}",
            f"started: {started}  elapsed: {_elapsed(created)}",
        ]
    )


process_detail.validator(_require_pid)


def _safe(fn: Any, default: Any = "?") -> Any:
    try:
        return fn()
    except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess, OSError):
        return default


@tool(risk="read", plan="psutil.disk_partitions() + psutil.disk_usage(mountpoint) per mount")
def disk_usage() -> str:
    """Show used/free space and percent for every mounted filesystem (like `df -h`)."""
    out = [f"{'MOUNT':<24} {'FS':<8} {'SIZE':>8} {'USED':>8} {'FREE':>8} {'USE%':>5}"]
    skip = {"squashfs", "tmpfs", "devtmpfs", "overlay", "iso9660", "proc", "sysfs"}
    for part in psutil.disk_partitions(all=False):
        if part.fstype in skip or "cdrom" in part.opts:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        out.append(
            f"{part.mountpoint[:24]:<24} {part.fstype[:8]:<8} {_gb(usage.total):>8} "
            f"{_gb(usage.used):>8} {_gb(usage.free):>8} {usage.percent:>4.0f}%"
        )
    return "\n".join(out)


def _gb(n: float) -> str:
    return f"{n / (1024**3):.1f}G"


@tool(risk="read", plan="psutil.virtual_memory(); psutil.swap_memory()")
def memory() -> str:
    """Show RAM and swap usage in detail (total, used, available, cached, swap)."""
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    cached = getattr(vm, "cached", 0)
    buffers = getattr(vm, "buffers", 0)
    shared = getattr(vm, "shared", 0)
    return "\n".join(
        [
            f"memory: total={_mb(vm.total)} used={_mb(vm.used)} free={_mb(vm.free)} "
            f"available={_mb(vm.available)} percent={vm.percent:.1f}",
            f"cache: cached={_mb(cached)} buffers={_mb(buffers)} shared={_mb(shared)}",
            f"swap: total={_mb(sw.total)} used={_mb(sw.used)} free={_mb(sw.free)} "
            f"percent={sw.percent:.1f}",
        ]
    )


@tool(risk="read", plan="psutil per-process io_counters() delta sampled over 1s")
def io_top(limit: ProcessLimit = 10) -> str:
    """List processes doing the most disk I/O over a 1-second window.

    Args:
        limit: how many processes to show (1-25).
    """
    first: dict[int, tuple[int, int, str]] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            io = proc.io_counters()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
            continue
        first[proc.pid] = (io.read_bytes, io.write_bytes, str(proc.info.get("name") or "?"))
    if not first:
        return "io counters are not available on this host (needs Linux and permission)"
    time.sleep(1.0)
    rows: list[tuple[int, int, int, str]] = []
    for pid, (r0, w0, name) in first.items():
        try:
            io = psutil.Process(pid).io_counters()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        rows.append((max(0, io.read_bytes - r0), max(0, io.write_bytes - w0), pid, name))
    rows.sort(key=lambda r: r[0] + r[1], reverse=True)
    out = [f"{'PID':>7} {'READ/s':>10} {'WRITE/s':>10}  NAME"]
    for read, write, pid, name in rows[:limit]:
        out.append(f"{pid:>7} {_kb(read):>10} {_kb(write):>10}  {name}")
    return "\n".join(out)


def _kb(n: int) -> str:
    return f"{n / 1024:.0f}KB"


@tool(risk="read", plan="ss -s; psutil.net_connections(kind='inet') grouped by status")
def connections() -> str:
    """Summarise TCP connection counts by state (established, time-wait, ...) via ss -s."""
    parts: list[str] = []
    try:
        result = run_cmd(["ss", "-s"], timeout=10)
        parts.append(result.output())
    except ToolExecutionError as exc:
        parts.append(f"ss -s unavailable: {exc.message}")
    counts: dict[str, int] = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            counts[conn.status] = counts.get(conn.status, 0) + 1
    except (psutil.AccessDenied, PermissionError):
        parts.append("per-state counts unavailable (permission denied)")
    else:
        summary = ", ".join(f"{k.lower()}={v}" for k, v in sorted(counts.items()))
        parts.append(f"by state: {summary or 'none'}")
        parts.append(f"established: {counts.get('ESTABLISHED', 0)}")
    return "\n".join(p for p in parts if p)
