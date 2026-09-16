"""Invariant 9: append-only, hash-chained audit log with tamper detection."""

from __future__ import annotations

import json
from pathlib import Path

from bastion.core.audit import GENESIS_HASH, AuditLog, AuditRecord, sha256_hex


def _fill(log: AuditLog, n: int = 3) -> None:
    for i in range(n):
        log.append(
            user="alice",
            tool="load_avg" if i % 2 else "restart_service",
            args={"i": i},
            plan=f"plan {i}",
            result=f"result {i}",
        )


def test_append_creates_file_and_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    r0 = log.append(user="u", tool="load_avg", args={}, plan="cat /proc/loadavg", result="1.0")
    r1 = log.append(user="u", tool="memory", args={}, plan="psutil", result="2.0")
    assert r0.prev_hash == GENESIS_HASH
    assert r1.prev_hash == r0.hash
    assert r0.result_hash == sha256_hex("1.0")
    assert path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert set(rec) >= {"ts", "user", "tool", "args", "plan", "result_hash", "prev_hash", "hash"}


def test_verify_ok(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    _fill(log, 5)
    v = log.verify()
    assert v.ok and v.records == 5


def test_verify_empty_is_ok(tmp_path: Path) -> None:
    v = AuditLog(tmp_path / "missing.jsonl").verify()
    assert v.ok and v.records == 0


def test_reopen_continues_chain(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 2)
    later = AuditLog(path)
    rec = later.append(user="u", tool="t", args={}, plan="p", result="r")
    prev = json.loads(path.read_text(encoding="utf-8").splitlines()[1])
    assert rec.prev_hash == prev["hash"]
    assert later.verify().ok


def test_tamper_edit_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["tool"] = "memory"  # pretend the write was a read
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = AuditLog(path).verify()
    assert not v.ok
    assert v.first_bad_line == 2
    assert "hash mismatch" in v.reason


def test_tamper_delete_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = AuditLog(path).verify()
    assert not v.ok and v.first_bad_line == 2
    assert "prev_hash" in v.reason


def test_tamper_reorder_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not AuditLog(path).verify().ok


def test_tamper_recomputed_hash_still_breaks_link(tmp_path: Path) -> None:
    """An attacker who edits a record *and* recomputes its hash still breaks the
    prev_hash link of the following record."""
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["plan"] = "something innocuous"
    rec["hash"] = AuditRecord.compute_hash(rec)
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = AuditLog(path).verify()
    assert not v.ok and v.first_bad_line == 2


def test_corrupt_line_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 2)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("not json\n")
    v = AuditLog(path).verify()
    assert not v.ok and v.first_bad_line == 3


def test_tail(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    _fill(log, 6)
    assert [r["args"]["i"] for r in log.tail(2)] == [4, 5]
    assert log.tail(0) == []
    assert len(log.tail(100)) == 6


def test_result_rows_are_not_stored(tmp_path: Path) -> None:
    """Only a hash of the result is persisted, never the result body."""
    path = tmp_path / "a.jsonl"
    AuditLog(path).append(user="u", tool="t", args={}, plan="p", result="SECRET-ROW-DATA")
    assert "SECRET-ROW-DATA" not in path.read_text(encoding="utf-8")
