"""Append-only, hash-chained JSONL audit log (invariant 9).

Each record carries ``prev_hash`` (the ``hash`` of the previous record, or 64
zeros for the first) and ``hash`` (SHA-256 of the canonical JSON of the record
without its ``hash`` field). Tampering with, reordering, or deleting any line
breaks the chain and is detected by :meth:`AuditLog.verify`.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    ts: str
    user: str
    tool: str
    args: dict[str, Any]
    plan: str
    result_hash: str
    prev_hash: str
    hash: str
    status: str = "ok"

    @staticmethod
    def compute_hash(fields: dict[str, Any]) -> str:
        body = {k: v for k, v in fields.items() if k != "hash"}
        return sha256_hex(canonical_json(body))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    records: int
    first_bad_line: int | None = None
    reason: str = ""


class AuditLog:
    """Thread-safe append-only writer/reader for the hash-chained audit file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._last_hash: str | None = None

    # -- writing ---------------------------------------------------------

    def append(
        self,
        *,
        user: str,
        tool: str,
        args: dict[str, Any],
        plan: str,
        result: str,
        status: str = "ok",
    ) -> AuditRecord:
        with self._lock:
            prev = self._current_last_hash()
            fields: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "user": user,
                "tool": tool,
                "args": args,
                "plan": plan,
                "result_hash": sha256_hex(result),
                "prev_hash": prev,
                "status": status,
            }
            fields["hash"] = AuditRecord.compute_hash(fields)
            record = AuditRecord(**fields)
            self._write_line(canonical_json(record.to_dict()))
            self._last_hash = record.hash
            return record

    def _write_line(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        fd = os.open(self.path, flags, 0o640)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _current_last_hash(self) -> str:
        if self._last_hash is not None:
            return self._last_hash
        last = GENESIS_HASH
        for rec in self._iter_raw():
            last = str(rec.get("hash", last))
        self._last_hash = last
        return last

    # -- reading ---------------------------------------------------------

    def _iter_raw(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    obj = {"_corrupt": line}
                out.append(obj)
        return out

    def records(self) -> list[dict[str, Any]]:
        return self._iter_raw()

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if n <= 0:
            return []
        return self._iter_raw()[-n:]

    def verify(self) -> VerifyResult:
        """Walk the chain; report the first line whose hash or link is wrong."""
        prev = GENESIS_HASH
        recs = self._iter_raw()
        for i, rec in enumerate(recs, start=1):
            if "_corrupt" in rec:
                return VerifyResult(False, len(recs), i, "line is not valid JSON")
            if not isinstance(rec.get("hash"), str):
                return VerifyResult(False, len(recs), i, "record has no hash")
            if rec["hash"] != AuditRecord.compute_hash(rec):
                return VerifyResult(False, len(recs), i, "record hash mismatch (content altered)")
            if rec.get("prev_hash") != prev:
                return VerifyResult(
                    False, len(recs), i, "prev_hash does not link to the previous record"
                )
            prev = rec["hash"]
        return VerifyResult(True, len(recs))
