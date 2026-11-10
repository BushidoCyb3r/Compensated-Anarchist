"""Tamper-evident, append-only audit log (hash-chained JSONL).

Every tool decision (allowed / approved / denied), every tool result digest, every
analyst approval and every memory promotion is recorded. Each record carries the
SHA-256 of the previous record, so any edit or deletion breaks the chain and is
detected by `canarchist audit-verify`.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

try:  # several processes may write one case's log (dashboard + CLI): serialize with an OS file lock
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]


def _tail_hash(fh) -> str:
    """Hash of the last record, reading backwards from the end of a binary file handle."""
    fh.seek(0, os.SEEK_END)
    pos = fh.tell()
    buf = b""
    while pos > 0:
        step = min(65536, pos)
        pos -= step
        fh.seek(pos)
        buf = fh.read(step) + buf
        lines = [ln for ln in buf.split(b"\n") if ln.strip()]
        if lines and (len(lines) > 1 or pos == 0):
            return json.loads(lines[-1])["hash"]
    return GENESIS


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, path: Path, operator: str):
        self.path = path
        self.operator = operator
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else GENESIS

    def record(self, event: str, **data: Any) -> str:
        with self._lock, open(self.path, "a+b") as fh:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                prev = _tail_hash(fh)  # re-read: another process may have appended since our last record
                body = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "operator": self.operator,
                    "event": event,
                    "data": data,
                    "prev_hash": prev,
                }
                digest = hashlib.sha256(_canon(body).encode()).hexdigest()
                body["hash"] = digest
                fh.seek(0, os.SEEK_END)
                fh.write((_canon(body) + "\n").encode("utf-8"))
                fh.flush()
            finally:
                if fcntl:
                    fcntl.flock(fh, fcntl.LOCK_UN)
            self._prev = digest
            return digest


def verify(path: Path) -> tuple[bool, str]:
    prev = GENESIS
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            claimed = rec.pop("hash")
            if rec.get("prev_hash") != prev:
                return False, f"line {n}: chain broken (prev_hash mismatch)"
            if hashlib.sha256(_canon(rec).encode()).hexdigest() != claimed:
                return False, f"line {n}: record modified (hash mismatch)"
            prev = claimed
    return True, "audit chain intact"
