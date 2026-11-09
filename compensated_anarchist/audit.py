"""Tamper-evident, append-only audit log (hash-chained JSONL).

Every tool decision (allowed / approved / denied), every tool result digest, every
analyst approval and every memory promotion is recorded. Each record carries the
SHA-256 of the previous record, so any edit or deletion breaks the chain and is
detected by `canarchist audit-verify`.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


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
        with self._lock:
            body = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "operator": self.operator,
                "event": event,
                "data": data,
                "prev_hash": self._prev,
            }
            digest = hashlib.sha256(_canon(body).encode()).hexdigest()
            body["hash"] = digest
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(_canon(body) + "\n")
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
