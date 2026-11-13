"""Tamper-evident, append-only audit log (hash-chained JSONL with a signed head).

Every tool decision (allowed / approved / denied), every tool result digest, every
analyst approval and every memory promotion is recorded. Each record carries the
SHA-256 of the previous record, so editing or removing a record inside the log breaks
the chain. A chain alone cannot show that records were cut off the end, or that the
whole file was rewritten with fresh hashes, so the log also keeps a signed head
(<log>.head): how many records it holds and the hash of the last one, with an HMAC
under this installation's key (config/secrets/audit.key). `canarchist audit-verify`
checks both. The key protects against anyone who can change the case folder but not
read config/secrets; the account that runs the harness can read the key, so for
evidence against that account, copy the head somewhere it cannot write.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
MISMATCH = "audit_head_mismatch"  # recorded when the log no longer matches its signed head at the next write

try:  # several processes may write one case's log (dashboard + CLI): serialize with an OS file lock
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]


def install_key(root: Path) -> bytes:
    """This installation's audit key (config/secrets/audit.key, created once, mode 600)."""
    from .redact import load_key
    return load_key(Path(root) / "secrets" / "audit.key")


def head_path(path: Path) -> Path:
    return path.with_name(path.name + ".head")


def _mac(key: bytes, path: Path, records: int, digest: str) -> str:
    # bound to the case folder and file name, so a head cannot be moved to another case's log
    return hmac.new(key, f"{path.parent.name}/{path.name}:{records}:{digest}".encode(), hashlib.sha256).hexdigest()


def _read_head(path: Path) -> dict[str, Any] | None:
    try:
        head = json.loads(head_path(path).read_text(encoding="utf-8"))
        return head if isinstance(head, dict) else {}
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {}


def _head_ok(key: bytes, path: Path, head: dict[str, Any] | None) -> bool:
    try:
        return bool(head) and hmac.compare_digest(
            str(head.get("mac", "")), _mac(key, path, int(head.get("records", -1)), str(head.get("hash", ""))))
    except (TypeError, ValueError, AttributeError):
        return False


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
    def __init__(self, path: Path, operator: str, key: bytes | None = None):
        self.path = path
        self.operator = operator
        self.key = key  # with a key, every write also updates the signed head
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

    def _append(self, fh, event: str, data: dict[str, Any], prev: str) -> str:
        body = {"ts": datetime.now(timezone.utc).isoformat(), "operator": self.operator, "event": event, "data": data,
                "prev_hash": prev}
        if self.key:
            body["signed"] = True  # from here on the log has a signed head; verify reports a missing one
        digest = hashlib.sha256(_canon(body).encode()).hexdigest()
        body["hash"] = digest
        fh.seek(0, os.SEEK_END)
        fh.write((_canon(body) + "\n").encode("utf-8"))
        fh.flush()
        return digest

    def _records_now(self, fh, prev: str) -> tuple[int, str]:
        """(records in the log, why it no longer matches its signed head or "")."""
        assert self.key
        head = _read_head(self.path)
        if _head_ok(self.key, self.path, head) and head and head.get("hash") == prev:
            return int(head["records"]), ""
        fh.seek(0)
        n, signed = 0, False
        for line in fh:
            if line.strip():
                n += 1
                signed = signed or b'"signed":true' in line
        if head is None:
            return n, "the signed head is missing" if signed else ""
        if not _head_ok(self.key, self.path, head):
            return n, "the signed head does not match its signature"
        return n, (f"the signed head says {head['records']} records ending in {str(head['hash'])[:12]}, but the log "
                   f"has {n} ending in {prev[:12]}")

    def _write_head(self, records: int, digest: str) -> None:
        assert self.key
        target = head_path(self.path)
        tmp = target.with_name(target.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"records": records, "hash": digest, "mac": _mac(self.key, self.path, records, digest)}, fh)
        os.replace(tmp, target)

    def record(self, event: str, **data: Any) -> str:
        with self._lock, open(self.path, "a+b") as fh:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                prev = _tail_hash(fh)  # re-read: another process may have appended since our last record
                if self.key:
                    n, problem = self._records_now(fh, prev)
                    if problem:  # never re-sign a changed log silently: the change goes into the chain first
                        prev = self._append(fh, MISMATCH, {"problem": problem}, prev)
                        n += 1
                    digest = self._append(fh, event, data, prev)
                    self._write_head(n + 1, digest)
                else:
                    digest = self._append(fh, event, data, prev)
            finally:
                if fcntl:
                    fcntl.flock(fh, fcntl.LOCK_UN)
            self._prev = digest
            return digest


def verify(path: Path, key: bytes | None = None) -> tuple[bool, str]:
    """Check the hash chain, and with the installation's key the signed head: records cut off the end, a rewritten
    file, a missing head, or a mismatch found at a later write all fail."""
    prev, n, signed, mismatches = GENESIS, 0, False, []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            claimed = rec.pop("hash")
            if rec.get("prev_hash") != prev:
                return False, f"line {lineno}: chain broken (prev_hash mismatch)"
            if hashlib.sha256(_canon(rec).encode()).hexdigest() != claimed:
                return False, f"line {lineno}: record modified (hash mismatch)"
            prev, n = claimed, n + 1
            signed = signed or rec.get("signed") is True
            if rec.get("event") == MISMATCH:
                mismatches.append((lineno, str((rec.get("data") or {}).get("problem", ""))))
    if key is None:
        return True, "audit chain intact" + (" (signed head not checked: no key)" if signed else "")
    head = _read_head(path)
    if head is None:
        if signed:
            return False, "the signed head is missing: the log may have been cut or replaced"
        return True, "audit chain intact (no signed head yet: written before signed heads)"
    if not _head_ok(key, path, head):
        return False, "the signed head does not match its signature (changed, or made with another installation's key)"
    if int(head["records"]) != n or head.get("hash") != prev:
        return False, (f"the log has {n} records ending in {prev[:12]}, but its signed head says {head['records']} "
                       f"ending in {str(head.get('hash'))[:12]}: records were cut off, added or replaced")
    if mismatches:
        lineno, problem = mismatches[0]
        return False, (f"line {lineno}: when the harness next wrote the log, it no longer matched its signed head "
                       f"({problem}); records were changed outside the harness, or a write was cut off by a crash")
    return True, f"audit chain intact; signed head matches ({n} records)"
