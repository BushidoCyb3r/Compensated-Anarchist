"""Isolated MemProcFS worker: `python -m compensated_anarchist.tools.memprocfs_runner '<json request>'`.

Runs in its own process so a native crash on a malformed image cannot take down the harness.
Works through MemProcFS' virtual file system (the same tree the FUSE mount shows), e.g.
  /sys/proc/proc.txt   process tree          /sys/net/netstat.txt  network connections
  /forensic/findevil/findevil.txt            /forensic/csv/*.csv   (forensic mode timelines)
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

MAX_READ = 64 * 1024 * 1024


def main() -> None:
    req = json.loads(sys.argv[1])
    import memprocfs

    args = ["-device", req["image"]]
    forensic = req["action"] in ("findevil", "timeline") or req.get("forensic")
    if forensic:
        args += ["-forensic", "1"]
    vmm = memprocfs.Vmm(args)
    vfs = vmm.vfs

    def read(path: str, length: int = MAX_READ, offset: int = 0) -> bytes:
        return vfs.read(path, length, offset)

    def text(path: str, limit: int) -> str:
        return read(path, limit).decode("utf-8", "replace")

    if forensic:  # wait for MemProcFS forensic analysis to complete
        deadline = time.time() + int(req.get("forensic_timeout_s", 3600))
        while time.time() < deadline:
            try:
                pct = int(text("/forensic/progress_percent.txt", 16).strip() or "0")
            except Exception:
                pct = 0
            if pct >= 100:
                break
            time.sleep(3)

    action, limit = req["action"], int(req.get("max_chars", 60000))
    out: dict = {"action": action}
    if action == "summary":
        out["processes"] = text("/sys/proc/proc.txt", limit // 2)
        out["netstat"] = text("/sys/net/netstat.txt", limit // 2)
    elif action == "processes":
        out["processes"] = text("/sys/proc/proc.txt", limit)
    elif action == "netstat":
        out["netstat"] = text("/sys/net/netstat.txt", limit)
    elif action == "findevil":
        out["findevil"] = text("/forensic/findevil/findevil.txt", limit)
    elif action == "timeline":
        dest = Path(req["outdir"])
        dest.mkdir(parents=True, exist_ok=True)
        files = []
        for name, meta in vfs.list("/forensic/csv").items():
            if not name.endswith(".csv"):
                continue
            size, off = int(meta.get("size", 0)), 0
            with open(dest / name, "wb") as fh:
                while off < size:
                    chunk = read(f"/forensic/csv/{name}", min(MAX_READ, size - off), off)
                    if not chunk:
                        break
                    fh.write(chunk)
                    off += len(chunk)
            files.append({"file": str(dest / name), "bytes": off})
        out["csv"] = files
    elif action == "list":
        out["entries"] = {k: {"size": v.get("size"), "dir": bool(v.get("f_isdir"))}
                          for k, v in vfs.list(req.get("path", "/")).items()}
    elif action == "read":
        out["data"] = text(req["path"], min(limit, int(req.get("length", limit))))
    else:
        raise SystemExit(f"unknown action {action}")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
