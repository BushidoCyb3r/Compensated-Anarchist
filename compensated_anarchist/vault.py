"""Evidence vault: where files pulled from endpoints land. Treat everything in it as hostile.

What the harness guarantees (no root needed):
  - the vault and its folders are owner-only (0700); a folder is locked read-only (0500) once its download ends
  - every file is read-only and never executable (0400)
  - executables and scripts, recognized by content (PE "MZ", ELF, Mach-O, Java class, "#!" scripts) and by risky
    extensions, are stored with a ".quarantined" suffix so no file association or double-click can launch them
  - MANIFEST.jsonl records the endpoint path, stored path, size and SHA-256 of every file
  - local_run refuses to execute anything inside the evidence roots (the vault included)
Hardening that needs root (SETUP.md): put the vault on a noexec,nosuid,nodev mount, so nothing in it can run
even when invoked deliberately through a loader or interpreter; optionally `chattr +i` sealed folders.
"""

from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

QUARANTINE_SUFFIX = ".quarantined"
EXEC_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
              b"\xca\xfe\xba\xbe", b"#!")
RISKY_EXT = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".class", ".sh", ".bash", ".zsh", ".ksh",
    ".csh", ".py", ".pyc", ".pl", ".rb", ".php", ".elf", ".so", ".ko", ".dylib", ".app", ".pkg", ".dmg", ".deb", ".rpm",
    ".apk", ".appimage", ".desktop", ".run", ".command", ".scpt", ".xll", ".iso", ".img",
}
README = """EVIDENCE VAULT - files pulled from endpoints. Treat every file here as hostile.
Files are read-only and not executable; executables and scripts carry a .quarantined suffix.
Analyze them with the harness's local tools (strings, YARA, capa, FLOSS...), which read files and never run them.
Never copy anything out of here to run it. MANIFEST.jsonl lists every file with its origin and SHA-256.
"""


def is_executable(name: str, head: bytes) -> bool:
    """True for programs and scripts: by content first, then by extension."""
    if any(head.startswith(m) for m in EXEC_MAGIC):
        return True
    return Path(name.lower()).suffix in RISKY_EXT


def ensure(root: Path) -> Path:
    """Create the vault (owner-only) with a warning README."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    readme = root / "README.txt"
    if not readme.exists():
        readme.write_text(README, encoding="utf-8")
        os.chmod(readme, 0o400)
    return root


def seal_file(path: Path) -> Path:
    """Make a stored file read-only and non-executable; defang executables with the quarantine suffix.
    Returns the final path."""
    path = Path(path)
    with open(path, "rb") as fh:
        head = fh.read(8)
    if is_executable(path.name, head) and not path.name.endswith(QUARANTINE_SUFFIX):
        target = path.with_name(path.name + QUARANTINE_SUFFIX)
        os.replace(path, target)
        path = target
    os.chmod(path, 0o400)
    return path


def seal_tree(folder: Path) -> None:
    """Lock a finished folder: files 0400, folders 0500 (nothing can be added, changed or executed)."""
    folder = Path(folder)
    if not folder.exists():
        return
    for dirpath, dirnames, filenames in os.walk(folder, topdown=False):
        for f in filenames:
            p = Path(dirpath) / f
            if not p.is_symlink():
                os.chmod(p, 0o400)
        os.chmod(dirpath, 0o500)


@contextmanager
def writable(folder: Path) -> Iterator[Path]:
    """Open a vault folder for writing (owner only), and seal it again afterwards - even after an error."""
    folder = Path(folder)
    if folder.exists():
        for dirpath, _, _ in os.walk(folder):
            os.chmod(dirpath, 0o700)
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    try:
        yield folder
    finally:
        seal_tree(folder)


def open_new(path: Path):
    """Create a new evidence file that never existed before (no overwrite, never executable while written)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def stored_copy(path: Path) -> Path | None:
    """The file already in the vault for this name (plain or quarantined), if any."""
    for p in (path, path.with_name(path.name + QUARANTINE_SUFFIX)):
        if p.exists():
            return p
    return None


def record(root: Path, entry: dict[str, Any]) -> None:
    """Append one line to the vault manifest (owner-only)."""
    m = Path(root) / "MANIFEST.jsonl"
    fd = os.open(m, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"time": datetime.now(timezone.utc).isoformat(), **entry}, default=str) + "\n")


def mount_of(path: Path) -> tuple[str, set[str]]:
    """The mount point holding `path` and its per-mount options (noexec, nosuid, ...), from /proc/self/mountinfo."""
    target = str(Path(path).resolve())
    best, opts = "/", set()
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return best, opts
    for line in lines:
        f = line.split()
        if len(f) < 6:
            continue
        mp = f[4].replace("\\040", " ")
        if (target == mp or target.startswith(mp.rstrip("/") + "/")) and len(mp) >= len(best):
            best, opts = mp, set(f[5].split(","))
    return best, opts


def status(root: Path) -> dict[str, Any]:
    root = Path(root)
    if not root.exists():
        return {"path": str(root), "exists": False}
    mp, opts = mount_of(root)
    files = sum(len(fs) for _, _, fs in os.walk(root))
    return {"path": str(root), "exists": True, "mode": oct(stat.S_IMODE(root.stat().st_mode)), "mount": mp,
            "noexec": "noexec" in opts, "nosuid": "nosuid" in opts, "files": files}
