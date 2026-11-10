"""Per-case forensics folders: <forensics_dir>/<case-id>/, where the analyst drops artifacts for an investigation.

The folder is an evidence root: the local forensic tools can read it, `local_run` never executes anything in it,
and the forensics playbook starts from it. `inventory()` lists the case folder and the evidence vault with each
item's type detected from its content, so the team knows what it has before choosing a workflow.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

SUBFOLDERS = {
    "disk": "disk images (E01/Ex01, raw/dd, VMDK, VHD/VHDX, qcow2)",
    "memory": "memory images (raw, LiME, crash dumps, hiberfil, VM snapshots)",
    "logs": "EVTX, syslog, web/proxy/firewall logs, cloud audit logs",
    "network": "PCAP / PCAPNG, Zeek logs, NetFlow",
    "mobile": "Android / iOS extractions and backups",
    "triage": "triage packages (KAPE, Velociraptor offline collector, UAC zips)",
    "other": "anything else",
}
README = """CASE EVIDENCE FOLDER - drop artifacts for this investigation here (any subfolder; types are detected by content).
{subs}
The harness reads these files (forensic tools, YARA, capa...) and never runs them. Do not edit evidence after dropping
it: the team hashes and registers each item (chain of custody) before analysis. Malware samples are fine here.
Files pulled from endpoints by Velociraptor land separately, in the evidence vault (evidence/vault/).
"""

# (offset, magic, type) - checked in order; first match wins
_MAGIC: list[tuple[int, bytes, str]] = [
    (0, b"EVF\x09\x0d\x0a\xff\x00", "disk image (EWF/E01)"),
    (0, b"EVF2\x0d\x0a\x81\x00", "disk image (EWF2/Ex01)"),
    (0, b"KDMV", "disk image (VMDK sparse)"),
    (0, b"# Disk DescriptorFile", "disk image (VMDK descriptor)"),
    (0, b"vhdxfile", "disk image (VHDX)"),
    (0, b"conectix", "disk image (VHD)"),
    (0, b"QFI\xfb", "disk image (qcow2)"),
    (0, b"EMiL", "memory image (LiME)"),
    (0, b"PAGEDU64", "memory image (Windows crash dump)"),
    (0, b"PAGEDUMP", "memory image (Windows crash dump)"),
    (0, b"hibr", "memory image (hiberfil)"),
    (0, b"HIBR", "memory image (hiberfil)"),
    (0, b"ElfFile\x00", "Windows event log (EVTX)"),
    (4, b"LfLe", "Windows event log (legacy EVT)"),
    (0, b"regf", "registry hive"),
    (0, b"\xd4\xc3\xb2\xa1", "packet capture (PCAP)"),
    (0, b"\xa1\xb2\xc3\xd4", "packet capture (PCAP)"),
    (0, b"\x4d\x3c\xb2\xa1", "packet capture (PCAP, ns)"),
    (0, b"\x0a\x0d\x0d\x0a", "packet capture (PCAPNG)"),
    (0, b"MAM\x04", "Windows prefetch (compressed)"),
    (4, b"SCCA", "Windows prefetch"),
    (0, b"FILE0", "NTFS $MFT"),
    (0, b"SQLite format 3\x00", "SQLite database (browser / mobile / app artifact)"),
    (0, b"ANDROID BACKUP", "Android backup"),
    (0, b"PK\x03\x04", "zip archive (triage package?)"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (0, b"\x1f\x8b", "gzip archive"),
    (257, b"ustar", "tar archive"),
    (0, b"MZ", "Windows executable (PE) - analyze statically, never run"),
    (0, b"\x7fELF", "Linux executable (ELF) - analyze statically, never run"),
    (0, b"\xcf\xfa\xed\xfe", "macOS executable (Mach-O) - analyze statically, never run"),
    (0, b"\xce\xfa\xed\xfe", "macOS executable (Mach-O) - analyze statically, never run"),
    (0, b"\xca\xfe\xba\xbe", "Mach-O universal binary / Java class - analyze statically, never run"),
    (0, b"#!", "script - analyze statically, never run"),
    (0, b"%PDF", "PDF document"),
    (0, b"\xd0\xcf\x11\xe0", "OLE document (Office 97-2003 / MSI)"),
]
_EXT = {
    ".e01": "disk image (EWF/E01)", ".ex01": "disk image (EWF2/Ex01)", ".dd": "raw disk image", ".img": "raw image",
    ".raw": "raw image (disk or memory)", ".bin": "raw image (disk or memory)", ".vmdk": "disk image (VMDK)",
    ".vhd": "disk image (VHD)", ".vhdx": "disk image (VHDX)", ".qcow2": "disk image (qcow2)", ".iso": "optical image (ISO)",
    ".mem": "memory image", ".vmem": "memory image (VMware)", ".lime": "memory image (LiME)", ".dmp": "memory / crash dump",
    ".vmss": "VM suspend state (memory)", ".vmsn": "VM snapshot (memory)", ".evtx": "Windows event log (EVTX)",
    ".pcap": "packet capture (PCAP)", ".pcapng": "packet capture (PCAPNG)", ".log": "log file", ".json": "JSON log/data",
    ".jsonl": "JSON lines log", ".csv": "CSV data", ".xml": "XML data", ".txt": "text", ".pf": "Windows prefetch",
    ".lnk": "Windows shortcut (LNK)", ".zip": "zip archive (triage package?)", ".tar": "tar archive", ".gz": "gzip archive",
}


def safe_case_name(case_id: str) -> str:
    name = Path(str(case_id)).name
    if not name or name in (".", ".."):
        raise ValueError(f"bad case id {case_id!r}")
    return name


def ensure_case_folder(forensics_dir: Path, case_id: str) -> Path:
    """Create <forensics_dir>/<case-id>/ with typed subfolders and a README. Existing content is never touched."""
    root = Path(forensics_dir)
    if not root.exists():
        root.mkdir(parents=True)
        os.chmod(root, 0o750)
    folder = root / safe_case_name(case_id)
    new = not folder.exists()
    folder.mkdir(exist_ok=True)
    if new:
        os.chmod(folder, 0o750)
        for sub in SUBFOLDERS:
            (folder / sub).mkdir(exist_ok=True)
            os.chmod(folder / sub, 0o750)
    readme = folder / "README.txt"
    if not readme.exists():
        readme.write_text(README.format(subs="\n".join(f"  {k + '/':9s} {v}" for k, v in SUBFOLDERS.items())),
                          encoding="utf-8")
        os.chmod(readme, 0o440)
    return folder


def detect_type(path: Path) -> str:
    """What an artifact is, from its content first and its extension second."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
            mbr = head[510:512] == b"\x55\xaa" if len(head) >= 512 else False
            fh.seek(512)
            gpt = fh.read(8) == b"EFI PART"
    except OSError as e:
        return f"unreadable ({e.strerror})"
    for off, magic, kind in _MAGIC:
        if head[off:off + len(magic)] == magic:
            return kind
    if gpt:
        return "raw disk image (GPT)"
    if mbr and path.stat().st_size > 1 << 20:
        return "raw disk image (MBR)"
    if path.name.lower() in ("hiberfil.sys", "pagefile.sys", "swapfile.sys"):
        return f"memory artifact ({path.name})"
    if path.name.upper() in ("$MFT", "$LOGFILE", "$USNJRNL", "$J"):
        return f"NTFS metadata ({path.name})"
    if path.name.upper() in ("NTUSER.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "USRCLASS.DAT", "AMCACHE.HVE"):
        return "registry hive"
    return _EXT.get(path.suffix.lower(), "unknown - inspect with local_file_info")


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def inventory(case_folder: Path, vault_dir: Path | None, registered: set[str], include_vault: bool = True,
              max_entries: int = 500) -> str:
    """Every artifact available to this case, with detected type and chain-of-custody status."""
    lines: list[str] = []
    count = 0
    sections = [("Case evidence folder (dropped by the analyst)", Path(case_folder))]
    if include_vault and vault_dir:
        sections.append(("Evidence vault (pulled from endpoints by Velociraptor)", Path(vault_dir) / "velociraptor"))
    unregistered = 0
    for title, root in sections:
        lines.append(f"## {title}: {root}")
        files = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()
                       and p.name not in ("README.txt", "MANIFEST.jsonl")) if root.exists() else []
        if not files:
            lines.append("  (empty)")
            continue
        for p in files:
            if count >= max_entries:
                lines.append(f"  ... more files not shown (max_entries={max_entries})")
                break
            count += 1
            reg = str(p.resolve()) in registered
            unregistered += not reg
            lines.append(f"  {str(p.relative_to(root)):60s} {_human(p.stat().st_size):>9s}  {detect_type(p):45s} "
                         f"{'registered' if reg else 'NOT registered'}")
    lines.append("")
    lines.append(f"{count} file(s), {unregistered} not yet registered. Register each item with case_register_evidence "
                 "(hashes + chain of custody) before analyzing it; never modify evidence; never run executables.")
    return "\n".join(lines)
