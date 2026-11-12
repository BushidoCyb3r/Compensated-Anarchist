"""Hunt plans folder: <case dir>/hunt_plans/. The hunt_planner saves plans (and their ATT&CK Navigator layers) here;
the threat_hunter finds and reads them here, and saves its results next to them. The hunter executes a plan only
when the analyst asks; being able to read the folder does not start anything.
"""

from __future__ import annotations

import difflib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .tools.registry import Tool, schema

KINDS = {"plan": "hunt_plan_", "results": "hunt_results_"}


def ensure(folder: Path) -> Path:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o750)
    return folder


def slug(name: str, prefixes: tuple[str, ...] = ("hunt_plan_", "hunt_results_")) -> str:
    s = re.sub(r"\.md$", "", Path(name).name, flags=re.I)
    for p in prefixes:
        if s.lower().startswith(p):
            s = s[len(p):]
            break
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")[:80] or "plan"


AGENT_COPY = ".agent"  # what the agent last saved, to tell the analyst's later edits apart


def write_versioned(folder: Path, filename: str, content: str) -> Path:
    """Write a file into the folder. An earlier version is kept in older/ with its timestamp, and a copy of what the
    agent wrote goes to .agent/ so the analyst's later edits can be shown (analyst_changes) and learned from."""
    folder = ensure(folder)
    path = folder / Path(filename).name
    if path.exists():
        older = ensure(folder / "older")
        stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        os.replace(path, older / f"{path.stem}.{stamp}{path.suffix}")
    path.write_text(content, encoding="utf-8")
    (ensure(folder / AGENT_COPY) / path.name).write_text(content, encoding="utf-8")
    return path


def edited(path: Path) -> bool:
    """True when the file was changed after the agent saved it (by the analyst, in an editor)."""
    copy = path.parent / AGENT_COPY / path.name
    try:
        return copy.is_file() and copy.read_bytes() != path.read_bytes()
    except OSError:
        return False


def analyst_changes(folder: Path, name: str, max_chars: int = 30000) -> str:
    """A unified diff from what the agent saved to the file as it is now: the analyst's edits."""
    path = find(folder, name)
    if not path:
        return f"No file named '{name}' in {folder}."
    copy = path.parent / AGENT_COPY / path.name
    if not copy.is_file():
        return f"{path.name}: no agent-saved copy to compare with (it was not saved by an agent)."
    old, new = copy.read_text(encoding="utf-8", errors="replace"), path.read_text(encoding="utf-8", errors="replace")
    if old == new:
        return f"{path.name}: unchanged since the agent saved it."
    diff = "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        f"{path.name} (as the agent saved it)", f"{path.name} (as the analyst left it)"))
    more = f"\n[... diff cut at {max_chars} characters]" if len(diff) > max_chars else ""
    return (f"The analyst edited {path.name} after it was saved. Their changes (- removed, + added) show what they "
            f"want done differently; they are the analyst's decisions.\n{diff[:max_chars]}{more}")


def save(folder: Path, name: str, content: str, kind: str = "plan") -> Path:
    """Write a plan or results file; an earlier version is kept in older/ with its timestamp."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {list(KINDS)}")
    return write_versioned(folder, f"{KINDS[kind]}{slug(name)}.md", content)


def title(p: Path) -> str:
    """First non-blank line of a markdown file, without the heading marks."""
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                return line.strip("# ").strip()[:100]
    except OSError:
        pass
    return ""


FILE_KINDS = (("hunt_plan_", "plan"), ("hunt_results_", "results"), ("attack_layer_", "layer"),
              ("vuln_report_", "vuln_report"), ("cte_plan_", "cte_plan"), ("cte_results_", "cte_results"),
              ("report_", "report"))


def kind_of(name: str) -> str:
    if name.startswith("report_") and name.endswith("_final.md"):
        return "report_final"
    return next((k for p, k in FILE_KINDS if name.startswith(p)), "other")


def entries(folder: Path) -> list[dict]:
    """The folder's files (not older/), newest first: name, kind, title, size, mtime, path, and for plans whether
    they have been hunted (a results file with the same name exists)."""
    folder = Path(folder)
    files = [p for p in folder.glob("*") if p.is_file() and not p.is_symlink()] if folder.exists() else []
    out = []
    for p in sorted(files, key=lambda p: p.stat().st_mtime, reverse=True):
        k = kind_of(p.name)
        out.append({"name": p.name, "kind": k, "title": title(p) if p.suffix == ".md" else "",
                    "size": p.stat().st_size, "mtime": p.stat().st_mtime, "path": str(p),
                    "hunted": (folder / p.name.replace("hunt_plan_", "hunt_results_", 1)).exists() if k == "plan" else None,
                    "edited": edited(p)})
    return out


def find(folder: Path, name: str) -> Path | None:
    """A file directly in the plans folder by exact name (case-insensitive). Never a path outside it or a symlink."""
    want = Path(str(name)).name.lower()
    folder = Path(folder)
    if not want or not folder.is_dir():
        return None
    root = folder.resolve()
    for p in folder.iterdir():
        if p.name.lower() == want and p.is_file() and not p.is_symlink() and p.resolve().parent == root:
            return p
    return None


def list_plans(folder: Path) -> str:
    folder = Path(folder)
    rows_ = sorted(entries(folder), key=lambda e: e["name"])
    if not rows_:
        return (f"No hunt plans yet in {folder}. The hunt_planner writes them when the analyst asks for a hunt plan "
                f"(hunt_plan playbook).")
    labels = {"plan": "plan", "results": "results", "layer": "navigator layer", "vuln_report": "vuln report", "other": "other"}
    rows = [f"Hunt plans folder: {folder}"]
    for e in rows_:
        when = datetime.fromtimestamp(e["mtime"], timezone.utc).strftime("%Y-%m-%d %H:%MZ")
        rows.append(f"  {e['name']:52s} {labels.get(e['kind'], e['kind']):16s} {when}  {e['title']}")
    for e in rows_:
        if e["kind"] == "plan":
            rows.append(f"  -> {e['name']}: {'hunted (results saved)' if e['hunted'] else 'not hunted yet'}")
    older = folder / "older"
    if older.exists():
        rows.append(f"  ({sum(1 for _ in older.iterdir())} earlier version(s) kept in older/)")
    return "\n".join(rows)


def read(folder: Path, name: str, offset: int = 0, length: int = 40000) -> str:
    folder = Path(folder)
    want = Path(name).name
    cands = [want, f"{want}.md", f"hunt_plan_{slug(want)}.md", f"hunt_results_{slug(want)}.md"]
    path = next((p for c in cands if (p := find(folder, c))), None)  # case-insensitive, this folder only
    if not path:
        return f"No hunt plan named '{name}'.\n" + list_plans(folder)
    text = path.read_text(encoding="utf-8", errors="replace")
    chunk = text[offset:offset + length]
    more = f"\n[... {len(text) - offset - len(chunk)} more characters: read again with offset={offset + len(chunk)}]" \
        if offset + len(chunk) < len(text) else ""
    return f"# {path.name} ({len(text)} chars)\n{chunk}{more}"


def tools(folder: Callable[[], Path], on_saved: Callable[[Path, str], None] | None = None) -> list[Tool]:
    """on_saved(path, kind) is called after each save (the dashboard shows the file with links to open it)."""
    S, I = {"type": "string"}, {"type": "integer"}

    def hunt_plan_save(name: str, content: str, kind: str = "plan") -> str:
        path = save(folder(), name, content, kind)
        if on_saved:
            on_saved(path, kind)
        return f"saved {path}"

    return [
        Tool("hunt_plan_list", "List this case's hunt plans folder: plans written by the hunt_planner, their ATT&CK Navigator "
             "layers, and hunt results saved by the threat_hunter (with which plans have been hunted).",
             schema({}), lambda: list_plans(folder())),
        Tool("hunt_plan_read", "Read a hunt plan or hunt results file from the hunt plans folder, by the name hunt_plan_list "
             "shows (or just the actors part, e.g. 'apt29'). Long files: continue with offset.",
             schema({"name": S, "offset": I, "length": I}, ["name"]),
             lambda name, offset=0, length=40000: read(folder(), name, offset, length)),
        Tool("hunt_plan_save", "Save markdown to the hunt plans folder: kind='plan' (the hunt_planner's plan) or "
             "kind='results' (the threat_hunter's outcome per hunt). The name is the actors/topic, e.g. 'apt29_volt_typhoon'. "
             "Earlier versions are kept.",
             schema({"name": S, "content": S, "kind": {"type": "string", "enum": list(KINDS)}}, ["name", "content"]),
             hunt_plan_save),
    ]
