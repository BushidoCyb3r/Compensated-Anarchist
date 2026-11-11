"""Open case files (hunt plans, hunt results, Navigator layers) in a desktop editor, from the dashboard.

Two ways, both offered next to every saved plan:
  - **On this host:** the dashboard server launches an editor installed here: VS Code, Obsidian, the desktop's
    default text editor, or any other app that registers for text files. The editor appears on the host's screen,
    so the dashboard offers this only to a browser running on the host itself.
  - **Link:** a vscode:// or obsidian:// URL. The browser hands it to that editor on the viewer's own computer,
    which needs the file at the same path (same machine or a shared mount) or VS Code Remote-SSH (`vscode_remote`).

Launching takes an editor id from detect() and a file path the caller has already confined to the plans folder.
Nothing is run through a shell.
"""

from __future__ import annotations

import configparser
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

TEXT_TYPES = ("text/markdown", "text/x-markdown", "text/plain")
# Desktop ids of editors worth offering even when they do not register for text/* (VS Code registers none).
KNOWN = {
    "com.microsoft.VSCode": "VS Code", "code": "VS Code", "visual-studio-code": "VS Code",
    "code-oss": "Code - OSS", "codium": "VSCodium", "com.vscodium.codium": "VSCodium",
    "md.obsidian.Obsidian": "Obsidian", "obsidian": "Obsidian",
    "dev.zed.Zed": "Zed", "zed": "Zed", "sublime_text": "Sublime Text", "com.sublimetext.three": "Sublime Text",
    "org.gnome.TextEditor": "Text Editor", "org.gnome.gedit": "gedit", "org.kde.kate": "Kate",
    "org.kde.kwrite": "KWrite", "org.xfce.mousepad": "Mousepad", "mousepad": "Mousepad", "xed": "Xed",
    "org.geany.Geany": "Geany", "geany": "Geany", "pluma": "Pluma",
}
OBSIDIAN_IDS = {"md.obsidian.Obsidian", "obsidian"}
MAC_APPS = ["Visual Studio Code", "VSCodium", "Obsidian", "Zed", "Sublime Text", "BBEdit", "TextEdit"]
LINKS = {"vscode": "VS Code", "obsidian": "Obsidian"}
_DESKTOP_VAR = re.compile(r"^(HOME|USER|LOGNAME|SHELL|PATH|LANG|LANGUAGE|LC_[A-Z]+|TZ|TMPDIR|DISPLAY|WAYLAND_DISPLAY|"
                          r"XAUTHORITY|XDG_[A-Z_]+|DBUS_SESSION_BUS_ADDRESS|DESKTOP_SESSION|GDMSESSION|SYSTEMROOT|"
                          r"WINDIR|USERPROFILE|APPDATA|LOCALAPPDATA)$")
_CACHE_S = 60.0


@dataclass
class Editor:
    id: str
    name: str
    argv: list[str] = field(default_factory=list)  # the file path is appended (or replaces {file})
    default: bool = False
    url: bool = False                               # opened through an obsidian:// URL, not a file argument

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "default": self.default}


# ---- links (open on the viewer's computer) ------------------------------------------------------
def link(kind: str, path: Path | str, vscode_remote: str = "") -> str:
    p = str(path)
    if kind == "vscode":
        # vscode://file/<abs path>; with Remote-SSH: vscode://vscode-remote/ssh-remote+<host>/<abs path>
        return (f"vscode://vscode-remote/{quote(vscode_remote, safe='+')}{quote(p)}" if vscode_remote
                else f"vscode://file{quote(p)}")
    if kind == "obsidian":
        return f"obsidian://open?path={quote(p, safe='')}"  # the file must be inside an Obsidian vault
    raise ValueError(f"unknown link kind {kind!r}")


# ---- desktop session --------------------------------------------------------------------------
def graphical_env() -> dict[str, str] | None:
    """Environment for launching a GUI app on this host's desktop, or None when no desktop session is reachable.

    A dashboard started from SSH or a service has no DISPLAY/WAYLAND_DISPLAY; the user's systemd manager knows the
    graphical session's variables (GNOME and KDE import them), so they are borrowed from there.
    """
    # Only what a desktop app needs: the harness's environment also holds API keys from config/.env, and an editor
    # (or its extensions) must not inherit them.
    env = {k: v for k, v in os.environ.items() if _DESKTOP_VAR.match(k)}
    if sys.platform == "darwin" or os.name == "nt":
        return env
    if env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"):
        return env
    try:
        out = subprocess.run(["systemctl", "--user", "show-environment"], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    keep = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
            "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XDG_DATA_DIRS")
    for line in out.splitlines():
        k, _, v = line.partition("=")
        if k in keep and v:
            env[k] = v
    if env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"):
        return env
    run = Path(env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
    if (run / "wayland-0").exists():
        env.setdefault("XDG_RUNTIME_DIR", str(run))
        env["WAYLAND_DISPLAY"] = "wayland-0"
        return env
    return None


# ---- detection ------------------------------------------------------------------------------------
def _app_dirs() -> list[Path]:
    home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    dirs = [home] + [Path(p) for p in (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":") if p]
    dirs += [home / "flatpak/exports/share", Path("/var/lib/flatpak/exports/share")]
    seen, out = set(), []
    for d in dirs:
        a = d / "applications"
        if a not in seen and a.is_dir():
            seen.add(a)
            out.append(a)
    return out


def _desktop_entry(path: Path) -> dict[str, str] | None:
    cp = configparser.RawConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    try:
        cp.read(path, encoding="utf-8")
    except (configparser.Error, UnicodeDecodeError, OSError):
        return None
    return dict(cp["Desktop Entry"]) if cp.has_section("Desktop Entry") else None


def _exec_argv(exec_line: str) -> list[str] | None:
    """Desktop-entry Exec -> argv with {file} where the file goes (%f %F %u %U), other field codes dropped."""
    try:
        parts = shlex.split(exec_line)
    except ValueError:
        return None
    argv, placed = [], False
    for p in parts:
        if p in ("%f", "%F", "%u", "%U"):
            if not placed:
                argv.append("{file}")
                placed = True
        elif p in ("%i", "%c", "%k", "%d", "%D", "%n", "%N", "%v", "%m"):
            continue
        else:
            argv.append(p.replace("%%", "%"))
    return argv if argv else None


def _xdg_default(mime: str) -> str:
    try:
        return subprocess.run(["xdg-mime", "query", "default", mime], capture_output=True, text=True,
                              timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _detect_linux() -> list[Editor]:
    entries: dict[str, tuple[Path, dict[str, str]]] = {}
    for d in _app_dirs():  # earlier dirs win, as in the XDG spec
        for f in sorted(d.glob("*.desktop")):
            did = f.name[:-8]
            if did not in entries and (e := _desktop_entry(f)):
                entries[did] = (f, e)
    defaults = [x for x in (_xdg_default(m) for m in TEXT_TYPES) if x]
    default_id = defaults[0][:-8] if defaults else ""
    gio = shutil.which("gio")
    found: list[Editor] = []
    for did, (path, e) in entries.items():
        mimes = set(filter(None, e.get("MimeType", "").split(";")))
        known = did in KNOWN
        if not known and not mimes & set(TEXT_TYPES):
            continue
        if e.get("Type", "Application") != "Application" or e.get("NoDisplay") == "true" or e.get("Hidden") == "true":
            continue
        ex = e.get("Exec", "")
        if not ex or "UrlHandler" in did or "--open-url" in ex:
            continue
        if (te := e.get("TryExec")) and not shutil.which(te):
            continue
        if did in OBSIDIAN_IDS:  # Obsidian opens notes by URL, and only inside a vault
            found.append(Editor(did, "Obsidian", [gio, "open"] if gio else ["xdg-open"], url=True))
            continue
        argv = [gio, "launch", str(path)] if gio else _exec_argv(ex)
        if argv:
            found.append(Editor(did, KNOWN.get(did) or e.get("Name") or did, argv, default=did == default_id))
    if not any(x.id in OBSIDIAN_IDS for x in found) and _xdg_default("x-scheme-handler/obsidian"):
        found.append(Editor("obsidian", "Obsidian", [gio, "open"] if gio else ["xdg-open"], url=True))
    if not found and shutil.which("xdg-open"):
        found.append(Editor("xdg-open", "Default app", ["xdg-open"], default=True))
    found.sort(key=lambda x: (not x.default, x.url, x.name.lower()))
    return found


def _detect_mac() -> list[Editor]:
    out = [Editor("default", "Default text editor", ["open", "-t"], default=True)]
    for app in MAC_APPS:
        if any(Path(r, f"{app}.app").exists() for r in ("/Applications", str(Path.home() / "Applications"),
                                                        "/System/Applications")):
            out.append(Editor("obsidian", app, ["open"], url=True) if app == "Obsidian"
                       else Editor(app, app, ["open", "-a", app]))
    return out


_cache: tuple[float, list[Editor]] = (0.0, [])


def detect(refresh: bool = False) -> list[Editor]:
    """Editors installed on this host, the desktop's default text editor first. Cached for a minute."""
    global _cache
    if not refresh and _cache[1] and time.monotonic() - _cache[0] < _CACHE_S:
        return _cache[1]
    if sys.platform == "darwin":
        eds = _detect_mac()
    elif os.name == "nt":
        eds = [Editor("default", "Default app", [], default=True)]
    else:
        eds = _detect_linux()
    _cache = (time.monotonic(), eds)
    return eds


# ---- launch ----------------------------------------------------------------------------------------
def open_file(editor_id: str, path: Path, env: dict[str, str] | None = None) -> str:
    """Open `path` with the detected editor `editor_id`. The caller has confined `path` already."""
    ed = next((e for e in detect() if e.id == editor_id), None)
    if not ed:
        raise ValueError(f"no editor {editor_id!r} on this host")
    path = Path(path)
    if os.name == "nt" and not ed.argv:
        os.startfile(str(path))  # type: ignore[attr-defined]  # Windows default app
        return f"opened {path.name} with the default app"
    env = env if env is not None else graphical_env()
    if env is None:
        raise ValueError("no desktop session on this host to open an editor in (nobody is logged in graphically)")
    target = link("obsidian", path) if ed.url else str(path)
    argv = [a.replace("{file}", target) for a in ed.argv] if "{file}" in ed.argv else ed.argv + [target]
    try:
        p = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, start_new_session=True)
    except OSError as e:
        raise ValueError(f"could not start {ed.name}: {e}") from None
    try:
        # Launchers (gio, open, xdg-open) hand off and exit; an editor run directly keeps running - leave it be.
        _, err = p.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        threading.Thread(target=p.communicate, daemon=True).start()  # drain its stderr; reap it when it closes
        return f"opened {path.name} in {ed.name}"
    if p.returncode != 0:
        lines = err.decode(errors="replace").strip().splitlines()
        raise ValueError(f"{ed.name} did not open the file: {lines[-1] if lines else f'exit {p.returncode}'}")
    return f"opened {path.name} in {ed.name}"
