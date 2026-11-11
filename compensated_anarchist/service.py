"""Start and stop the dashboard as a background service (scripts/start.sh, scripts/stop.sh).

start: makes sure the sign-in account exists (asks for it on the first start), makes sure a TLS certificate exists
for the address it serves on (self-signed, renewed before it expires or when the address changes), launches the
dashboard detached from the terminal, waits until it is ready, and prints the sign-in link with this start's
access token. Every start has a new token; the previous one stops working.

stop: stops the running dashboard cleanly (it finishes writing the audit log and chat history).

Neither touches your data: cases, conversations, memory, skills, audit logs, plans and the account stay as they are.
Runtime files (pid, log, the current token) live in run/ (mode 700), next to config/.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .config import HarnessConfig
from .web import account

READY_TIMEOUT_S = 180
STOP_TIMEOUT_S = 30


# ---- settings ----------------------------------------------------------------------------------------
STARTUP_KEYS = ("host", "case", "posture")  # the start-up defaults the dashboard's Settings page can change
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def dashboard_settings_path(cfg: HarnessConfig) -> Path:
    """The server-side settings the dashboard's Settings page saves (banner, start-up defaults)."""
    sp = Path(str((cfg.raw.get("dashboard") or {}).get("settings_path") or Path(cfg.cases_dir) / "_dashboard_settings.json"))
    return sp if sp.is_absolute() else cfg.root / sp


def saved_startup(cfg: HarnessConfig) -> dict[str, Any]:
    try:
        data = json.loads(dashboard_settings_path(cfg).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    serve = data.get("serve") if isinstance(data, dict) else None
    return {k: v for k, v in (serve or {}).items() if k in STARTUP_KEYS} if isinstance(serve, dict) else {}


def validate_startup(values: dict[str, Any]) -> dict[str, str]:
    """Clean start-up defaults from the Settings page: host auto | 127.0.0.1 | an IP address; case '' (the most
    recently used) or a case id; posture observe | respond."""
    out: dict[str, str] = {}
    host = str(values.get("host", "auto")).strip() or "auto"
    if host not in ("auto", "127.0.0.1") and not _is_ip(host):
        raise ValueError("address: auto, 127.0.0.1 or an IP address of this host")
    out["host"] = host
    case = str(values.get("case", "")).strip()
    if case and not CASE_RE.match(case):
        raise ValueError("case: letters, digits, . _ - (up to 64), or empty for the most recently used case")
    out["case"] = case
    posture = str(values.get("posture", "observe")).strip()
    if posture not in ("observe", "respond"):
        raise ValueError("posture: observe or respond")
    out["posture"] = posture
    return out


def save_startup(cfg: HarnessConfig, **values: str) -> None:
    """Remember start-up choices (from start.sh's questions or the Settings page) as the next start's defaults."""
    path = dashboard_settings_path(cfg)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data = data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        data = {}
    serve = data.get("serve") if isinstance(data.get("serve"), dict) else {}
    data["serve"] = {**serve, **validate_startup({**{"host": "auto", "case": "", "posture": "observe"}, **serve, **values})}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def ask_startup(cfg: HarnessConfig, opts: dict[str, Any], ask=input) -> dict[str, Any]:
    """start.sh's questions: posture, address and case. Enter keeps the default (the last choice); an option given
    on the command line skips its question. The answers become the next start's defaults."""
    cur = {"host": "auto", "case": "", "posture": "observe",
           **{k: v for k, v in (((cfg.raw.get("dashboard") or {}).get("serve")) or {}).items() if k in STARTUP_KEYS and v},
           **{k: v for k, v in saved_startup(cfg).items() if v}}
    answers: dict[str, str] = {}
    out = dict(opts)
    print("Start-up choices - press Enter to keep the [default]:")
    if not opts.get("posture"):
        d = cur["posture"] if cur["posture"] in ("observe", "respond") else "observe"
        while True:
            a = ask(f"  Posture: observe (watch and investigate; response actions are refused) or respond (response "
                    f"actions allowed, each approved by you) [{d}]: ").strip().lower() or d
            if a in ("o", "observe", "r", "respond"):
                answers["posture"] = out["posture"] = "observe" if a.startswith("o") else "respond"
                break
            print("    type observe or respond")
    if not (opts.get("host") or opts.get("localhost")):
        main = primary_address()
        d = "2" if cur["host"] == "127.0.0.1" else "1"
        while True:
            a = ask(f"  Serve on: 1) the main address {main} (HTTPS, reachable from the network) or 2) this host only "
                    f"(127.0.0.1) [{d}]: ").strip().lower() or d
            if a in ("1", "2", "main", "network", "local", "localhost"):
                answers["host"] = out["host"] = "127.0.0.1" if a in ("2", "local", "localhost") else "auto"
                break
            print("    type 1 or 2")
    if not opts.get("case"):
        d = cur["case"] or latest_case(cfg)
        recent = sorted((x for x in Path(cfg.cases_dir).glob("*") if x.is_dir() and not x.name.startswith(("_", "."))),
                        key=lambda x: x.stat().st_mtime, reverse=True)[:8]
        if recent:
            print(f"    cases: {', '.join(x.name for x in recent)}")
        while True:
            a = ask(f"  Case: an existing case or a new case id [{d}]: ").strip() or d
            if CASE_RE.match(a):
                answers["case"] = out["case"] = a
                break
            print("    letters, digits, . _ - (up to 64 characters)")
    if answers:
        save_startup(cfg, **answers)
    print()
    return out


def settings(cfg: HarnessConfig, opts: dict[str, Any]) -> dict[str, Any]:
    """What a start uses: command-line options, else the start-up defaults saved on the dashboard's Settings page,
    else harness.yaml dashboard.serve, else built-in defaults."""
    serve = {**dict(((cfg.raw.get("dashboard") or {}).get("serve")) or {}), **saved_startup(cfg)}
    out = {k: opts.get(k) if opts.get(k) not in (None, "") else serve.get(k) for k in
           ("host", "port", "case", "posture", "model", "tls_cert", "tls_key")}
    if opts.get("localhost"):
        out["host"] = "127.0.0.1"
    host = str(out["host"] or "auto")
    out["host"] = primary_address() if host == "auto" else host
    out["port"] = int(out["port"] or 8765)
    out["case"] = out["case"] or latest_case(cfg)
    out["posture"] = out["posture"] or "observe"
    rel = lambda p, d: (Path(os.path.expanduser(str(p or d))) if Path(str(p or d)).is_absolute()  # noqa: E731
                        else cfg.root / str(p or d))
    out["tls_cert"] = rel(out["tls_cert"], "secrets/tls/dashboard.crt")
    out["tls_key"] = rel(out["tls_key"], "secrets/tls/dashboard.key")
    out["run_dir"] = run_dir(cfg)
    return out


def run_dir(cfg: HarnessConfig) -> Path:
    raw = ((cfg.raw.get("dashboard") or {}).get("serve") or {}).get("run_dir") or "../run"
    p = Path(os.path.expanduser(str(raw)))
    return (p if p.is_absolute() else cfg.root / p).resolve()


def primary_address() -> str:
    """This host's main IPv4 address (the one its default route uses). No packet is sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def latest_case(cfg: HarnessConfig) -> str:
    cases = [d for d in Path(cfg.cases_dir).glob("*") if d.is_dir() and not d.name.startswith(("_", "."))]
    return max(cases, key=lambda d: d.stat().st_mtime).name if cases else "CASE-0001"


def loopback(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1")


# ---- TLS -------------------------------------------------------------------------------------------------
def ensure_cert(cert: Path, key: Path, host: str) -> tuple[str, bool]:
    """A self-signed certificate valid for `host`; made or renewed when missing, expiring within 30 days, or made
    for another address. Returns (SHA-256 fingerprint, renewed)."""
    if not shutil.which("openssl"):
        raise SystemExit("openssl is needed to create the dashboard's TLS certificate (or pass --localhost)")
    fresh = cert.exists() and key.exists() and _ok(["openssl", "x509", "-checkend", str(30 * 86400), "-noout",
                                                    "-in", str(cert)])
    if fresh:
        san = _out(["openssl", "x509", "-noout", "-ext", "subjectAltName", "-in", str(cert)])
        fresh = (f"IP Address:{host}" in san) or (f"DNS:{host}" in san)
    if not fresh:
        cert.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(cert.parent, 0o700)
        name = socket.gethostname()
        alt = [f"IP:{host}" if _is_ip(host) else f"DNS:{host}", "IP:127.0.0.1", f"DNS:{name}", "DNS:localhost"]
        old_umask = os.umask(0o077)
        try:
            r = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                                "-nodes", "-days", "365", "-keyout", str(key), "-out", str(cert),
                                "-subj", f"/CN=Compensated Anarchist ({name})",
                                "-addext", "subjectAltName=" + ",".join(dict.fromkeys(alt)),
                                "-addext", "basicConstraints=critical,CA:FALSE",
                                "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, text=True)
        finally:
            os.umask(old_umask)
        if r.returncode != 0:
            raise SystemExit(f"could not create the TLS certificate: {r.stderr.strip()[-400:]}")
        os.chmod(key, 0o600)
    fp = _out(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(cert)]).strip().split("=", 1)[-1]
    return fp, not fresh


def _is_ip(v: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in v else socket.AF_INET, v)
        return True
    except OSError:
        return False


def _ok(argv: list[str]) -> bool:
    return subprocess.run(argv, capture_output=True).returncode == 0


def _out(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True).stdout


# ---- processes ---------------------------------------------------------------------------------------
def _cmdline(pid: int) -> list[str]:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace").split("\0")
    except OSError:
        return []


def _is_dashboard(pid: int, config: Path | None = None) -> bool:
    """A live process of this user running `canarchist ... dashboard`, with this installation's config when
    `config` is given (so a recycled pid, or another install's dashboard, is never signalled)."""
    try:
        if os.stat(f"/proc/{pid}").st_uid != os.getuid():
            return False
    except OSError:
        return False
    argv = _cmdline(pid)
    joined = " ".join(argv)
    if not (("canarchist" in joined or "compensated_anarchist" in joined) and {"dashboard", "gui"} & set(argv)):
        return False
    return config is None or _config_of(pid, argv) == config


def _config_of(pid: int, argv: list[str]) -> Path | None:
    """The harness.yaml a canarchist process runs with: --config, else $CA_CONFIG, else config/harness.yaml in its
    working directory."""
    try:
        cwd = Path(os.readlink(f"/proc/{pid}/cwd"))
        env = dict(x.split("=", 1) for x in Path(f"/proc/{pid}/environ").read_bytes().decode(errors="replace")
                   .split("\0") if "=" in x)
    except OSError:
        return None
    path = argv[argv.index("--config") + 1] if "--config" in argv[:-1] else env.get("CA_CONFIG") or "config/harness.yaml"
    p = Path(path)
    return (p if p.is_absolute() else cwd / p).resolve()


def running(cfg: HarnessConfig) -> list[int]:
    """This installation's dashboards: the one in run/dashboard.pid, plus any started by hand with the same config."""
    mine = Path(cfg.config_path).resolve() if cfg.config_path else None
    pids: list[int] = []
    for d in Path("/proc").glob("[0-9]*"):
        p = int(d.name)
        if p != os.getpid() and _is_dashboard(p, mine):
            pids.append(p)
    return pids


def _url_of(cfg: HarnessConfig) -> str:
    try:
        return json.loads((run_dir(cfg) / "dashboard.json").read_text()).get("url", "")
    except (OSError, json.JSONDecodeError):
        return ""


# ---- first-time layout -------------------------------------------------------------------------------------
MODELS_LOCAL = """# Site model profiles (git-ignored). Merged over config/models.yaml, which documents every field:
# add your own profiles here, override fields of a shipped one, set default_model, or hide one with
# `enabled: false`. Secrets stay in config/.env as ${VARIABLES}.
#
# default_model: claude-sonnet
models: {}
"""


def ensure_layout(cfg: HarnessConfig) -> list[str]:
    """Create whatever the installation needs and does not have yet: folders, and the site config files from their
    templates. Only ever creates; never overwrites, empties or deletes anything. Returns what it created."""
    made: list[str] = []
    home = cfg.root.parent.resolve()

    def folder(p: Path, mode: int) -> None:
        p = Path(p).resolve()
        if not p.exists():
            if not (p == home or home in p.parents):  # outside the install (e.g. a mounted evidence share)
                return
            p.mkdir(parents=True, mode=mode)
            os.chmod(p, mode)
            made.append(f"{p.relative_to(home)}/")

    def file(p: Path, text: str, mode: int = 0o600) -> None:
        if p.exists():
            return
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)  # O_EXCL: never replace an existing file
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        made.append(str(p.resolve().relative_to(home)))

    folder(cfg.root / "secrets", 0o700)
    folder(cfg.root / "secrets" / "tls", 0o700)
    folder(run_dir(cfg), 0o700)
    folder(Path(cfg.cases_dir), 0o750)
    folder(Path(cfg.forensics_dir), 0o750)
    for r in cfg.evidence_roots:
        folder(Path(r), 0o750)
    folder(Path(cfg.forensics.get("vault_dir") or Path(cfg.evidence_roots[0]) / "vault"), 0o700)
    folder(Path(cfg.memory_db).parent, 0o750)
    folder(Path(cfg.history_db).parent, 0o750)
    new_roe = False
    if (cfg.root / "roe.yaml").exists() and not (cfg.root / "roe.local.yaml").exists():
        file(cfg.root / "roe.local.yaml", "# Site ROE: copy of roe.yaml. Fill in scope.allowed_targets and "
             "scope.protected_assets (SETUP.md section 9).\n# Git-ignored. Selected with CA_ROE=roe.local.yaml in "
             "config/.env.\n" + (cfg.root / "roe.yaml").read_text(encoding="utf-8"))
        new_roe = True
    if (cfg.root / "env.example").exists() and not (cfg.root / ".env").exists():
        text = (cfg.root / "env.example").read_text(encoding="utf-8")
        text = re.sub(r"(?m)^CA_OPERATOR=.*$", f"CA_OPERATOR={os.environ.get('USER') or 'analyst'}", text)
        if new_roe or (cfg.root / "roe.local.yaml").exists():
            text = re.sub(r"(?m)^CA_ROE=.*$", "CA_ROE=roe.local.yaml               # your site's scope (git-ignored)", text)
        file(cfg.root / ".env", text)
    if (cfg.root / "models.yaml").exists():
        file(cfg.root / "models.local.yaml", MODELS_LOCAL, 0o640)
    return made


# ---- start / stop ----------------------------------------------------------------------------------------
def start(cfg: HarnessConfig, config_path: str, opts: dict[str, Any]) -> int:
    made = ensure_layout(cfg)
    if made:
        print("Set up what was missing (nothing existing was changed):\n  " + "\n  ".join(made) + "\n")
    live = running(cfg)
    if live:
        url = _url_of(cfg)
        print(f"Compensated Anarchist is already running (pid {', '.join(map(str, live))}){f' at {url}' if url else ''}.")
        if not sys.stdin.isatty():
            print("Stop it with scripts/stop.sh, then start it again for a new access token.")
            return 1
        if input("Restart it with a new access token? Signed-in browsers must sign in again and a running operation "
                 "is stopped; your data stays. [y/N] ").strip().lower() not in ("y", "yes"):
            print("Left it running.")
            return 1
        stop(cfg)
        print()
    acct = account.default_path(cfg)
    if not account.exists(acct):
        if not sys.stdin.isatty():
            print("No dashboard account yet. Run scripts/start.sh in a terminal (it asks for a username and password),"
                  " or: canarchist account create")
            return 1
        print("First start: create the dashboard sign-in account.\n")
        if account.interactive(acct, "create") != 0:
            return 1
        print()
    if sys.stdin.isatty() and not opts.get("yes") and not opts.get("foreground_child"):
        opts = ask_startup(cfg, opts)
    s = settings(cfg, opts)
    argv = [_canarchist(), "--config", str(Path(config_path).resolve()), "dashboard", "--case", s["case"],
            "--posture", s["posture"], "--host", s["host"], "--port", str(s["port"]), "--run-dir", str(s["run_dir"])]
    if s["model"]:
        argv += ["--model", s["model"]]
    fingerprint = ""
    if not loopback(s["host"]):
        fingerprint, renewed = ensure_cert(s["tls_cert"], s["tls_key"], s["host"])
        argv += ["--tls-cert", str(s["tls_cert"]), "--tls-key", str(s["tls_key"])]
        if renewed:
            print(f"Made a new TLS certificate for {s['host']} ({s['tls_cert']}).")
    if _port_busy(s["host"], s["port"]):
        print(f"Port {s['port']} on {s['host']} is in use by another program. Free it or pass --port.")
        return 1
    rd = s["run_dir"]
    rd.mkdir(parents=True, exist_ok=True)
    os.chmod(rd, 0o700)
    (rd / "dashboard.json").unlink(missing_ok=True)
    env = {k: v for k, v in os.environ.items() if k != "CA_DASHBOARD_TOKEN"}
    if opts.get("foreground"):
        os.execve(argv[0], argv, env)  # serve() prints the link and token; Ctrl+C stops it
    log = rd / "dashboard.log"
    if log.exists():
        os.replace(log, rd / "dashboard.log.1")
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as out:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, env=env,
                                cwd=str(cfg.root.parent), start_new_session=True, close_fds=True)
    (rd / "dashboard.pid").write_text(str(proc.pid))
    print(f"Starting Compensated Anarchist (case {s['case']}, posture {s['posture'].upper()})"
          f" - connectors take a few seconds...", flush=True)
    state = None
    deadline = time.time() + READY_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            tail = log.read_text(errors="replace").strip().splitlines()[-15:]
            print("It stopped during start-up. Last lines of run/dashboard.log:\n  " + "\n  ".join(tail))
            (rd / "dashboard.pid").unlink(missing_ok=True)
            return 1
        try:
            st = json.loads((rd / "dashboard.json").read_text())
            if st.get("pid") == proc.pid:
                state = st
                break
        except (OSError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    if not state:
        print(f"Not ready after {READY_TIMEOUT_S}s; it is still starting. Check run/dashboard.log, or stop it with "
              f"scripts/stop.sh.")
        return 1
    conn = state.get("connectors") or {}
    ok = sum(1 for v in conn.values() if str(v).startswith("connected"))
    print(f"""
  Compensated Anarchist is running (pid {proc.pid})
  Case {state['case']} · model {state['model']} · posture {str(state['posture']).upper()} · connectors {ok}/{len(conn)} connected

  Sign in:       {state['url']}/login?token={state['token']}
  Access token:  {state['token']}
                 New at every start; the previous one no longer works. Keep it private.
  Then enter your username and password.
""" + (f"""  Certificate:   self-signed. Your browser warns once; check this SHA-256 fingerprint matches:
                 {fingerprint}
""" if fingerprint else "") + f"""
  Log: {log}     Stop: scripts/stop.sh
""")
    for name, v in conn.items():
        if not str(v).startswith("connected"):
            print(f"  note: connector {name}: {v}")
    return 0


def stop(cfg: HarnessConfig) -> int:
    rd = run_dir(cfg)
    pids = running(cfg)
    if not pids:
        print("Compensated Anarchist is not running.")
        (rd / "dashboard.pid").unlink(missing_ok=True)
        (rd / "dashboard.json").unlink(missing_ok=True)
        return 0
    for p in pids:
        try:
            os.kill(p, signal.SIGTERM)  # a clean shutdown: audit log and chat history are closed properly
        except ProcessLookupError:
            pass
    deadline = time.time() + STOP_TIMEOUT_S
    while time.time() < deadline and any(_is_dashboard(p) for p in pids):
        time.sleep(0.3)
    forced = [p for p in pids if _is_dashboard(p)]  # the same processes, if they are still there
    for p in forced:
        try:
            if os.getpgid(p) == p:  # started by start.sh in its own process group: take its connectors with it
                os.killpg(p, signal.SIGKILL)
            else:  # started by hand inside a shell's group: never signal the shell
                os.kill(p, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    (rd / "dashboard.pid").unlink(missing_ok=True)
    (rd / "dashboard.json").unlink(missing_ok=True)  # the old access token is gone with it
    print(f"Stopped Compensated Anarchist (pid {', '.join(map(str, pids))})"
          + (f"; had to force pid {', '.join(map(str, forced))}" if forced else "")
          + ". Your cases, conversations, memory, skills and audit logs are untouched.")
    return 0


def _canarchist() -> str:
    exe = Path(sys.executable).with_name("canarchist")
    return str(exe) if exe.exists() else (shutil.which("canarchist") or "canarchist")


def _port_busy(host: str, port: int) -> bool:
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0
