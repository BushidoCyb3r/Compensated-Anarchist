"""Start/stop scripts, first-time setup, the dashboard account and the token + account sign-in."""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import sys
import time
from pathlib import Path

import httpx
import pytest
import yaml
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dashboard import H, login, make  # noqa: E402
from test_harness import TEST_PASSWORD, TEST_USER, write_config  # noqa: E402

from compensated_anarchist import service  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.web import account  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


# ---- the account -------------------------------------------------------------------------------------------
def test_account_storage(tmp_path):
    p = tmp_path / "secrets" / "dashboard_account.json"
    assert not account.exists(p) and not account.verify(p, "a", "b")
    with pytest.raises(ValueError):
        account.save(p, "analyst1", "short")
    with pytest.raises(ValueError):
        account.save(p, "longusername1", "longusername1")
    account.save(p, "analyst1", "a long enough passphrase")
    raw = p.read_text()
    assert "a long enough passphrase" not in raw and json.loads(raw)["scheme"] == "scrypt"  # only a salted hash
    assert stat.S_IMODE(p.stat().st_mode) == 0o600 and stat.S_IMODE(p.parent.stat().st_mode) == 0o700
    assert account.verify(p, "analyst1", "a long enough passphrase")
    assert not account.verify(p, "analyst1", "a long enough passphrasE") and not account.verify(p, "analyst", "a long enough passphrase")
    created = json.loads(raw)["created"]
    account.save(p, "analyst1", "another long passphrase")
    assert json.loads(p.read_text())["created"] == created and account.verify(p, "analyst1", "another long passphrase")


# ---- sign-in: the token of this start AND the account ----------------------------------------------------------
def test_signin_needs_token_and_account(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        assert login(c, password="wrong password!!").status_code == 401        # right token, wrong password
        assert login(c, username="someone").status_code == 401                 # wrong username
        assert login(c, token="old-token-from-last-start").status_code == 401   # right account, stale token
        assert c.get("/api/state", headers={"Authorization": "Bearer test-token"}).status_code == 401  # token alone: no
        r = login(c)
        assert r.status_code == 200 and r.json()["user"] == TEST_USER
        assert c.get("/api/state").status_code == 200
        audit = [json.loads(x) for x in (tmp_path / "cases" / "WEB-1" / "audit.jsonl").read_text().splitlines()]
        fails = [a for a in audit if a["event"] == "dashboard_login_failed"]
        assert len(fails) == 3 and all("password" not in json.dumps(a["data"]) for a in fails)
        assert any(a["event"] == "dashboard_login" and a["data"]["user"] == TEST_USER for a in audit)


def test_session_idles_out(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        sid = c.cookies.get("ca_session")
        s = dash.sessions[sid]
        s["seen"] -= dash.idle_s - 60          # 11h59m without activity
        assert c.get("/api/state").status_code == 200
        before = s["seen"]
        c.get("/api/state")
        assert s["seen"] == before            # background reads do not keep it alive
        assert c.post("/api/activity", json={}, headers=H).status_code == 200
        assert s["seen"] > before             # the analyst using the page does
        s["seen"] -= dash.idle_s + 1
        assert c.get("/api/state").status_code == 401 and sid not in dash.sessions
        login(c)
        assert c.post("/api/logout", json={}, headers=H).json()["ok"] and not dash.sessions
        assert c.get("/api/state").status_code == 401


def test_no_account_means_no_signin(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    (tmp_path / "secrets" / "dashboard_account.json").unlink()
    with TestClient(app) as c:
        assert c.get("/api/public").json()["account"] is False
        r = login(c)
        assert r.status_code == 403 and "canarchist account create" in r.json()["error"]


# ---- first-time setup ------------------------------------------------------------------------------------------
def install(tmp_path: Path) -> Path:
    """A minimal installation: config/ with the shipped templates and a test harness.yaml."""
    cfgdir = tmp_path / "inst" / "config"
    cfgdir.mkdir(parents=True)
    for f in ("roe.yaml", "env.example", "models.yaml"):
        shutil.copy(ROOT / "config" / f, cfgdir / f)
    p = write_config(cfgdir)  # harness.yaml, roe.yaml (scoped), the dashboard account
    raw = yaml.safe_load(p.read_text())
    raw["harness"].update({"cases_dir": "../cases", "evidence_roots": ["../evidence"], "forensics_dir": "../forensics"})
    raw["memory"] = {"db_path": "../memory/mem.db"}
    raw["history"] = {"db_path": "../cases/_history.db"}
    raw["models_file"] = "models.yaml"
    p.write_text(yaml.safe_dump(raw))
    return p


def test_first_setup_builds_then_never_overwrites(tmp_path, monkeypatch):
    for k in ("CA_ROE", "CA_OPERATOR"):
        monkeypatch.delenv(k, raising=False)
    p = install(tmp_path)
    cfg = load_config(p)
    made = service.ensure_layout(cfg)
    home = tmp_path / "inst"
    for want in ("config/secrets/tls/", "run/", "cases/", "forensics/", "evidence/", "evidence/vault/", "memory/",
                 "config/roe.local.yaml", "config/.env", "config/models.local.yaml"):
        assert want in made, (want, made)
    assert stat.S_IMODE((home / "config" / ".env").stat().st_mode) == 0o600
    assert stat.S_IMODE((home / "run").stat().st_mode) == 0o700
    env = (home / "config" / ".env").read_text()
    assert "CA_ROE=roe.local.yaml" in env and "CA_OPERATOR=" in env
    # the analyst's data and edits, then a later start: nothing is created, changed or removed
    (home / "config" / ".env").write_text("MY_EDIT=1\n")
    (home / "cases" / "IR-1").mkdir()
    (home / "cases" / "IR-1" / "audit.jsonl").write_text("precious\n")
    (home / "config" / "roe.local.yaml").write_text("posture: observe\n")
    assert service.ensure_layout(load_config(p)) == []
    assert (home / "config" / ".env").read_text() == "MY_EDIT=1\n"
    assert (home / "cases" / "IR-1" / "audit.jsonl").read_text() == "precious\n"
    assert (home / "config" / "roe.local.yaml").read_text() == "posture: observe\n"


def test_tls_certificate(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    crt, key = tmp_path / "tls" / "d.crt", tmp_path / "tls" / "d.key"
    fp, renewed = service.ensure_cert(crt, key, "127.0.0.1")
    assert renewed and len(fp.split(":")) == 32 and stat.S_IMODE(key.stat().st_mode) == 0o600
    assert service.ensure_cert(crt, key, "127.0.0.1") == (fp, False)  # still good: kept
    fp2, renewed2 = service.ensure_cert(crt, key, "10.9.8.7")         # new address: new certificate
    assert renewed2 and fp2 != fp


# ---- start / stop, for real ---------------------------------------------------------------------------------
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def signin(url: str, token: str) -> int:
    with httpx.Client(base_url=url, timeout=10) as c:
        return c.post("/api/login", json={"token": token, "username": TEST_USER, "password": TEST_PASSWORD},
                      headers=H).status_code


def test_start_stop_keeps_data_and_renews_token(tmp_path, monkeypatch, capsys):
    p = install(tmp_path)
    cfg = load_config(p)
    port = free_port()
    opts = {"host": "127.0.0.1", "port": port, "case": "SVC-1"}
    try:
        assert service.start(cfg, str(p), opts) == 0
        first = json.loads((service.run_dir(cfg) / "dashboard.json").read_text())
        assert stat.S_IMODE((service.run_dir(cfg) / "dashboard.json").stat().st_mode) == 0o600
        out = capsys.readouterr().out
        assert f"Access token:  {first['token']}" in out and "username and password" in out
        log = (service.run_dir(cfg) / "dashboard.log").read_text()
        assert "open: http" in log and first["token"] not in log  # the background log never holds the token
        assert signin(first["url"], first["token"]) == 200
        assert service.start(cfg, str(p), opts) == 1  # already running (no terminal to confirm a restart)
        assert "already running" in capsys.readouterr().out
        audit = tmp_path / "inst" / "cases" / "SVC-1" / "audit.jsonl"
        assert audit.exists()

        assert service.stop(cfg) == 0
        assert not service.running(cfg) and not (service.run_dir(cfg) / "dashboard.json").exists()
        assert "untouched" in capsys.readouterr().out
        kept = audit.read_text()

        assert service.start(cfg, str(p), opts) == 0  # a later start: new token, same data
        second = json.loads((service.run_dir(cfg) / "dashboard.json").read_text())
        assert second["token"] != first["token"]
        assert signin(second["url"], first["token"]) == 401 and signin(second["url"], second["token"]) == 200
        assert audit.read_text().startswith(kept)  # the audit log continued; nothing was lost
    finally:
        service.stop(cfg)
    assert service.stop(cfg) == 0 and "not running" in capsys.readouterr().out


# ---- start.sh's questions, and live changes from the Settings page ------------------------------------------
def test_start_questions_remember_answers(tmp_path, monkeypatch):
    p = install(tmp_path)
    cfg = load_config(p)
    (tmp_path / "inst" / "cases" / "OLD-1").mkdir(parents=True)
    answers = iter(["maybe", "respond", "2", "bad id!", "IR-0042"])
    out = service.ask_startup(cfg, {}, ask=lambda prompt: next(answers))
    assert out["posture"] == "respond" and out["host"] == "127.0.0.1" and out["case"] == "IR-0042"
    assert service.saved_startup(cfg) == {"host": "127.0.0.1", "case": "IR-0042", "posture": "respond"}
    prompts = []
    again = service.ask_startup(cfg, {}, ask=lambda prompt: prompts.append(prompt) or "")  # Enter keeps the last choice
    assert (again["posture"], again["host"], again["case"]) == ("respond", "127.0.0.1", "IR-0042")
    assert "[respond]" in prompts[0] and "[2]" in prompts[1] and "[IR-0042]" in prompts[2]
    asked = []
    service.ask_startup(cfg, {"posture": "observe", "localhost": True}, ask=lambda prompt: asked.append(prompt) or "")
    assert len(asked) == 1 and asked[0].strip().startswith("Case")  # options skip their questions
    s = service.settings(cfg, {})
    assert s["host"] == "127.0.0.1" and s["case"] == "IR-0042" and s["posture"] == "respond"


def test_live_posture_and_case(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        info = c.get("/api/settings/startup").json()
        assert info["now"]["case"] == "WEB-1" and info["can_move"] is False and info["running"] is False
        assert c.post("/api/settings/posture", json={"posture": "respond"}, headers=H).json()["posture"] == "respond"
        assert dash.harness.roe.posture == "respond" and c.get("/api/state").json()["posture"] == "respond"
        assert c.post("/api/settings/posture", json={"posture": "attack"}, headers=H).status_code == 400
        old_case = dash.harness.case.dir
        (old_case / "notes.txt").write_text("keep me")
        r = c.post("/api/settings/case", json={"case": "IR-7"}, headers=H)
        assert r.status_code == 200 and dash.harness.case.id == "IR-7"
        st = c.get("/api/state").json()  # still signed in, on the new case, same posture
        assert st["case"]["id"] == "IR-7" and st["posture"] == "respond"
        # the reload signal is live only: kept in the backlog, every page load replayed it and reloaded again
        assert not [e for e in c.get("/api/events/poll?after=0").json() if e["kind"] == "case_switched"]
        assert (old_case / "notes.txt").read_text() == "keep me"
        assert c.post("/api/settings/case", json={"case": "../etc"}, headers=H).status_code == 400
        r = c.post("/api/settings/address", json={"address": "127.0.0.1"}, headers=H)
        assert r.status_code == 400 and "scripts/start.sh" in r.json()["error"]  # not started by the start script
        saved = service.saved_startup(dash.cfg)
        assert saved["posture"] == "respond" and saved["case"] == "IR-7"   # the next start's defaults
        audit = (dash.harness.case.dir / "audit.jsonl").read_text() + (old_case / "audit.jsonl").read_text()
        assert '"event":"posture_changed"' in audit and '"event":"case_switch"' in audit


def test_case_switch_reloads_the_page_once(tmp_path, monkeypatch):
    """Switching case from Settings reloads the page once and it stays put (it used to reload over and over)."""
    from test_accessibility import CHROME, Served

    if CHROME is None:
        pytest.skip("no Chrome/Chromium on this host")
    dash, _ = make(tmp_path, monkeypatch, {})
    with Served(dash, tmp_path) as chrome:
        chrome.send("Page.addScriptToEvaluateOnNewDocument",  # counts page loads in this tab from here on
                    {"source": "sessionStorage.loads = String(+(sessionStorage.loads || 0) + 1);"})
        chrome.js("go('settings'); true")
        chrome.wait("!!document.getElementById('run-case-new')")
        chrome.js("const f = document.getElementById('run-case-new'); f.value = 'IR-9'; f.dispatchEvent(new Event('input'));"
                  "[...document.querySelectorAll('button')].find((b) => b.textContent === 'Switch case').click(); true")
        chrome.wait("sessionStorage.loads === '1' && typeof S !== 'undefined' && !!S.st && S.st.case.id === 'IR-9'")
        time.sleep(2)
        assert chrome.js("sessionStorage.loads") == "1"  # one reload for the reply and the live event together
        # a reload signal left in the backlog (as an older dashboard kept it) is not acted on when replayed
        dash.seq += 1
        dash.events.append({"seq": dash.seq, "ts": time.time(), "kind": "case_switched", "data": {"case": "IR-9"}})
        chrome.js("setTimeout(() => location.reload(), 50); true")
        chrome.wait("sessionStorage.loads === '2' && typeof S !== 'undefined' && !!S.st")
        time.sleep(2)
        assert chrome.js("sessionStorage.loads") == "2"


def test_handoff_token_only_for_this_process(tmp_path):
    from compensated_anarchist.web.app import Dashboard

    f = tmp_path / "handoff.json"
    f.write_text(json.dumps({"pid": os.getpid() + 1, "token": "x", "expires": time.time() + 60}))
    assert Dashboard.handoff_token(tmp_path) == "" and not f.exists()
    f.write_text(json.dumps({"pid": os.getpid(), "token": "keep-me", "expires": time.time() + 60}))
    assert Dashboard.handoff_token(tmp_path) == "keep-me" and not f.exists()
    f.write_text(json.dumps({"pid": os.getpid(), "token": "old", "expires": time.time() - 1}))
    assert Dashboard.handoff_token(tmp_path) == ""


def test_move_address_in_place_keeps_token(tmp_path, capsys):
    main = service.primary_address()
    if main.startswith("127.") or not shutil.which("openssl"):
        pytest.skip("needs a non-loopback address and openssl")
    p = install(tmp_path)
    cfg = load_config(p)
    port = free_port()
    try:
        assert service.start(cfg, str(p), {"host": "127.0.0.1", "port": port, "case": "MOVE-1"}) == 0
        first = json.loads((service.run_dir(cfg) / "dashboard.json").read_text())
        with httpx.Client(base_url=first["url"], timeout=10) as c:
            assert c.post("/api/login", json={"token": first["token"], "username": TEST_USER, "password": TEST_PASSWORD},
                          headers=H).status_code == 200
            r = c.post("/api/settings/address", json={"address": "0.0.0.0"}, headers=H)
            assert r.status_code == 200 and r.json()["url"] == f"https://{main}:{port}"
        moved = None
        for _ in range(120):
            time.sleep(0.5)
            try:
                st = json.loads((service.run_dir(cfg) / "dashboard.json").read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if st["url"].startswith("https://"):
                moved = st
                break
        assert moved and moved["pid"] == first["pid"] and moved["token"] == first["token"]  # same process, same token
        with httpx.Client(base_url=moved["url"], timeout=10, verify=False) as c:
            assert c.post("/api/login", json={"token": first["token"], "username": TEST_USER, "password": TEST_PASSWORD},
                          headers=H).status_code == 200
        assert service.saved_startup(cfg)["host"] == "0.0.0.0"
        with httpx.Client(base_url=f"https://127.0.0.1:{port}", timeout=10, verify=False) as c:  # every interface
            assert c.get("/api/public").status_code == 200
    finally:
        service.stop(cfg)


# ---- where it listens: 0.0.0.0 or 127.0.0.1 -----------------------------------------------------------------
def test_addresses_are_all_interfaces_or_this_host(tmp_path):
    assert [service.normalize_host(v) for v in ("", "auto", "all", "0.0.0.0", "AUTO")] == ["0.0.0.0"] * 5
    assert [service.normalize_host(v) for v in ("localhost", "127.0.0.1")] == ["127.0.0.1"] * 2
    assert service.normalize_host("192.0.2.10") == "192.0.2.10"
    with pytest.raises(ValueError, match="0.0.0.0"):
        service.normalize_host("example.org")
    p = install(tmp_path)
    cfg = load_config(p)
    service.save_startup(cfg, host="auto")  # what older versions saved
    assert service.saved_startup(cfg)["host"] == "0.0.0.0" and service.settings(cfg, {})["host"] == "0.0.0.0"
    assert service.settings(cfg, {"localhost": True})["host"] == "127.0.0.1"
    answers = iter(["", "1", ""])
    out = service.ask_startup(cfg, {}, ask=lambda prompt: next(answers))
    assert out["host"] == "0.0.0.0" and service.saved_startup(cfg)["host"] == "0.0.0.0"
    assert service.public_url("127.0.0.1", 8765) == "http://127.0.0.1:8765"
    assert service.public_url("192.0.2.10", 8765) == "https://192.0.2.10:8765"
    assert service.public_url("0.0.0.0", 8765) != "https://0.0.0.0:8765"  # never an address to browse to


def test_certificate_names_every_address_when_listening_everywhere(tmp_path, monkeypatch):
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    crt, key = tmp_path / "tls" / "d.crt", tmp_path / "tls" / "d.key"
    monkeypatch.setattr(service, "host_addresses", lambda: ["192.0.2.10", "198.51.100.7"])
    fp, renewed = service.ensure_cert(crt, key, "0.0.0.0")
    san = service._out(["openssl", "x509", "-noout", "-ext", "subjectAltName", "-in", str(crt)])
    assert renewed and all(f"IP Address:{a}" in san for a in ("192.0.2.10", "198.51.100.7", "127.0.0.1"))
    assert service.ensure_cert(crt, key, "0.0.0.0") == (fp, False)  # the same addresses: kept
    monkeypatch.setattr(service, "host_addresses", lambda: ["192.0.2.10", "198.51.100.7", "203.0.113.4"])
    fp2, renewed2 = service.ensure_cert(crt, key, "0.0.0.0")  # a new address on the host: a new certificate
    assert renewed2 and fp2 != fp
    assert service.ensure_cert(crt, key, "192.0.2.10") == (fp2, False)  # one address it already names


def test_port_check_binds_like_the_server():
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert service._port_busy("127.0.0.1", port) and service._port_busy("0.0.0.0", port)
    assert not service._port_busy("0.0.0.0", port)


FAKE_FIREWALL = """#!/bin/sh
case "$1" in
  --state) [ "$FW_STATE" = running ] && { echo running; exit 0; }; echo "not running"; exit 252 ;;
  --get-active-zones) printf 'public (default)\n  interfaces: eth0\n' ;;
  --zone=public)
    case "$2" in
      --add-port=*|--remove-port=*) echo "$*" >> "$FW_LOG"; exit "${FW_DENY:-0}" ;;
    esac
    [ "$FW_FAIL" = 1 ] && exit 13; echo "$FW_PORTS" ;;
esac
"""
FAKE_SUDO = """#!/bin/sh
[ "$1" = "-n" ] && shift
exec "$@"
"""


def fake_firewall(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in (("firewall-cmd", FAKE_FIREWALL), ("sudo", FAKE_SUDO)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FW_STATE", "running")
    monkeypatch.setenv("FW_PORTS", "")
    monkeypatch.setenv("FW_LOG", str(tmp_path / "fw.log"))
    return tmp_path / "fw.log"


def test_firewall_note_and_ssh_tunnel_hint(tmp_path, monkeypatch):
    fake_firewall(tmp_path, monkeypatch)
    assert service.firewall_closed(8765) == ["public"]
    note = service.firewall_note(8765)
    assert "zone public" in note and "--open-firewall" in note and "SSH tunnel" in note
    for ports in ("8765/tcp", "8000-9000/tcp", "22/tcp 8765/tcp"):
        monkeypatch.setenv("FW_PORTS", ports)
        assert service.firewall_note(8765) == "", ports
    monkeypatch.setenv("FW_PORTS", "8765/udp")
    assert service.firewall_note(8765)
    monkeypatch.setenv("FW_FAIL", "1")  # it cannot tell (no permission): no guess
    assert service.firewall_note(8765) == ""
    monkeypatch.setenv("FW_STATE", "stopped")
    assert service.firewall_note(8765) == ""
    local = service.tunnel_hint("127.0.0.1", 8765)
    assert "ssh -L 8765:127.0.0.1:8765 " in local and "the sign-in link above" in local
    assert "https://127.0.0.1:8765/login" in service.tunnel_hint("0.0.0.0", 8765)


def test_start_opens_the_port_while_it_runs_and_stop_closes_it(tmp_path, monkeypatch):
    log = fake_firewall(tmp_path, monkeypatch)
    rd = tmp_path / "run"
    rd.mkdir()
    assert service.open_firewall(rd, 8765, ["public"], interactive=False) == ""
    state = rd / service.FIREWALL_STATE
    assert json.loads(state.read_text()) == {"port": 8765, "zones": ["public"]}
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert log.read_text().splitlines() == ["--zone=public --add-port=8765/tcp"]  # runtime only: no --permanent
    assert service.close_firewall(rd, interactive=False) == "Closed port 8765/tcp in the firewall again."
    assert not state.exists() and log.read_text().splitlines()[-1] == "--zone=public --remove-port=8765/tcp"
    assert service.close_firewall(rd, interactive=False) == ""  # nothing it opened: nothing to close
    monkeypatch.setenv("FW_DENY", "1")  # sudo refused (no password without a terminal)
    why = service.open_firewall(rd, 8765, ["public"], interactive=False)
    assert "zone public still blocks port 8765/tcp" in why and not state.exists()
    monkeypatch.delenv("FW_DENY")
    service.open_firewall(rd, 8765, ["public"], interactive=False)
    monkeypatch.setenv("FW_DENY", "1")
    left = service.close_firewall(rd, interactive=False)
    assert "still open" in left and "sudo firewall-cmd --zone=public --remove-port=8765/tcp" in left and state.exists()


def test_the_firewall_question_and_its_flags(tmp_path):
    cfg = load_config(install(tmp_path))
    assert service.want_firewall(cfg, 8765, ["public"], {"open_firewall": True}) is True
    assert service.want_firewall(cfg, 8765, ["public"], {"open_firewall": False}) is False
    assert service.want_firewall(cfg, 8765, ["public"], {}, interactive=False) is False  # never asked: leave it
    prompts = []
    assert service.want_firewall(cfg, 8765, ["public"], {}, ask=lambda p: prompts.append(p) or "") is True  # Enter: yes
    assert "[y]" in prompts[0] and "zone public" in prompts[0] and service.saved_startup(cfg)["firewall"] == "open"
    assert service.want_firewall(cfg, 8765, ["public"], {"yes": True}) is True  # --yes: the last answer
    answers = iter(["maybe", "n"])
    assert service.want_firewall(cfg, 8765, ["public"], {}, ask=lambda p: next(answers)) is False
    assert service.saved_startup(cfg)["firewall"] == "leave"
    prompts.clear()
    assert service.want_firewall(cfg, 8765, ["public"], {}, ask=lambda p: prompts.append(p) or "") is False
    assert "[n]" in prompts[0]  # Enter keeps the last answer
    with pytest.raises(ValueError):
        service.save_startup(cfg, firewall="sometimes")
