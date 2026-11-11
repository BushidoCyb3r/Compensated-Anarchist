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
        assert (old_case / "notes.txt").read_text() == "keep me"
        assert c.post("/api/settings/case", json={"case": "../etc"}, headers=H).status_code == 400
        r = c.post("/api/settings/address", json={"address": "127.0.0.1"}, headers=H)
        assert r.status_code == 400 and "scripts/start.sh" in r.json()["error"]  # not started by the start script
        saved = service.saved_startup(dash.cfg)
        assert saved["posture"] == "respond" and saved["case"] == "IR-7"   # the next start's defaults
        audit = (dash.harness.case.dir / "audit.jsonl").read_text() + (old_case / "audit.jsonl").read_text()
        assert '"event":"posture_changed"' in audit and '"event":"case_switch"' in audit


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
            r = c.post("/api/settings/address", json={"address": "auto"}, headers=H)
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
        assert service.saved_startup(cfg)["host"] == "auto"
    finally:
        service.stop(cfg)
