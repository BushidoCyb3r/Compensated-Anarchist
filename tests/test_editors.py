"""Opening hunt plans in an editor: editor detection, links, launching, and the dashboard endpoints around them."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dashboard import H, login, make, wait_for  # noqa: E402

from compensated_anarchist import editors, huntplans  # noqa: E402
from compensated_anarchist.web.app import Dashboard  # noqa: E402

RECORDER = "import sys, pathlib; pathlib.Path(sys.argv[1]).with_suffix('.opened').write_text(' '.join(sys.argv[1:]))"


def test_links():
    assert editors.link("vscode", "/cases/A B/hunt_plan_x.md") == "vscode://file/cases/A%20B/hunt_plan_x.md"
    assert editors.link("vscode", "/c/p.md", "ssh-remote+soc") == "vscode://vscode-remote/ssh-remote+soc/c/p.md"
    assert editors.link("obsidian", "/c/p q.md") == "obsidian://open?path=%2Fc%2Fp%20q.md"
    with pytest.raises(ValueError):
        editors.link("notepad", "/x")


def test_exec_parsing():
    assert editors._exec_argv("gnome-text-editor %U") == ["gnome-text-editor", "{file}"]
    assert editors._exec_argv('"/opt/My Ed/ed" --new %F %F %i') == ["/opt/My Ed/ed", "--new", "{file}"]
    assert editors._exec_argv("kate -b") == ["kate", "-b"]  # no field code: the file is appended at launch


def _desktop(d: Path, did: str, **kv):
    d.mkdir(parents=True, exist_ok=True)
    body = "[Desktop Entry]\nType=Application\n" + "".join(f"{k}={v}\n" for k, v in kv.items())
    (d / f"{did}.desktop").write_text(body + "\n[Desktop Action new]\nName=New Window\nExec=ignored\n")


def test_detect_linux(tmp_path, monkeypatch):
    apps = tmp_path / "applications"
    _desktop(apps, "org.example.Edit", Name="Example Edit", Exec="exedit %U", MimeType="text/plain;")
    _desktop(apps, "com.microsoft.VSCode", Name="Visual Studio Code", Exec="/usr/share/code/code %F",
             MimeType="application/x-code-workspace;")  # no text/* mime: found by its desktop id
    _desktop(apps, "com.microsoft.VSCode.UrlHandler", Name="VS Code URL", Exec="code --open-url %U", MimeType="text/plain;")
    _desktop(apps, "hidden-ed", Name="Hidden", Exec="h %f", MimeType="text/plain;", NoDisplay="true")
    _desktop(apps, "org.example.Viewer", Name="Image Viewer", Exec="iv %f", MimeType="image/png;")
    _desktop(apps, "md.obsidian.Obsidian", Name="Obsidian", Exec="obsidian %u", MimeType="x-scheme-handler/obsidian;")
    monkeypatch.setattr(editors, "_app_dirs", lambda: [apps])
    monkeypatch.setattr(editors, "_xdg_default", lambda m: "org.example.Edit.desktop" if m == "text/plain" else "")
    monkeypatch.setattr(editors.sys, "platform", "linux")
    real_which = editors.shutil.which
    monkeypatch.setattr(editors.shutil, "which", lambda c: None if c == "gio" else real_which(c))
    found = editors.detect(refresh=True)
    assert [e.id for e in found] == ["org.example.Edit", "com.microsoft.VSCode", "md.obsidian.Obsidian"]
    ex, code, obs = found
    assert ex.default and ex.name == "Example Edit" and ex.argv == ["exedit", "{file}"]
    assert code.name == "VS Code" and code.argv == ["/usr/share/code/code", "{file}"]
    assert obs.url and obs.argv == ["xdg-open"]
    monkeypatch.setattr(editors.shutil, "which", lambda c: "/usr/bin/gio" if c == "gio" else real_which(c))
    with_gio = editors.detect(refresh=True)
    assert with_gio[0].argv == ["/usr/bin/gio", "launch", str(apps / "org.example.Edit.desktop")]
    editors.detect(refresh=True)  # leave the real detection cached for other tests


def test_open_file(tmp_path, monkeypatch):
    plan = tmp_path / "hunt_plan_apt29.md"
    plan.write_text("# plan\n")
    eds = [editors.Editor("rec", "Recorder", [sys.executable, "-c", RECORDER]),
           editors.Editor("obs", "Obsidian", [sys.executable, "-c",
                          "import sys, pathlib; pathlib.Path(sys.argv[2]).write_text(sys.argv[1])", "{file}",
                          str(tmp_path / "url.txt")], url=True),
           editors.Editor("bad", "Broken", [sys.executable, "-c", "import sys; sys.stderr.write('no display\\n'); sys.exit(3)"])]
    monkeypatch.setattr(editors, "detect", lambda refresh=False: eds)
    env = dict(os.environ)
    assert editors.open_file("rec", plan, env) == "opened hunt_plan_apt29.md in Recorder"
    assert (tmp_path / "hunt_plan_apt29.opened").read_text() == str(plan)
    editors.open_file("obs", plan, env)
    assert (tmp_path / "url.txt").read_text() == editors.link("obsidian", plan)
    with pytest.raises(ValueError, match="no display"):
        editors.open_file("bad", plan, env)
    with pytest.raises(ValueError, match="no editor"):
        editors.open_file("vim-in-a-shell", plan, env)
    monkeypatch.setattr(editors, "graphical_env", lambda: None)  # nobody logged in to the desktop
    with pytest.raises(ValueError, match="desktop session"):
        editors.open_file("rec", plan)


def test_viewer_on_host():
    def req(client, server):
        return SimpleNamespace(client=SimpleNamespace(host=client) if client else None, scope={"server": (server, 8765)})
    on = Dashboard.viewer_on_host
    assert on(req("127.0.0.1", "127.0.0.1")) and on(req("::1", "::1"))
    assert on(req("10.0.5.16", "10.0.5.16"))                # browser on the host, dashboard bound to its address
    assert on(req("::ffff:10.0.5.16", "10.0.5.16"))
    assert not on(req("10.0.5.20", "10.0.5.16"))            # another machine
    assert not on(req("testclient", "testserver")) and not on(req(None, "10.0.5.16"))


def test_plans_endpoints(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        h = dash.harness
        save = h.registry.tools["hunt_plan_save"].handler
        assert "saved" in save(name="APT29 Volt Typhoon", content="# APT29 / Volt Typhoon hunt plan\n\n| rank | T-code |\n")
        ev, _ = wait_for(c, "plan_saved")
        assert ev["data"]["name"] == "hunt_plan_APT29_Volt_Typhoon.md" and ev["data"]["kind"] == "plan"
        assert ev["data"]["title"] == "APT29 / Volt Typhoon hunt plan"
        assert any(r["kind"] == "plan_saved" for r in h.history.events(h.conversation["id"], 100))  # replayed later
        assert c.get("/api/state").json()["plans_folder"] == str(h.hunt_plans_dir)

        d = c.get("/api/plans").json()
        assert d["folder"] == str(h.hunt_plans_dir) and d["links"] == ["vscode", "obsidian"]
        f = d["files"][0]
        assert f["name"] == "hunt_plan_APT29_Volt_Typhoon.md" and f["hunted"] is False and f["path"].startswith(str(h.hunt_plans_dir))
        assert d["host"]["available"] is False and "not on the dashboard's host" in d["host"]["why"]  # test client is remote

        r = c.get("/api/plans/hunt_plan_apt29_volt_typhoon.md")  # case-insensitive
        assert r.status_code == 200 and r.text.startswith("# APT29") and r.headers["content-type"].startswith("text/plain")
        r = c.get("/api/plans/hunt_plan_APT29_Volt_Typhoon.md?download=1")
        assert 'attachment; filename="hunt_plan_APT29_Volt_Typhoon.md"' == r.headers["content-disposition"]
        # only files directly in the folder: no traversal, no symlinks out
        (h.case.dir / "secret.md").write_text("case secret")
        (h.hunt_plans_dir / "hunt_plan_link.md").symlink_to(h.case.dir / "secret.md")
        for bad in ("..%2Fsecret.md", "%2E%2E%2Fsecret.md", "hunt_plan_link.md", "nope.md"):
            assert c.get(f"/api/plans/{bad}").status_code == 404, bad

        url = "/api/plans/hunt_plan_APT29_Volt_Typhoon.md/open"
        assert c.post(url, json={"editor": "rec"}).status_code == 403  # CSRF header
        r = c.post(url, json={"editor": "rec"}, headers=H)
        assert r.status_code == 403 and "not on the dashboard's host" in r.json()["error"]

        # a browser on the host: the server launches the chosen editor and audits it
        monkeypatch.setattr(Dashboard, "viewer_on_host", staticmethod(lambda request: True))
        monkeypatch.setattr(editors, "detect", lambda refresh=False: [editors.Editor("rec", "Recorder", [sys.executable, "-c", RECORDER], default=True)])
        monkeypatch.setattr(editors, "graphical_env", lambda: dict(os.environ))
        host = c.get("/api/plans").json()["host"]
        assert host == {"available": True, "why": "", "editors": [{"id": "rec", "name": "Recorder", "default": True}]}
        r = c.post(url, json={"editor": "rec"}, headers=H)
        assert r.status_code == 200 and r.json()["message"] == "opened hunt_plan_APT29_Volt_Typhoon.md in Recorder"
        assert (h.hunt_plans_dir / "hunt_plan_APT29_Volt_Typhoon.opened").exists()
        assert c.post(url, json={"editor": "notepad"}, headers=H).status_code == 400
        assert c.post("/api/plans/..%2Fsecret.md/open", json={"editor": "rec"}, headers=H).status_code == 404
        audit = [json.loads(x) for x in (h.case.dir / "audit.jsonl").read_text().splitlines()]
        assert any(a["event"] == "dashboard_open_file" and a["data"]["editor"] == "rec" for a in audit)

        dash.editor_cfg["open_on_host"] = False
        r = c.post(url, json={"editor": "rec"}, headers=H)
        assert r.status_code == 403 and "open_on_host" in r.json()["error"]


def test_entries_and_find(tmp_path):
    folder = huntplans.ensure(tmp_path / "hunt_plans")
    huntplans.save(folder, "apt29", "# APT29 plan")
    huntplans.save(folder, "apt29", "# results", kind="results")
    (folder / "attack_layer_apt29.json").write_text("{}")
    rows = {e["name"]: e for e in huntplans.entries(folder)}
    assert rows["hunt_plan_apt29.md"]["hunted"] is True and rows["hunt_results_apt29.md"]["kind"] == "results"
    assert rows["attack_layer_apt29.json"]["kind"] == "layer" and rows["attack_layer_apt29.json"]["title"] == ""
    assert huntplans.find(folder, "HUNT_PLAN_APT29.MD") == folder / "hunt_plan_apt29.md"
    assert huntplans.find(folder, "../hunt_plans/hunt_plan_apt29.md") == folder / "hunt_plan_apt29.md"  # name only
    assert huntplans.find(folder, "older") is None and huntplans.find(folder, "") is None
