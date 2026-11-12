"""Model profiles in config/models.yaml: the shipped file, site overrides, readiness, live reload, picker API."""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dashboard import H, login, make  # noqa: E402

from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.llm.openai_compat import OpenAICompatBackend  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_MODEL_SMALL", "GENAI_BASE_URL", "GENAI_MODEL",
        "CA_MODEL", "MY_LLM_API_KEY")


def shipped(tmp_path: Path, monkeypatch, local: str | None = None) -> Path:
    """A harness.yaml next to a copy of the shipped models.yaml (and optionally a models.local.yaml)."""
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    shutil.copy(ROOT / "config" / "models.yaml", tmp_path / "models.yaml")
    if local is not None:
        (tmp_path / "models.local.yaml").write_text(local)
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.safe_dump({"harness": {"cases_dir": "cases"}, "models_file": "models.yaml"}))
    return p


def test_shipped_models(tmp_path, monkeypatch):
    cfg = load_config(shipped(tmp_path, monkeypatch))
    groups = {p.group for p in cfg.models.values()}
    assert {"GenAI", "Claude", "ChatGPT", "Local"} <= groups
    assert {"genai-gateway", "claude-opus", "claude-sonnet", "claude-haiku", "chatgpt", "chatgpt-luna",
            "local-ollama", "local-vllm", "local-textmode", "my-local-model"} <= set(cfg.models)
    assert cfg.default_model == "my-local-model" and "claude-mythos" not in cfg.models  # commented out
    assert "CHANGE-ME" in cfg.model().problem()  # a fresh install starts on the template: it says what to set up
    m = cfg.models
    assert "CHANGE-ME" in m["my-local-model"].problem() and "CHANGE-ME" in m["genai-gateway"].problem()
    assert "OPENAI_API_KEY" in m["chatgpt"].problem()
    assert m["chatgpt"].model == "gpt-5.6-sol" and m["chatgpt"].max_tokens_param == "max_completion_tokens"
    assert m["local-ollama"].problem() == "" and m["local-ollama"].public()["ready"] is True
    assert m["my-local-model"].label == "My local model" and m["my-local-model"].public()["group"] == "Local"
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-other")
    cfg = load_config(tmp_path / "harness.yaml")
    assert cfg.models["chatgpt"].problem() == "" and cfg.models["chatgpt"].model == "gpt-other"


def test_site_file_merges(tmp_path, monkeypatch):
    local = yaml.safe_dump({"default_model": "lab", "models": {
        "lab": {"label": "Lab box", "group": "Local", "provider": "openai_compat", "base_url": "http://10.0.0.5:8080/v1", "model": "qwen"},
        "my-local-model": {"model": "llama3.3:70b"},          # fill in the template from the site file
        "chatgpt-luna": {"enabled": False},                   # hide a shipped profile
    }})
    cfg = load_config(shipped(tmp_path, monkeypatch, local))
    assert cfg.default_model == "lab" and cfg.models["lab"].label == "Lab box"
    t = cfg.models["my-local-model"]
    assert t.model == "llama3.3:70b" and t.base_url == "http://127.0.0.1:8080/v1" and t.problem() == ""  # fields kept
    assert "chatgpt-luna" not in cfg.models and "chatgpt" in cfg.models
    monkeypatch.setenv("CA_MODEL", "claude-haiku")
    assert load_config(tmp_path / "harness.yaml").default_model == "claude-haiku"  # env wins
    (tmp_path / "models.local.yaml").write_text(yaml.safe_dump({"models": {"x": {"provider": "openai_compat", "model": "m", "colour": "red"}}}))
    with pytest.raises(ValueError, match="unknown keys"):
        load_config(tmp_path / "harness.yaml")


def test_legacy_inline_models_still_work(tmp_path, monkeypatch):
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.safe_dump({"harness": {"default_model": "a"}, "models": {"a": {"provider": "openai_compat", "base_url": "http://x/v1", "model": "m"}}}))
    cfg = load_config(p)  # no models.yaml next to it
    assert list(cfg.models) == ["a"] and cfg.default_model == "a"


def test_reload(tmp_path, monkeypatch):
    cfg = load_config(shipped(tmp_path, monkeypatch, "models: {}\n"))
    assert cfg.reload_models() is False  # nothing changed
    local = tmp_path / "models.local.yaml"
    local.write_text(yaml.safe_dump({"models": {"new-one": {"provider": "openai_compat", "base_url": "http://h/v1", "model": "m"}}}))
    os.utime(local, (time.time() + 5, time.time() + 5))
    assert cfg.reload_models() is True and "new-one" in cfg.models and cfg.models_error == ""
    local.write_text("models: {broken: [\n")
    os.utime(local, (time.time() + 10, time.time() + 10))
    assert cfg.reload_models() is False and "new-one" in cfg.models and cfg.models_error  # old profiles kept


def test_openai_token_param(tmp_path, monkeypatch):
    cfg = load_config(shipped(tmp_path, monkeypatch))
    sent = {}

    async def fake_post(self, body):
        sent.update(body)
        return {"choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}], "usage": {}}

    monkeypatch.setattr(OpenAICompatBackend, "_post", fake_post)
    asyncio.run(OpenAICompatBackend(cfg.models["chatgpt"]).chat([{"role": "user", "content": "hi"}], []))
    assert sent["max_completion_tokens"] == 32000 and "max_tokens" not in sent and sent["reasoning_effort"] == "medium"
    sent.clear()
    asyncio.run(OpenAICompatBackend(cfg.models["local-ollama"]).chat([{"role": "user", "content": "hi"}], []))
    assert sent["max_tokens"] == 4096 and "max_completion_tokens" not in sent


def test_picker_api(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        st = c.get("/api/state").json()
        assert st["models"][0] == {"name": "fake", "label": "fake", "group": "Other", "provider": "openai_compat",
                                   "model": "x", "ready": True, "problem": ""}
        assert st["models_files"][0].endswith("models.yaml") and st["models_error"] == ""
        # the analyst adds a profile to models.yaml while the dashboard runs: it shows up without a restart
        (tmp_path / "models.yaml").write_text(yaml.safe_dump({"models": {
            "todo": {"label": "Not yet", "group": "Local", "provider": "openai_compat", "base_url": "http://h/v1", "model": "CHANGE-ME"},
            "fake2": {"label": "Second", "group": "Local", "provider": "openai_compat", "base_url": "http://h/v1", "model": "y"}}}))
        st = c.get("/api/state").json()
        rows = {m["name"]: m for m in st["models"]}
        assert rows["todo"]["ready"] is False and "CHANGE-ME" in rows["todo"]["problem"] and rows["fake2"]["ready"]
        r = c.post("/api/model", json={"name": "todo"}, headers=H)
        assert r.status_code == 400 and "not usable yet" in r.json()["error"]
        assert c.post("/api/model", json={"name": "fake2"}, headers=H).status_code == 200
        assert c.get("/api/state").json()["model"] == "fake2"


# ---- config/.env: read at startup and re-read while running ------------------------------------------------
from compensated_anarchist import agent as agent_mod, editors  # noqa: E402
from compensated_anarchist.config import EnvFile, parse_env_file  # noqa: E402
from compensated_anarchist.web.app import Dashboard, create_app  # noqa: E402


def forget(monkeypatch, *keys):
    """Make monkeypatch restore these variables (to unset) after the test, whoever sets them."""
    for k in keys:
        monkeypatch.setenv(k, "x")
        monkeypatch.delenv(k)


def bump(p: Path, s: float) -> None:
    os.utime(p, (time.time() + s, time.time() + s))


def test_parse_env_file(tmp_path):
    p = tmp_path / ".env"
    p.write_text("# comment\nA=1\nexport B=two\nC=           # optional: a note\nD=/etc/ca.crt   # copy of the CA\n"
                 "E=\"has spaces # not a comment\"\nF='single'\nG=x#y\n  H=indented\nnot a line\nI=\n")
    assert parse_env_file(p) == {"A": "1", "B": "two", "C": "", "D": "/etc/ca.crt", "E": "has spaces # not a comment",
                                 "F": "single", "G": "x#y", "H": "indented", "I": ""}


def test_env_file_load_and_refresh(tmp_path, monkeypatch):
    forget(monkeypatch, "CA_T_A", "CA_T_B", "CA_T_C", "CA_T_D")
    monkeypatch.setenv("CA_T_A", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CA_T_A=from-file\nCA_T_B=b1\nCA_T_C=c1\n")
    ef = EnvFile(p)
    ef.load()
    assert os.environ["CA_T_A"] == "from-shell" and os.environ["CA_T_B"] == "b1"  # the launching shell wins
    assert ef.refresh() == []  # unchanged file
    p.write_text("CA_T_A=from-file\nCA_T_B=b2\nCA_T_D=new\n")  # B changed, C removed, D added; A as before
    bump(p, 5)
    assert sorted(ef.refresh()) == ["CA_T_B", "CA_T_C", "CA_T_D"]
    assert os.environ["CA_T_A"] == "from-shell" and os.environ["CA_T_B"] == "b2" and os.environ["CA_T_D"] == "new"
    assert "CA_T_C" not in os.environ


def test_config_reads_env_file(tmp_path, monkeypatch):
    forget(monkeypatch, "CA_T_URL")
    (tmp_path / ".env").write_text("CA_T_URL=http://from-dotenv/v1\n")
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.safe_dump({"models": {"m": {"provider": "openai_compat", "base_url": "${CA_T_URL:-http://default/v1}", "model": "x"}}}))
    assert load_config(p).models["m"].base_url == "http://from-dotenv/v1"  # no `source config/.env` needed


def test_new_key_in_env_file_without_restart(tmp_path, monkeypatch):
    forget(monkeypatch, "CA_T_KEY")
    dash, app = make(tmp_path, monkeypatch, {})
    (tmp_path / "models.yaml").write_text(yaml.safe_dump({"models": {"cloud": {
        "label": "Cloud", "provider": "openai_compat", "base_url": "https://api.openai.com/v1", "model": "gpt-x",
        "api_key": "${CA_T_KEY:-}"}}}))
    with TestClient(app) as c:
        login(c)
        cloud = {m["name"]: m for m in c.get("/api/state").json()["models"]}["cloud"]
        assert not cloud["ready"] and "OPENAI_API_KEY" in cloud["problem"]
        (tmp_path / ".env").write_text("CA_T_KEY=sk-added-later\n")  # the analyst adds the key while it runs
        cloud = {m["name"]: m for m in c.get("/api/state").json()["models"]}["cloud"]
        assert cloud["ready"] and dash.cfg.models["cloud"].api_key == "sk-added-later"
        assert "sk-added-later" not in c.get("/api/state").text  # never shown
        assert c.post("/api/model", json={"name": "cloud"}, headers=H).status_code == 200


def test_runs_pick_up_a_rotated_key(tmp_path, monkeypatch):
    forget(monkeypatch, "CA_T_KEY")
    from test_harness import write_config

    cfg_path = write_config(tmp_path)
    raw = yaml.safe_load(cfg_path.read_text())
    raw["models"]["fake"]["api_key"] = "${CA_T_KEY:-}"
    cfg_path.write_text(yaml.safe_dump(raw))
    (tmp_path / ".env").write_text("CA_T_KEY=old\n")

    class Fake:
        def __init__(self, profile):
            self.profile = profile

        async def aclose(self):
            pass

    monkeypatch.setattr(agent_mod, "make_backend", Fake)
    dash = Dashboard(load_config(cfg_path), "WEB-9", token="test-token")
    with TestClient(create_app(dash)):
        h = dash.harness
        assert h.lead.backend.profile.api_key == "old"
        h.refresh_models()
        assert h.lead.backend.profile.api_key == "old"  # nothing changed: same backend
        (tmp_path / ".env").write_text("CA_T_KEY=rotated\n")
        bump(tmp_path / ".env", 5)
        h.refresh_models()  # what mission() and retro() do first
        assert h.lead.backend.profile.api_key == "rotated" and len(h.retired_backends) == 1


def test_editors_do_not_inherit_secrets(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("SO_API_KEY", "secret2")
    env = editors.graphical_env()
    assert env["DISPLAY"] == ":0" and "HOME" in env and "PATH" in env
    assert "ANTHROPIC_API_KEY" not in env and "SO_API_KEY" not in env


def test_a_model_that_is_not_set_up_stops_the_run_with_what_to_do(tmp_path, monkeypatch):
    """A fresh install starts on the my-local-model template: the first model call says what to set up, instead of a
    connection error, and nothing falls back to another (possibly hosted) model by itself."""
    import asyncio

    from compensated_anarchist.llm import ModelNotReady, NotReadyBackend, make_backend
    cfg = load_config(shipped(tmp_path, monkeypatch))
    b = make_backend(cfg.model())
    assert isinstance(b, NotReadyBackend) and b.profile_name == "my-local-model"
    with pytest.raises(ModelNotReady, match=r"'my-local-model' is not set up yet: fill in its CHANGE-ME.*model picker"):
        asyncio.run(b.chat([{"role": "user", "content": "hi"}], []))
    assert not isinstance(make_backend(cfg.model("local-ollama")), NotReadyBackend)  # a ready profile is used as is
