"""Credential redaction: credentials in tool output are replaced before the model, the feed, spill files and the
audit hash see them, with keyed fingerprints that stay the same for the same value, and ordinary security text is
left alone. Every fake credential here is assembled at run time, so this file holds nothing secret scanners match."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from compensated_anarchist.audit import AuditLog
from compensated_anarchist.llm.base import ToolCall
from compensated_anarchist.redact import HARNESS_NOTE, Redactor
from compensated_anarchist.roe import RoeGate
from compensated_anarchist.tools.registry import Tool, ToolExecutor, ToolRegistry, schema

KEY = b"k" * 32


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


ES_ID = "AbCdEfGhIjKlMnOpQrSt"
ES_KEY = b64(ES_ID + ":" + "x" * 22)
TOKEN = "t0k" * 8
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow" + "A" * 40 + "\n-----END " + "RSA PRIVATE KEY-----"
JWT = "eyJ" + "hbGciOiJIUzI1" + ".eyJ" + "zdWIiOiIxMjM0" + "." + "s" * 20
VENDOR = {"aws-access-key-id": "AK" + "IA" + "Q" * 16, "github-token": "gh" + "p_" + "a" * 36,
          "slack-token": "xo" + "xb-" + "1" * 12, "ai-api-key": "s" + "k-ant-" + "b" * 24}


def red(text: str, env: dict | None = None) -> tuple[str, int]:
    return Redactor(KEY, env=lambda: env or {}).redact(text)


@pytest.mark.parametrize("text,secret,kind", [
    (f'curl -H "Authorization: ApiKey {ES_KEY}" https://so:9200/_security/_has_privileges', ES_KEY, f"apikey id:{ES_ID}"),
    (f'{{"Authorization": "Bearer {TOKEN}"}}', TOKEN, "bearer"),
    (f"curl -s https://10.0.5.16:8765/api/state -H 'Bearer {TOKEN}'", TOKEN, "bearer"),
    (f"Authorization: Basic {b64('analyst:aaaaaaaa')}", b64("analyst:aaaaaaaa"), "basic"),
    (f"proxy auth basic {b64('svc:bbbbbbbb')} sent", b64("svc:bbbbbbbb"), "basic"),
    ("GET https://svc:cccccccc@10.0.5.9/api", "cccccccc", "url-password"),
    (f"key file:\n{PEM}\nend", PEM, "private-key"),
    (f'cookie {JWT};', JWT, "jwt"),
    *[(f"found {v} in the script", v, k) for k, v in VENDOR.items()],
    ("mysql login password=dddddddd host=db", "dddddddd", "password"),
    ('{"api_key": "eeeeeeee", "user": "x"}', "eeeeeeee", "api_key"),
    ("client_secret: ffffffff", "ffffffff", "client_secret"),
    ("tool --token gggggggg --verbose", "gggggggg", "token"),
    ("tool --password=hhhhhhhh", "hhhhhhhh", "password"),
    ("GET /login?user=x&pass=llllllll HTTP/1.1", "llllllll", "pass"),
])
def test_each_kind_is_redacted(text, secret, kind):
    out, n = red(text)
    assert secret not in out and n == 1 and f"<redacted:{kind}" in out, out


@pytest.mark.parametrize("text", [
    "Logon Failure (Wrong Password)", "PasswordLastSet: 2026-01-01", '"password_last_set": "2026-01-01"',
    "bearer tokens were seen in 46 events", "165 passed, 10 skipped", '{"token": null, "secret": false}',
    "basic configuration options", "pass: true", "Authorization: Bearer", "an ApiKey header was present",
    "https://example.com/path?q=1", "C.1111111111111111", "TargetUserName: admin",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "token_count: 12", "Second pass: verify the beacons in Zeek",
    "kex: sk-ecdsa-sha2-nistp256@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",  # Zeek SSH algorithms
])
def test_ordinary_security_text_is_left_alone(text):
    assert red(text) == (text, 0)


def test_fingerprints_are_keyed_and_stable():
    a, b = Redactor(KEY), Redactor(b"z" * 32)
    t = f"Authorization: Bearer {TOKEN}"
    assert a.redact(t)[0] == a.redact(t + "")[0]  # the same value, the same fingerprint
    assert a.redact(t)[0] != b.redact(t)[0]  # another installation's key: another fingerprint
    assert hashlib.sha256(TOKEN.encode()).hexdigest()[:10] not in a.redact(t)[0]  # not a plain hash to guess against
    once, n1 = a.redact(f"{t} and password=iiiiiiii")
    assert n1 == 2 and a.redact(once) == (once, 0)  # redacting twice changes nothing


def test_this_installations_own_secrets_by_exact_value():
    env = {"SO_API_KEY": "jjjjjjjjjjjj", "ARCHER_PASSWORD": "kkkkkkkk", "GENAI_API_KEY_HEADER": "Authorization",
           "VELO_API_CONFIG": "/opt/x/api.yaml", "GENAI_CLIENT_KEY": "/etc/pki/client.key", "CA_MODEL": "claude-haiku",
           "SHORT_TOKEN": "abc"}
    r = Redactor(KEY, env=lambda: env)
    assert [n for n, _ in r.own_secrets()] == ["SO_API_KEY", "ARCHER_PASSWORD"]
    out, n = r.redact("ran with jjjjjjjjjjjj and kkkkkkkk; Authorization header; claude-haiku; /opt/x/api.yaml")
    assert n == 2 and "<redacted:SO_API_KEY fp:" in out and "<redacted:ARCHER_PASSWORD fp:" in out
    assert "Authorization header; claude-haiku; /opt/x/api.yaml" in out


def test_site_patterns_off_switch_and_the_key_file(tmp_path):
    cfg = SimpleNamespace(root=tmp_path / "config", raw={"redaction": {"patterns": [r"CORP-[0-9]{6}"]}})
    r = Redactor.for_config(cfg)
    keyfile = tmp_path / "config" / "secrets" / "redaction.key"
    assert keyfile.stat().st_mode & 0o777 == 0o600 and Redactor.for_config(cfg).key == r.key  # made once, reused
    assert "<redacted:site-pattern" in r.redact("badge CORP-123456 used")[0]
    off = Redactor.for_config(SimpleNamespace(root=tmp_path / "config", raw={"redaction": {"enabled": False}}))
    assert off.redact(f"Authorization: Bearer {TOKEN}") == (f"Authorization: Bearer {TOKEN}", 0)
    with pytest.raises(ValueError, match="redaction.patterns"):
        Redactor.for_config(SimpleNamespace(root=tmp_path / "config", raw={"redaction": {"patterns": ["("]}}))


def test_the_executor_redacts_before_the_model_the_feed_the_spill_and_the_audit(tmp_path):
    roe = tmp_path / "roe.yaml"
    roe.write_text(yaml.safe_dump({"posture": "respond", "default_tier": "auto", "rules": [], "scope": {"enforce": False}}))
    audit = AuditLog(tmp_path / "audit.jsonl", "t")

    async def approve(*_):
        return True, ""
    line = f'curl -H "Authorization: ApiKey {ES_KEY}" https://so:9200/x\n'
    reg = ToolRegistry()
    reg.add(Tool("search", "Search logs.", schema({"q": {"type": "string"}}), lambda q="": line * 400))
    events = []
    ex = ToolExecutor(reg, RoeGate(roe, audit, approve), audit, tmp_path / "spill", 2000,
                      lambda k, d: events.append((k, d)), redactor=Redactor(KEY))
    out, err = asyncio.run(ex.execute(ToolCall("c1", "search", {"q": "*"}), "threat_hunter", "hunt", reg.specs()))
    assert not err and ES_KEY not in out and f"<redacted:apikey id:{ES_ID} fp:" in out
    assert out.rstrip().endswith(HARNESS_NOTE.format(n=400)) and out.index("</tool_output>") < out.index("[harness:")
    spill = next((tmp_path / "spill").iterdir()).read_text()
    assert ES_KEY not in spill and spill.count("<redacted:apikey") == 400
    assert all(ES_KEY not in json.dumps(d) for _, d in events)
    rec = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(r["event"] == "tool_result" and r["data"].get("credentials_redacted") == 400 for r in rec)
