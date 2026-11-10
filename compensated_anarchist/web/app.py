"""Compensated Anarchist dashboard - local web GUI (`canarchist dashboard`).

One dashboard process drives one case: a single Harness (orchestrator + subagents + connectors) whose events
are broadcast to every connected browser over Server-Sent Events. Response actions that need approval are
parked as pending approvals and resolved from the browser. The case's conversations are persisted; the feed of
the open conversation is replayed when the dashboard starts or the analyst switches conversation.

Security model (the GUI can approve response actions, so it is stricter than a typical local dashboard):
  - a bearer token is ALWAYS required, even on localhost; /login?token=... exchanges it for an
    HttpOnly, SameSite=Strict session cookie
  - state-changing requests also need the X-CA-Request header (CSRF defense in depth)
  - binding to a non-loopback address requires TLS (or an explicit --allow-plaintext)
  - strict Content-Security-Policy; the frontend renders all agent/tool/log text as text, never HTML,
    because that data is attacker-influenced
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from importlib import resources
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Route

from .. import NAME, __version__
from ..agent import Harness
from ..audit import verify
from ..config import HarnessConfig
from ..memory import KINDS

COOKIE = "ca_session"
EPHEMERAL = {"telemetry", "delta", "ui_updated"}  # broadcast live, never kept in the replay buffer
MAX_LOGIN_FAILURES = 10    # per client address, per 5 minutes
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
MAX_MARKING_CHARS = 120


def classification_from(raw: dict[str, Any] | None) -> dict[str, str]:
    """Normalize and validate a classification banner setting: {"text", "background", "color"}. Empty text = off."""
    raw = raw or {}
    text = " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", str(raw.get("text") or "")).split())
    if len(text) > MAX_MARKING_CHARS:
        raise ValueError(f"the marking is longer than {MAX_MARKING_CHARS} characters")
    out = {"text": text, "background": str(raw.get("background") or "#007a33"), "color": str(raw.get("color") or "#ffffff")}
    for k in ("background", "color"):
        if not HEX_COLOR.match(out[k]):
            raise ValueError(f"{k} must be a color like #007a33")
        out[k] = out[k].lower()
    return out


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class Dashboard:
    def __init__(self, cfg: HarnessConfig, case_id: str, model: str | None = None, posture: str | None = None,
                 token: str | None = None, approval_timeout_s: int = 3600, harness: Harness | None = None,
                 conversation_id: str | None = None, new_conversation: bool = False):
        self.cfg = cfg
        self.token = token or os.environ.get("CA_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)
        self.session_secret = secrets.token_urlsafe(32)
        self.approval_timeout_s = approval_timeout_s
        self.events: deque[dict[str, Any]] = deque(maxlen=5000)
        self.seq = 0
        self.subscribers: set[asyncio.Queue] = set()
        self.pending: dict[str, dict[str, Any]] = {}
        self.run_task: asyncio.Task | None = None
        self.run_label = ""
        self.harness = harness or Harness(cfg, case_id, model, posture, interactive=True, on_event=self.emit)
        self.harness.on_event = self.emit  # harness.emit persists feed events, then forwards them here
        self.harness.roe.approver = self.web_approver
        self.start_args = (conversation_id, new_conversation)
        self.telemetry: dict[str, Any] = {}
        self.live: dict[str, dict[str, Any]] = {}  # agent_id -> reply being streamed {"text", "seq"}, for late joiners
        self.login_failures: dict[str, list[float]] = {}
        ui = cfg.raw.get("dashboard") or {}
        cls = ui.get("classification") or {}
        # The banner's default comes from harness.yaml; the Settings page can override it (saved server-side, for
        # every viewer) unless the config locks it.
        try:
            self.config_classification = classification_from(cls)
        except ValueError as e:
            raise ValueError(f"dashboard.classification in harness.yaml: {e}") from None
        self.classification_locked = bool(cls.get("locked"))
        sp = Path(str(ui.get("settings_path") or cfg.cases_dir / "_dashboard_settings.json"))
        self.settings_path = sp if sp.is_absolute() else cfg.root / sp
        saved = None if self.classification_locked else self._load_settings().get("classification")
        try:
            current = classification_from(saved) if saved is not None else self.config_classification
        except ValueError:  # a hand-edited settings file with a bad value: fall back to the config
            current = self.config_classification
        self.ui = {"classification": current, "consent_text": str(ui.get("consent_text") or "").strip()}

    # ---- event bus ----------------------------------------------------------------
    def emit(self, kind: str, data: dict[str, Any]) -> None:
        if kind == "telemetry" and data.get("agent_id") == "lead":
            self.telemetry = data
        self.seq += 1
        ev = {"seq": self.seq, "ts": time.time(), "kind": kind, "data": data}
        if kind == "delta":
            self._track_live(data)
        elif kind in ("text", "telemetry"):  # the streamed reply is complete
            self.live.pop(str(data.get("agent_id") or ""), None)
        if kind not in EPHEMERAL:
            self.events.append(ev)
        for q in list(self.subscribers):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                self.subscribers.discard(q)

    def _track_live(self, d: dict[str, Any]) -> None:
        aid = str(d.get("agent_id") or "")
        if d.get("reset"):
            self.live.pop(aid, None)
            return
        cur = self.live.get(aid, {}).get("text", "")
        off = int(d.get("offset") or 0)
        self.live[aid] = {"text": cur[:off] + str(d.get("text") or ""), "seq": self.seq}

    # ---- server-side settings -----------------------------------------------------
    def _load_settings(self) -> dict[str, Any]:
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_settings(self, data: dict[str, Any]) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.settings_path.with_name(self.settings_path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.settings_path)

    def classification_source(self) -> str:
        if self.classification_locked:
            return "locked"
        return "settings" if "classification" in self._load_settings() else "config"

    def set_classification(self, value: dict[str, Any] | None) -> dict[str, str]:
        """Change the banner for every viewer (None = back to the harness.yaml default). Audited."""
        if self.classification_locked:
            raise ValueError("the classification banner is locked in config/harness.yaml (dashboard.classification.locked)")
        old = dict(self.ui["classification"])
        settings = self._load_settings()
        if value is None:
            settings.pop("classification", None)
            new = dict(self.config_classification)
        else:
            new = classification_from(value)
            settings["classification"] = new
        self._save_settings(settings)
        self.ui["classification"] = new
        self.harness.audit.record("dashboard_setting", setting="classification", old=old, new=new, reset=value is None)
        self.emit("ui_updated", {"classification": new, "source": self.classification_source()})
        return new

    # ---- approvals ----------------------------------------------------------------
    async def web_approver(self, tool: str, arguments: dict[str, Any], rationale: str, why: str) -> tuple[bool, str]:
        aid = uuid.uuid4().hex[:12]
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending[aid] = {"id": aid, "tool": tool, "arguments": arguments, "rationale": rationale, "why": why,
                             "requested": time.time(), "future": fut}
        self.harness.emit("approval_request", self._public(self.pending[aid]))
        try:
            ok, note = await asyncio.wait_for(fut, self.approval_timeout_s)
        except asyncio.TimeoutError:
            ok, note = False, f"no analyst decision within {self.approval_timeout_s}s"
        except asyncio.CancelledError:
            ok, note = False, "operation stopped by analyst"
            self.pending.pop(aid, None)
            self.harness.emit("approval_resolved", {"id": aid, "approved": False, "note": note})
            raise
        self.pending.pop(aid, None)
        self.harness.emit("approval_resolved", {"id": aid, "approved": ok, "note": note, "by": self.cfg.operator})
        return ok, note

    @staticmethod
    def _public(p: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in p.items() if k != "future"}

    def resolve(self, aid: str, approve: bool, note: str) -> bool:
        p = self.pending.get(aid)
        if not p or p["future"].done():
            return False
        p["future"].set_result((approve, note))
        return True

    # ---- runs -------------------------------------------------------------------------
    def start_run(self, label: str, coro_factory) -> bool:
        if self.run_task and not self.run_task.done():
            return False
        self.run_label = label

        async def runner():
            self.emit("run_start", {"label": label})
            t0 = time.monotonic()
            h = self.harness
            try:
                text = await coro_factory()
                h.emit("run_end", {"label": label, "ok": True, "text": text, "seconds": round(time.monotonic() - t0, 1)})
            except asyncio.CancelledError:
                self._repair_all("operation stopped by analyst")
                h.emit("run_end", {"label": label, "ok": False, "text": "Stopped by analyst.", "stopped": True})
            except Exception as e:  # surface backend/model failures to the GUI
                self._repair_all(f"run failed: {type(e).__name__}")
                h.emit("run_end", {"label": label, "ok": False, "text": f"{type(e).__name__}: {e}"})

        self.run_task = asyncio.create_task(runner())
        return True

    def _repair_all(self, reason: str) -> None:
        h = self.harness
        if h.lead:
            h.lead.repair(reason)
        for sa in h.subagents.values():  # subagents cancelled mid-task keep a valid history for follow-ups
            if sa.agent and sa.status == "running":
                sa.status = "interrupted"
                sa.agent.repair(reason)

    def running(self) -> bool:
        return bool(self.run_task and not self.run_task.done())

    # ---- conversations ------------------------------------------------------------------
    def load_history(self) -> None:
        """Put the open conversation's saved feed on the bus (flagged as replay) for browsers to render."""
        self.events.clear()
        self.live.clear()
        h = self.harness
        if not h.conversation:
            return
        cid = h.conversation["id"]
        keep = (self.events.maxlen or 5000) - 200
        total = h.history.count(cid)
        if total > keep:
            self.emit("history_truncated", {"omitted": total - keep})
        for r in h.history.events(cid, keep):
            self.seq += 1
            self.events.append({"seq": self.seq, "ts": r["ts"], "kind": r["kind"], "data": r["data"], "replay": True})

    def switch(self, action) -> None:
        if self.running():
            raise ValueError("an operation is running - stop it first")
        action()
        self.load_history()
        conv = self.harness.conversation
        self.emit("conversation_switched", {"id": conv["id"] if conv else None})

    def stop(self) -> bool:
        if not self.run_task or self.run_task.done():
            return False
        for p in list(self.pending.values()):
            if not p["future"].done():
                p["future"].set_result((False, "operation stopped by analyst"))
        self.run_task.cancel()
        return True

    # ---- state ----------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        h = self.harness
        playbooks = sorted(f.name[:-3] for f in resources.files("compensated_anarchist").joinpath("playbooks").iterdir()
                           if f.name.endswith(".md"))
        return {
            "case": h.case.data,
            "evidence_folder": str(h.case_evidence_dir),
            "vault_folder": str(h.vault_dir / "velociraptor"),
            "session": h.session,
            "operator": self.cfg.operator,
            "posture": h.roe.posture,
            "model": h.model_name,
            "models": [{"name": n, "provider": p.provider, "model": p.model} for n, p in self.cfg.models.items()],
            "connectors": h.mcp.status,
            "experts": [{"name": n, "title": e.title, "description": e.description, "model": e.model or h.model_name}
                        for n, e in h.experts.items()],
            "conversation": h.conversation and {k: h.conversation.get(k) for k in ("id", "title", "created")},
            "subagents": [{**{k: v for k, v in sa.meta().items() if k != "context"},
                           "elapsed": round(time.time() - sa.started, 1) if sa.status == "running" and sa.started else None}
                          for sa in h.subagents.values()],
            "telemetry": self.telemetry,
            "live": self.live,
            "ui": {"classification": self.ui["classification"], "classification_source": self.classification_source(),
                   "classification_default": self.config_classification, "name": NAME, "version": __version__},
            "skills": h.skills.stats(),
            "memory": h.memory.stats(),
            "running": bool(self.run_task and not self.run_task.done()),
            "run_label": self.run_label,
            "pending": [self._public(p) for p in self.pending.values()],
            "playbooks": playbooks,
            "memory_kinds": KINDS,
            "last_seq": self.seq,
        }

    # ---- auth ---------------------------------------------------------------------------
    def _session_value(self) -> str:
        return hmac.new(self.session_secret.encode(), self.token.encode(), "sha256").hexdigest()

    def authed(self, request: Request) -> bool:
        cookie = request.cookies.get(COOKIE, "")
        if cookie and hmac.compare_digest(cookie, self._session_value()):
            return True
        auth = request.headers.get("authorization", "")
        return auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], self.token)


def create_app(dash: Dashboard) -> Starlette:
    static = resources.files("compensated_anarchist").joinpath("web/static")

    def guard(handler, write: bool = False):
        async def wrapped(request: Request) -> Response:
            if not dash.authed(request):
                return JSONResponse({"error": "unauthorized - sign in again"}, 401)
            if write and request.headers.get("x-ca-request") != "1":
                return JSONResponse({"error": "missing X-CA-Request header"}, 403)
            try:
                return await handler(request)
            except (ValueError, KeyError) as e:
                return JSONResponse({"error": str(e)}, 400)
        return wrapped

    async def body(request: Request) -> dict[str, Any]:
        try:
            data = await request.json()
        except json.JSONDecodeError:
            raise ValueError("invalid JSON body")
        if not isinstance(data, dict):
            raise ValueError("JSON object expected")
        return data

    # -- pages and sign-in --
    def page(name: str) -> Response:
        return FileResponse(str(static.joinpath(name)), media_type="text/html")

    async def login_page(request: Request) -> Response:
        return page("login.html")  # the token in ?token=… is read by login.js and posted, never put in a cookie by GET

    async def public_info(request: Request) -> Response:
        return JSONResponse({"name": NAME, "version": __version__, "classification": dash.ui["classification"],
                             "consent_text": dash.ui["consent_text"], "authed": dash.authed(request)})

    async def api_login(request: Request) -> Response:
        if request.headers.get("x-ca-request") != "1":
            return JSONResponse({"error": "missing X-CA-Request header"}, 403)
        client = request.client.host if request.client else "?"
        now = time.time()
        recent = [t for t in dash.login_failures.get(client, []) if now - t < 300]
        dash.login_failures[client] = recent
        if len(recent) >= MAX_LOGIN_FAILURES:
            return JSONResponse({"error": "too many failed sign-ins; wait five minutes"}, 429)
        try:
            d = await body(request)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        if dash.ui["consent_text"] and d.get("consent") is not True:
            return JSONResponse({"error": "acknowledge the notice and consent to sign in"}, 400)
        if not hmac.compare_digest(str(d.get("token", "")), dash.token):
            recent.append(now)
            await asyncio.sleep(0.4)
            return JSONResponse({"error": "that token is not valid for this dashboard"}, 401)
        dash.login_failures.pop(client, None)
        dash.harness.audit.record("dashboard_login", client=client, consent=bool(dash.ui["consent_text"]))
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE, dash._session_value(), httponly=True, samesite="strict",
                        secure=request.url.scheme == "https")
        return resp

    async def api_logout(request: Request) -> Response:
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE)
        return resp

    async def index(request: Request) -> Response:
        if not dash.authed(request):
            return RedirectResponse("/login", 303)
        return page("index.html")

    async def asset(request: Request) -> Response:
        name = request.path_params["name"]
        if name not in ("app.js", "app.css", "login.js", "favicon.svg", "logo.svg"):
            return PlainTextResponse("not found", 404)
        types = {"js": "text/javascript", "css": "text/css", "svg": "image/svg+xml"}
        return FileResponse(str(static.joinpath(name)), media_type=types[name.rsplit(".", 1)[1]])

    # -- read --
    async def get_state(request: Request) -> Response:
        return JSONResponse(dash.state())

    async def events_poll(request: Request) -> Response:
        after = int(request.query_params.get("after", "0"))
        return JSONResponse([e for e in dash.events if e["seq"] > after])

    async def events_stream(request: Request) -> Response:
        after = int(request.query_params.get("after", "0"))
        q: asyncio.Queue = asyncio.Queue(maxsize=10000)
        backlog = [e for e in dash.events if e["seq"] > after]
        dash.subscribers.add(q)

        async def gen():
            try:
                for e in backlog:
                    yield f"id: {e['seq']}\ndata: {json.dumps(e, default=str)}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        e = await asyncio.wait_for(q.get(), 15)
                        yield f"id: {e['seq']}\ndata: {json.dumps(e, default=str)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                dash.subscribers.discard(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    async def memory_list(request: Request) -> Response:
        status = request.query_params.get("status") or None
        kind = request.query_params.get("kind") or None
        return JSONResponse(dash.harness.memory.list(status, kind, 300))

    async def audit(request: Request) -> Response:
        path = dash.harness.case.dir / "audit.jsonl"
        ok, msg = verify(path)
        limit = min(int(request.query_params.get("limit", "300")), 2000)
        lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
        return JSONResponse({"verified": ok, "message": msg, "records": [json.loads(x) for x in lines][::-1]})

    async def tools(request: Request) -> Response:
        h = dash.harness
        rows = []
        for t in h.registry.tools.values():
            tier, why = h.roe.classify(t.name, {}, t.annotations, t.server)
            rows.append({"name": t.name, "tier": tier, "why": why, "server": t.server or "local",
                         "description": t.description[:300]})
        return JSONResponse(rows)

    async def report(request: Request) -> Response:
        p = dash.harness.case.dir / "report.md"
        return PlainTextResponse(p.read_text(encoding="utf-8") if p.exists() else "")

    # -- write --
    async def message(request: Request) -> Response:
        d = await body(request)
        text = str(d.get("text", "")).strip()
        playbook = str(d.get("playbook", "")).strip()
        if playbook:
            pb = resources.files("compensated_anarchist").joinpath(f"playbooks/{playbook}.md")
            if not pb.is_file():
                raise ValueError(f"unknown playbook {playbook}")
            text = pb.read_text(encoding="utf-8") + "\n\n# Details from analyst\n" + (text or "(none)")
        if not text:
            raise ValueError("empty message")
        if not dash.start_run(playbook or "mission", lambda: dash.harness.mission(text, str(d.get("text", "")), playbook)):
            return JSONResponse({"error": "an operation is already running - wait or press Stop"}, 409)
        return JSONResponse({"ok": True})

    async def stop(request: Request) -> Response:
        return JSONResponse({"ok": dash.stop()})

    async def approval(request: Request) -> Response:
        d = await body(request)
        ok = dash.resolve(request.path_params["aid"], bool(d.get("approve")), str(d.get("note", ""))[:2000])
        return JSONResponse({"ok": ok}, 200 if ok else 404)

    async def verdict(request: Request) -> Response:
        d = await body(request)
        ok = dash.harness.set_verdict(str(d["finding_id"]), str(d["verdict"]), str(d.get("note", "")))
        dash.emit("case_updated", {"reason": "verdict"})
        return JSONResponse({"ok": ok}, 200 if ok else 404)

    async def remember(request: Request) -> Response:
        d = await body(request)
        mid = dash.harness.remember(str(d["kind"]), str(d["title"]), str(d["content"]))
        dash.emit("memory_updated", {"id": mid})
        return JSONResponse({"ok": True, "id": mid})

    async def memory_action(request: Request) -> Response:
        d = await body(request)
        status = {"promote": "approved", "reject": "rejected", "retire": "retired"}[str(d["action"])]
        ok = dash.harness.memory.set_status(int(request.path_params["mid"]), status, dash.cfg.operator)
        dash.emit("memory_updated", {"id": request.path_params["mid"], "status": status})
        return JSONResponse({"ok": ok})

    async def retro(request: Request) -> Response:
        if not dash.start_run("after-action review", dash.harness.retro):
            return JSONResponse({"error": "an operation is already running"}, 409)
        return JSONResponse({"ok": True})

    async def rate(request: Request) -> Response:
        d = await body(request)
        r = int(d["rating"])
        if not 1 <= r <= 5:
            raise ValueError("rating must be 1-5")
        dash.harness.rate(r, str(d.get("note", "")))
        dash.emit("rated", {"rating": r})
        return JSONResponse({"ok": True})

    async def model(request: Request) -> Response:
        d = await body(request)
        if dash.run_task and not dash.run_task.done():
            return JSONResponse({"error": "cannot switch model during an operation"}, 409)
        dash.harness.switch_model(str(d["name"]))
        dash.emit("model_switched", {"model": dash.harness.model_name})
        return JSONResponse({"ok": True})

    # -- settings --
    async def setting_classification(request: Request) -> Response:
        d = await body(request)
        new = dash.set_classification(None if d.get("reset") else d)
        return JSONResponse({"ok": True, "classification": new, "source": dash.classification_source()})

    # -- subagents --
    async def subagent_steer(request: Request) -> Response:
        d = await body(request)
        dash.harness.steer_subagent(request.path_params["sid"], str(d.get("message", "")), dash.cfg.operator)
        return JSONResponse({"ok": True})

    async def subagent_stop(request: Request) -> Response:
        dash.harness.stop_subagent(request.path_params["sid"], dash.cfg.operator)
        return JSONResponse({"ok": True})

    # -- conversations --
    async def conversations(request: Request) -> Response:
        h = dash.harness
        return JSONResponse({"active": h.conversation["id"] if h.conversation else None,
                             "conversations": h.history.list(h.case.id)})

    async def conversation_new(request: Request) -> Response:
        dash.switch(dash.harness.new_conversation)
        return JSONResponse({"ok": True})

    async def conversation_open(request: Request) -> Response:
        cid = request.path_params["cid"]
        dash.switch(lambda: dash.harness.open_conversation(cid))
        return JSONResponse({"ok": True})

    async def conversation_rename(request: Request) -> Response:
        d = await body(request)
        cid = request.path_params["cid"]
        c = dash.harness.history.get(cid)
        if not c or c["case_id"] != dash.harness.case.id:
            return JSONResponse({"error": "no such conversation"}, 404)
        dash.harness.history.rename(cid, str(d.get("title", "")).strip() or c["title"])
        if dash.harness.conversation and dash.harness.conversation["id"] == cid:
            dash.harness.conversation["title"] = str(d.get("title", "")).strip() or c["title"]
        dash.emit("case_updated", {"reason": "conversation renamed"})
        return JSONResponse({"ok": True})

    async def conversation_delete(request: Request) -> Response:
        d = await body(request)
        cid = request.path_params["cid"]
        if str(d.get("confirm", "")) != cid:
            raise ValueError("deletion not confirmed: send the conversation id as 'confirm'")
        active = dash.harness.conversation and dash.harness.conversation["id"] == cid
        if active and dash.running():
            raise ValueError("an operation is running in this conversation - stop it first")
        if not dash.harness.delete_conversation(cid):
            return JSONResponse({"error": "no such conversation"}, 404)
        if active:
            dash.switch(lambda: None)
        else:
            dash.emit("case_updated", {"reason": "conversation deleted"})
        return JSONResponse({"ok": True})

    # -- skills --
    async def skills(request: Request) -> Response:
        from ..skills import needs_revision, track_record

        st = dash.harness.skills
        rows = [r | {"track_record": track_record(r), "needs_revision": needs_revision(r)} for r in st.list(include_retired=True)]
        pend = [v | {"diff": st.diff(v["id"])} for v in st.pending()]
        return JSONResponse({"skills": rows, "pending": pend, "stats": st.stats(),
                             "require_approval": st.require_approval})

    async def skill_detail(request: Request) -> Response:
        st = dash.harness.skills
        s = st.get(request.path_params["name"])
        if not s:
            return JSONResponse({"error": "no such skill"}, 404)
        return JSONResponse({"skill": s, "versions": st.versions(s["name"])})

    async def skill_version_action(request: Request) -> Response:
        d = await body(request)
        vid, action, note = request.path_params["vid"], str(d.get("action")), str(d.get("note", ""))[:1000]
        st = dash.harness.skills
        if action == "approve":
            st.approve(vid, dash.cfg.operator, note)
        elif action == "reject":
            st.reject(vid, dash.cfg.operator, note)
        else:
            raise ValueError("action must be approve or reject")
        dash.emit("skills_updated", {"version": vid, "action": action})
        return JSONResponse({"ok": True})

    async def skill_action(request: Request) -> Response:
        d = await body(request)
        name, action = request.path_params["name"], str(d.get("action"))
        st = dash.harness.skills
        if action in ("retire", "restore"):
            ok = st.set_status(name, "retired" if action == "retire" else "active", dash.cfg.operator)
        elif action == "rollback":
            ok = bool(st.rollback(name, int(d["version"]), dash.cfg.operator))
        else:
            raise ValueError("action must be retire, restore or rollback")
        dash.emit("skills_updated", {"skill": name, "action": action})
        return JSONResponse({"ok": ok}, 200 if ok else 404)

    @asynccontextmanager
    async def lifespan(app):
        await dash.harness.start(*dash.start_args)
        dash.load_history()
        dash.emit("ready", {"connectors": dash.harness.mcp.status})
        try:
            yield
        finally:
            dash.stop()
            await dash.harness.close()

    routes = [
        Route("/", index), Route("/login", login_page), Route("/static/{name}", asset),
        Route("/api/public", public_info),
        Route("/api/login", api_login, methods=["POST"]),
        Route("/api/logout", guard(api_logout, True), methods=["POST"]),
        Route("/api/subagents/{sid}/steer", guard(subagent_steer, True), methods=["POST"]),
        Route("/api/subagents/{sid}/stop", guard(subagent_stop, True), methods=["POST"]),
        Route("/api/state", guard(get_state)),
        Route("/api/events", guard(events_stream)),
        Route("/api/events/poll", guard(events_poll)),
        Route("/api/memory", guard(memory_list)),
        Route("/api/audit", guard(audit)),
        Route("/api/tools", guard(tools)),
        Route("/api/report", guard(report)),
        Route("/api/message", guard(message, True), methods=["POST"]),
        Route("/api/stop", guard(stop, True), methods=["POST"]),
        Route("/api/approvals/{aid}", guard(approval, True), methods=["POST"]),
        Route("/api/verdict", guard(verdict, True), methods=["POST"]),
        Route("/api/remember", guard(remember, True), methods=["POST"]),
        Route("/api/memory/{mid:int}", guard(memory_action, True), methods=["POST"]),
        Route("/api/retro", guard(retro, True), methods=["POST"]),
        Route("/api/rate", guard(rate, True), methods=["POST"]),
        Route("/api/model", guard(model, True), methods=["POST"]),
        Route("/api/settings/classification", guard(setting_classification, True), methods=["POST"]),
        Route("/api/conversations", guard(conversations)),
        Route("/api/conversations/new", guard(conversation_new, True), methods=["POST"]),
        Route("/api/conversations/{cid}/open", guard(conversation_open, True), methods=["POST"]),
        Route("/api/conversations/{cid}/rename", guard(conversation_rename, True), methods=["POST"]),
        Route("/api/conversations/{cid}/delete", guard(conversation_delete, True), methods=["POST"]),
        Route("/api/skills", guard(skills)),
        Route("/api/skills/versions/{vid:int}", guard(skill_version_action, True), methods=["POST"]),
        Route("/api/skills/{name}", guard(skill_detail)),
        Route("/api/skills/{name}/action", guard(skill_action, True), methods=["POST"]),
    ]
    return SecurityHeaders(Starlette(routes=routes, lifespan=lifespan))


class SecurityHeaders:
    """Pure-ASGI middleware (safe for streaming SSE responses) adding CSP and hardening headers."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        api = path.startswith("/api/") or path in ("/", "/login")  # never cache pages or API data

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"cache-control" or not api]
                headers += [(b"content-security-policy", CSP.encode()), (b"x-content-type-options", b"nosniff"),
                            (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY")]
                if api:
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


def serve(cfg: HarnessConfig, case_id: str, model: str | None, posture: str | None, host: str, port: int,
          tls_cert: str = "", tls_key: str = "", allow_plaintext: bool = False, conversation_id: str | None = None,
          new_conversation: bool = False) -> None:
    import uvicorn

    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not (tls_cert and tls_key) and not allow_plaintext:
        raise SystemExit("refusing to serve the dashboard on a non-loopback address without TLS "
                         "(--tls-cert/--tls-key), or pass --allow-plaintext if you really mean it")
    dash = Dashboard(cfg, case_id, model, posture, conversation_id=conversation_id, new_conversation=new_conversation)
    scheme = "https" if tls_cert else "http"
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"\n  Compensated Anarchist dashboard  case={case_id}\n"
          f"  open: {scheme}://{shown}:{port}/login?token={dash.token}\n"
          f"  (the token is required; keep it private. Ctrl+C to stop.)\n", flush=True)
    uvicorn.run(create_app(dash), host=host, port=port, log_level="warning",
                ssl_certfile=tls_cert or None, ssl_keyfile=tls_key or None)
