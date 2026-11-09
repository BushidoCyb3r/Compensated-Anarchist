"""Compensated Anarchist dashboard - local web GUI (`canarchist dashboard`).

One dashboard process drives one case: a single Harness (lead + experts + connectors) whose events are
broadcast to every connected browser over Server-Sent Events. Response actions that need approval are
parked as pending approvals and resolved from the browser.

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
import secrets
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from importlib import resources
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Route

from ..agent import Harness
from ..audit import verify
from ..config import HarnessConfig
from ..memory import KINDS

COOKIE = "ca_session"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class Dashboard:
    def __init__(self, cfg: HarnessConfig, case_id: str, model: str | None = None, posture: str | None = None,
                 token: str | None = None, approval_timeout_s: int = 3600, harness: Harness | None = None):
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
        self.harness.on_event = self.emit
        self.harness.executor.on_event = self.emit
        self.harness.roe.approver = self.web_approver

    # ---- event bus ----------------------------------------------------------------
    def emit(self, kind: str, data: dict[str, Any]) -> None:
        self.seq += 1
        ev = {"seq": self.seq, "ts": time.time(), "kind": kind, "data": data}
        self.events.append(ev)
        for q in list(self.subscribers):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                self.subscribers.discard(q)

    # ---- approvals ----------------------------------------------------------------
    async def web_approver(self, tool: str, arguments: dict[str, Any], rationale: str, why: str) -> tuple[bool, str]:
        aid = uuid.uuid4().hex[:12]
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending[aid] = {"id": aid, "tool": tool, "arguments": arguments, "rationale": rationale, "why": why,
                             "requested": time.time(), "future": fut}
        self.emit("approval_request", self._public(self.pending[aid]))
        try:
            ok, note = await asyncio.wait_for(fut, self.approval_timeout_s)
        except asyncio.TimeoutError:
            ok, note = False, f"no analyst decision within {self.approval_timeout_s}s"
        except asyncio.CancelledError:
            ok, note = False, "operation stopped by analyst"
            self.pending.pop(aid, None)
            self.emit("approval_resolved", {"id": aid, "approved": False, "note": note})
            raise
        self.pending.pop(aid, None)
        self.emit("approval_resolved", {"id": aid, "approved": ok, "note": note, "by": self.cfg.operator})
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
            try:
                text = await coro_factory()
                self.emit("run_end", {"label": label, "ok": True, "text": text, "seconds": round(time.monotonic() - t0, 1)})
            except asyncio.CancelledError:
                if self.harness.lead:
                    self.harness.lead.repair("operation stopped by analyst")
                self.emit("run_end", {"label": label, "ok": False, "text": "Stopped by analyst.", "stopped": True})
            except Exception as e:  # surface backend/model failures to the GUI
                if self.harness.lead:
                    self.harness.lead.repair(f"run failed: {type(e).__name__}")
                self.emit("run_end", {"label": label, "ok": False, "text": f"{type(e).__name__}: {e}"})

        self.run_task = asyncio.create_task(runner())
        return True

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
            "session": h.session,
            "operator": self.cfg.operator,
            "posture": h.roe.posture,
            "model": h.model_name,
            "models": [{"name": n, "provider": p.provider, "model": p.model} for n, p in self.cfg.models.items()],
            "connectors": h.mcp.status,
            "experts": [{"name": n, "title": e.title, "description": e.description, "model": e.model or h.model_name}
                        for n, e in h.experts.items()],
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
                return JSONResponse({"error": "unauthorized - open the login URL printed in the terminal"}, 401)
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

    # -- pages --
    async def login(request: Request) -> Response:
        tok = request.query_params.get("token", "")
        if not hmac.compare_digest(tok, dash.token):
            return PlainTextResponse("invalid token", 401)
        tab = request.query_params.get("tab", "")
        resp = RedirectResponse("/" + (f"#{tab}" if tab.isalpha() and len(tab) < 20 else ""), 303)
        resp.set_cookie(COOKIE, dash._session_value(), httponly=True, samesite="strict",
                        secure=request.url.scheme == "https")
        return resp

    async def index(request: Request) -> Response:
        if not dash.authed(request):
            return PlainTextResponse("Compensated Anarchist dashboard: open the login URL printed in the terminal "
                                     "(…/login?token=…).", 401)
        return FileResponse(str(static.joinpath("index.html")), media_type="text/html")

    async def asset(request: Request) -> Response:
        name = request.path_params["name"]
        if name not in ("app.js", "app.css", "favicon.svg"):
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
        dash.emit("analyst_message", {"text": str(d.get("text", "")), "playbook": playbook})
        if not dash.start_run(playbook or "mission", lambda: dash.harness.mission(text)):
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
        if not dash.start_run("retro", dash.harness.retro):
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

    @asynccontextmanager
    async def lifespan(app):
        await dash.harness.start()
        dash.emit("ready", {"connectors": dash.harness.mcp.status})
        try:
            yield
        finally:
            dash.stop()
            await dash.harness.close()

    routes = [
        Route("/", index), Route("/login", login), Route("/static/{name}", asset),
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
          tls_cert: str = "", tls_key: str = "", allow_plaintext: bool = False) -> None:
    import uvicorn

    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not (tls_cert and tls_key) and not allow_plaintext:
        raise SystemExit("refusing to serve the dashboard on a non-loopback address without TLS "
                         "(--tls-cert/--tls-key), or pass --allow-plaintext if you really mean it")
    dash = Dashboard(cfg, case_id, model, posture)
    scheme = "https" if tls_cert else "http"
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"\n  Compensated Anarchist dashboard  case={case_id}\n"
          f"  open: {scheme}://{shown}:{port}/login?token={dash.token}\n"
          f"  (the token is required; keep it private. Ctrl+C to stop.)\n", flush=True)
    uvicorn.run(create_app(dash), host=host, port=port, log_level="warning",
                ssl_certfile=tls_cert or None, ssl_keyfile=tls_key or None)
