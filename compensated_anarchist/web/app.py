"""Compensated Anarchist dashboard - local web GUI (`canarchist dashboard`).

One dashboard process drives one case: a single Harness (orchestrator + subagents + connectors) whose events
are broadcast to every connected browser over Server-Sent Events. Response actions that need approval are
parked as pending approvals and resolved from the browser. The case's conversations are persisted; the feed of
the open conversation is replayed when the dashboard starts or the analyst switches conversation.

Durable operations: every agent checkpoints its context after each step, and every approval request is saved. When
the dashboard stops (or crashes) mid-operation, the next start offers the operation as interrupted: the approvals it
was waiting for are shown again, and deciding one, or pressing Resume, carries the operation on from where each agent
stopped. End closes it instead. Stop (the analyst's) is different: it ends the operation for good.

Security model (the GUI can approve response actions, so it is stricter than a typical local dashboard):
  - signing in takes BOTH the access token, generated fresh at every start (printed by scripts/start.sh), AND the
    dashboard account's username and password (created once on the host: canarchist account create; stored as a
    salted scrypt hash). Even on localhost. A sign-in gets a random server-side session in an HttpOnly,
    SameSite=Strict cookie; it ends after `dashboard.session_idle_hours` (default 12) without analyst activity,
    on sign-out, and when the dashboard stops
  - state-changing requests also need the X-CA-Request header (CSRF defense in depth)
  - binding to a non-loopback address requires TLS (or an explicit --allow-plaintext)
  - strict Content-Security-Policy; the frontend renders all agent/tool/log text as text, never HTML,
    because that data is attacker-influenced
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
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

from .. import NAME, __version__, docx, editors, huntplans, reports, service
from . import account
from ..agent import Harness
from ..audit import verify
from ..history import LATER
from ..tools.registry import CURRENT_CALL
from ..config import HarnessConfig
from ..memory import KINDS

COOKIE = "ca_session"
# broadcast live, never kept in the replay buffer. case_switched tells open pages to reload: kept, every page load
# would replay it and reload again, over and over.
EPHEMERAL = {"telemetry", "delta", "ui_updated", "settings_changed", "case_switched"}
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
                 conversation_id: str | None = None, new_conversation: bool = False, account_path: Path | None = None,
                 run_dir: Path | None = None):
        self.cfg = cfg
        # new at every start; never configured. (An address change restarts this same process and keeps it.)
        self.token = token or self.handoff_token(run_dir) or secrets.token_urlsafe(24)
        self.account_path = Path(account_path) if account_path else account.default_path(cfg)
        self.sessions: dict[str, dict[str, Any]] = {}  # session id -> {user, client, created, seen}
        self.run_dir = Path(run_dir) if run_dir else None
        self.url = ""  # set by serve()
        self.bind: dict[str, Any] = {}  # {"host", "port"} set by serve()
        self.server = None  # the uvicorn server, so an address change can restart it in place
        self.relaunch: list[str] | None = None
        self.owner_q: asyncio.Queue = asyncio.Queue()
        self.approval_timeout_s = approval_timeout_s
        self.events: deque[dict[str, Any]] = deque(maxlen=5000)
        self.seq = 0
        self.subscribers: set[asyncio.Queue] = set()
        self.pending: dict[str, dict[str, Any]] = {}
        self.run_task: asyncio.Task | None = None
        self.run_label = ""
        self.last_ok = False  # the last stage of the run completed (an automatic review may follow it)
        self.shutting_down = False  # the dashboard is stopping: a running operation is interrupted, not stopped
        self.interrupted: dict[str, Any] | None = None  # the open conversation's operation cut off by a restart
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
        self.settings_path = service.dashboard_settings_path(cfg)
        saved = None if self.classification_locked else self._load_settings().get("classification")
        try:
            current = classification_from(saved) if saved is not None else self.config_classification
        except ValueError:  # a hand-edited settings file with a bad value: fall back to the config
            current = self.config_classification
        self.ui = {"classification": current, "consent_text": str(ui.get("consent_text") or "").strip()}
        self.idle_s = float(ui.get("session_idle_hours", 12)) * 3600
        ed = ui.get("editors") or {}
        self.editor_cfg = {"open_on_host": ed.get("open_on_host", True) is not False,
                           "links": [k for k in (ed.get("links") or list(editors.LINKS)) if k in editors.LINKS],
                           "vscode_remote": str(ed.get("vscode_remote") or "").strip()}

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

    # ---- opening hunt plans in an editor -----------------------------------------------
    @staticmethod
    def viewer_on_host(request: Request) -> bool:
        """True when the browser runs on this host: a loopback client, or a client connecting from the very address it
        connected to. (Behind a reverse proxy on this host every viewer looks local: set open_on_host: false.)"""
        def ip(v: Any):
            try:
                a = ipaddress.ip_address(str(v).split("%")[0])
            except ValueError:
                return None
            return getattr(a, "ipv4_mapped", None) or a
        client = ip(request.client.host) if request.client else None
        server = ip((request.scope.get("server") or ("",))[0])
        return bool(client and (client.is_loopback or client == server))

    def host_open(self, request: Request) -> dict[str, Any]:
        """Whether this viewer can have the host open a plan in an editor, and with which editors."""
        if not self.editor_cfg["open_on_host"]:
            return {"available": False, "why": "turned off in harness.yaml (dashboard.editors.open_on_host)", "editors": []}
        if not self.viewer_on_host(request):
            return {"available": False, "why": "your browser is not on the dashboard's host; use a link or download",
                    "editors": []}
        eds = editors.detect()
        if not eds:
            return {"available": False, "why": "no text editor found on the host", "editors": []}
        if editors.graphical_env() is None:
            return {"available": False, "why": "nobody is logged in to the host's desktop", "editors": []}
        return {"available": True, "why": "", "editors": [e.public() for e in eds]}

    # ---- posture, address and case: live from the Settings page, and the next start's defaults --------
    def address_mode(self) -> str:
        return "127.0.0.1" if self.bind.get("host") in ("127.0.0.1", "localhost", "::1") else "auto"

    def startup_info(self) -> dict[str, Any]:
        h = self.harness
        cases = sorted((d for d in Path(self.cfg.cases_dir).glob("*") if d.is_dir() and not d.name.startswith(("_", "."))),
                       key=lambda d: d.stat().st_mtime, reverse=True)
        return {"now": {"posture": h.roe.posture, "case": h.case.id, "address": self.address_mode(), "url": self.url},
                "main_address": service.primary_address(), "port": self.bind.get("port"),
                "defaults": {k: v for k, v in service.settings(self.cfg, {}).items() if k in ("case", "posture")}
                | {"address": service.saved_startup(self.cfg).get("host", "auto")},
                "cases": [d.name for d in cases[:300]], "can_move": bool(self.run_dir and self.bind),
                "running": self.running()}

    def _remember(self, **values: str) -> None:
        service.save_startup(self.cfg, **values)  # the default scripts/start.sh offers next time

    def set_posture(self, posture: str, user: str) -> None:
        if posture not in ("observe", "respond"):
            raise ValueError("posture: observe or respond")
        old = self.harness.roe.posture
        self.harness.roe.posture = posture  # applies to every decision from now on
        self._remember(posture=posture)
        self.harness.audit.record("posture_changed", old=old, new=posture, by=user)
        self.emit("settings_changed", {"posture": posture})

    # The harness (and its connector sessions) is started, switched and closed by ONE long-lived owner task: MCP
    # client sessions must be closed by the task that opened them, so request handlers only hand it the work.
    async def own_harness(self, ready: asyncio.Future) -> None:
        try:
            await self.harness.start(*self.start_args)
        except BaseException as e:
            if not ready.done():
                ready.set_exception(e)
            return
        self.load_history()
        self.emit("ready", {"connectors": self.harness.mcp.status})
        self.write_run_state()  # scripts/start.sh waits for this, then prints the URL and the new token
        ready.set_result(None)
        while True:
            cmd, arg, fut = await self.owner_q.get()
            if cmd == "close":
                try:
                    await self.halt()
                    await self.harness.close()
                    self.clear_run_state()
                finally:
                    fut.set_result(None)
                return
            try:
                await self._switch_case(*arg)
                fut.set_result(None)
            except Exception as e:  # reported to the analyst who asked
                fut.set_exception(e)

    async def _ask_owner(self, cmd: str, arg: Any = None) -> None:
        fut = asyncio.get_running_loop().create_future()
        await self.owner_q.put((cmd, arg, fut))
        await fut

    async def switch_case(self, case_id: str, user: str) -> None:
        """Move the dashboard to another case (an existing one, or a new one): a new harness for it; the old case's
        files stay as they are. Connectors reconnect; signed-in browsers stay signed in."""
        case_id = case_id.strip()
        if not service.CASE_RE.match(case_id):
            raise ValueError("case: letters, digits, . _ - (up to 64)")
        if self.running():
            raise ValueError("an operation is running - stop it first")
        if case_id != self.harness.case.id:
            await self._ask_owner("switch", (case_id, user))

    async def _switch_case(self, case_id: str, user: str) -> None:
        old = self.harness
        old.audit.record("case_switch", to=case_id, by=user)
        for p in list(self.pending.values()):
            if p.get("future") and not p["future"].done():
                p["future"].set_result((False, "the dashboard moved to another case"))
        await old.close()
        new = Harness(self.cfg, case_id, old.model_name, old.roe.posture, interactive=True, on_event=self.emit)
        new.on_event = self.emit
        new.roe.approver = self.web_approver
        await new.start()
        self.harness, self.pending, self.live, self.telemetry = new, {}, {}, {}
        new.audit.record("case_switch", came_from=old.case.id, by=user)
        self._remember(case=case_id)
        self.load_history()
        self.write_run_state()
        self.emit("case_switched", {"case": case_id})

    def move_address(self, mode: str, user: str) -> str:
        """Serve on the main network address ("auto") or this host only ("127.0.0.1"). The listening socket has to
        change, so the dashboard restarts itself in place (same process and pid, same access token); browsers sign
        in again at the new address. Returns the new URL."""
        if mode not in ("auto", "127.0.0.1"):
            raise ValueError("address: auto (the main network address) or 127.0.0.1 (this host only)")
        if not self.can_move():
            raise ValueError("this dashboard was not started with scripts/start.sh; restart it with the address you want")
        if self.running():
            raise ValueError("an operation is running - stop it first")
        host = service.primary_address() if mode == "auto" else "127.0.0.1"
        port = int(self.bind["port"])
        argv = [sys.argv[0], "--config", str(self.cfg.config_path), "dashboard", "--case", self.harness.case.id,
                "--posture", self.harness.roe.posture, "--model", self.harness.model_name, "--host", host,
                "--port", str(port), "--run-dir", str(self.run_dir)]
        if self.harness.conversation:
            argv += ["--conversation", self.harness.conversation["id"]]
        if mode == "auto":
            st = service.settings(self.cfg, {})
            service.ensure_cert(st["tls_cert"], st["tls_key"], host)
            argv += ["--tls-cert", str(st["tls_cert"]), "--tls-key", str(st["tls_key"])]
        self._remember(host=mode)
        self.harness.audit.record("address_changed", old=self.url, new_host=host, by=user)
        url = f"{'http' if mode == '127.0.0.1' else 'https'}://{host}:{port}"
        handoff = self.run_dir / "handoff.json"  # this start's token, for the same process after it re-executes
        fd = os.open(handoff, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"pid": os.getpid(), "token": self.token, "expires": time.time() + 120}, fh)
        self.relaunch = argv
        self.emit("settings_changed", {"address": mode, "url": url, "restarting": True})
        asyncio.get_running_loop().call_later(0.8, self._shutdown_for_relaunch)
        return url

    def can_move(self) -> bool:
        return bool(self.run_dir and self.bind and self.server is not None)

    def _shutdown_for_relaunch(self) -> None:
        if self.server is not None:
            self.server.should_exit = True

    @staticmethod
    def handoff_token(run_dir: Path | None) -> str:
        """The token of the start this process belongs to, when it re-executed itself to change address."""
        if not run_dir:
            return ""
        f = Path(run_dir) / "handoff.json"
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ""
        f.unlink(missing_ok=True)
        ok = isinstance(d, dict) and d.get("pid") == os.getpid() and float(d.get("expires", 0)) > time.time()
        return str(d.get("token") or "") if ok else ""

    # ---- approvals ----------------------------------------------------------------
    # Every request is saved (history.approvals). One still waiting when the dashboard stops is shown again after the
    # restart ("restored": no future); the analyst's decision on it is stored and applied when the operation resumes.
    async def web_approver(self, tool: str, arguments: dict[str, Any], rationale: str, why: str) -> tuple[bool, str]:
        h = self.harness
        ref = CURRENT_CALL.get()
        conv = h._conv()["id"]
        key = ref.key if ref else ""
        row = h.history.approval_for_call(conv, key) if ref and ref.resumed else None
        if row and row["status"] in LATER and row["tool"] == tool:  # decided after the restart: apply it now
            ok = LATER[row["status"]]
            h.history.approval_update(row["id"], status="approved" if ok else "denied")
            self.pending.pop(row["id"], None)
            h.emit("approval_resolved", {"id": row["id"], "approved": ok, "note": row["note"], "by": row["decided_by"],
                                         "applied": True})
            return ok, f"{row['note']} (decided while the operation was interrupted)".strip()
        aid = row["id"] if row else uuid.uuid4().hex[:12]
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        entry = {"id": aid, "tool": tool, "arguments": arguments, "rationale": rationale, "why": why,
                 "requested": row["requested"] if row else time.time(), "agent_id": ref.agent_id if ref else "",
                 "asked_before_restart": bool(row), "future": fut}
        if not row:
            h.history.approval_add({"id": aid, "conversation_id": conv, "operation_id": (h.op or {}).get("id", ""),
                                    "agent_id": entry["agent_id"], "call_key": key, "tool": tool, "arguments": arguments,
                                    "rationale": rationale, "why": why, "requested": entry["requested"]})
        self.pending[aid] = entry
        h.emit("approval_request", self._public(entry))
        try:
            ok, note = await asyncio.wait_for(fut, self.approval_timeout_s)
            status = "approved" if ok else "denied"
        except asyncio.TimeoutError:
            ok, note, status = False, f"no analyst decision within {self.approval_timeout_s}s", "timeout"
        except asyncio.CancelledError:
            self.pending.pop(aid, None)
            if not self.shutting_down:  # stopping the dashboard keeps it pending for after the restart
                note = "operation stopped by analyst"
                h.history.approval_update(aid, status="cancelled", note=note, decided=time.time())
                h.emit("approval_resolved", {"id": aid, "approved": False, "note": note})
            raise
        self.pending.pop(aid, None)
        by = entry.get("by") or self.cfg.operator
        h.history.approval_update(aid, status=status, note=note[:2000], decided_by=by, decided=time.time())
        h.emit("approval_resolved", {"id": aid, "approved": ok, "note": note, "by": by})
        return ok, note

    @staticmethod
    def _public(p: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in p.items() if k != "future"}

    def resolve(self, aid: str, approve: bool, note: str, user: str = "") -> bool:
        p = self.pending.get(aid)
        if not p:
            return False
        by = user or self.cfg.operator
        if "future" not in p:  # asked before the dashboard restarted: decided now, applied as the operation resumes
            h = self.harness
            h.history.approval_update(aid, status="approved_later" if approve else "denied_later", note=note[:2000],
                                      decided_by=by, decided=time.time())
            self.pending.pop(aid)
            h.audit.record("approval_decided_after_restart", id=aid, tool=p["tool"], arguments=p["arguments"],
                           approved=approve, note=note[:500], by=by)
            h.emit("approval_resolved", {"id": aid, "approved": approve, "note": note, "by": by, "later": True})
            if self.interrupted and self.interrupted.get("resumable") and not self.running():
                self.resume_run(by)  # the decision is the analyst's go-ahead: carry the operation on
            return True
        if p["future"].done():
            return False
        p["by"] = by
        p["future"].set_result((approve, note))
        return True

    # ---- runs -------------------------------------------------------------------------
    def start_run(self, label: str, coro_factory, kind: str = "mission", playbook: str = "") -> bool:
        """Run an operation in the background. kind: mission | retro | resume (the harness records a resume itself).
        Starting anything else ends an interrupted operation in this conversation."""
        if self.running():
            return False
        h = self.harness
        if kind != "resume":
            h.op_begin(kind, label, playbook)
        self.interrupted = None
        self.pending = {k: v for k, v in self.pending.items() if "future" in v}
        self.run_label = label

        async def runner():
            await stage(label, coro_factory, kind)
            # a completed playbook mission is reviewed by itself (learning.auto_retro), in the same run
            if kind in ("mission", "resume") and h.op is None and self.last_ok and (why := h.auto_retro_due(playbook)):
                review = "after-action review (automatic)"
                h.op_begin("retro", review)
                self.run_label = review
                h.emit("retro_auto", {"why": why})
                await stage(review, h.retro, "retro")

        async def stage(label: str, coro_factory, kind: str) -> None:
            self.last_ok = False
            self.emit("run_start", {"label": label, "resumed": kind == "resume"})
            t0 = time.monotonic()
            try:
                text = await coro_factory()
                h.op_end("done")
                self.last_ok = True
                h.emit("run_end", {"label": label, "ok": True, "text": text, "seconds": round(time.monotonic() - t0, 1),
                                   **({"learning": self.learning_counts()} if kind == "retro" else {})})
            except asyncio.CancelledError:
                if self.shutting_down:  # the agents' checkpoints and pending approvals are kept for a resume
                    h.op_end("interrupted")
                    h.emit("run_end", {"label": label, "ok": False, "interrupted": True,
                                       "text": "After the dashboard starts again, resume the operation from where it "
                                               "stopped, or end it."})
                else:
                    self._repair_all("operation stopped by analyst")
                    h.op_end("stopped")
                    h.emit("run_end", {"label": label, "ok": False, "text": "Stopped by analyst.", "stopped": True})
            except Exception as e:  # surface backend/model failures to the GUI
                self._repair_all(f"run failed: {type(e).__name__}")
                h.op_end("failed", f"{type(e).__name__}: {e}")
                h.emit("run_end", {"label": label, "ok": False, "text": f"{type(e).__name__}: {e}"})

        self.run_task = asyncio.create_task(runner())
        return True

    def resume_run(self, user: str) -> bool:
        """Carry on with the interrupted operation (Resume, or deciding an approval it was waiting for)."""
        op = self.interrupted
        if not op or not op.get("resumable"):
            raise ValueError("there is no interrupted operation to resume in this conversation")
        if self.running():
            raise ValueError("an operation is running - stop it first")
        self.harness.audit.record("operation_resume_requested", operation=op["id"], by=user)
        return self.start_run(op["label"] or "mission", self.harness.resume, kind="resume", playbook=op["playbook"])

    def end_interrupted(self, user: str) -> bool:
        if self.running():
            raise ValueError("an operation is running - stop it first")
        op = self.harness.end_interrupted(f"ended by {user}")
        self._load_interrupted()
        return bool(op)

    def _repair_all(self, reason: str) -> None:
        h = self.harness
        if h.lead:
            h.lead.repair(reason)
        for sa in h.subagents.values():  # subagents cancelled mid-task keep a valid history for follow-ups
            if sa.agent and sa.status in ("running", "queued"):
                sa.status = "interrupted"
                sa.agent.repair(reason)

    def learning(self, scope: str) -> tuple[list[dict[str, Any]], ...]:
        """What waits for review: (memory candidates, skill versions, tool proposals) from this conversation, this
        case, or anywhere."""
        h = self.harness
        conv = h.conversation["id"] if h.conversation else ""
        cat = h.onboarding.catalog if getattr(h, "onboarding", None) else None
        skills, tools = h.skills.pending(), cat.proposals() if cat else []
        if scope == "conversation":
            if not conv:
                return [], [], [], []
            return (h.memory.pending(conversation_id=conv), [v for v in skills if v.get("conversation_id") == conv],
                    [p for p in tools if p.get("conversation_id") == conv], [])
        if scope == "case":
            return (h.memory.pending(case_id=h.case.id), [v for v in skills if v.get("case_id") == h.case.id],
                    [p for p in tools if p.get("case_id") == h.case.id], [])
        blocked = [t for t in cat.tools() if t.get("status") == "blocked"] if cat else []  # a changed binary to decide on
        return h.memory.pending(), skills, tools, blocked

    def learning_counts(self) -> dict[str, int]:
        return {scope: sum(map(len, self.learning(scope))) for scope in ("conversation", "case", "all")}

    def running(self) -> bool:
        return bool(self.run_task and not self.run_task.done())

    async def halt(self) -> None:
        """The dashboard is stopping: cut the running operation off where it is, without denying its approvals or
        closing its agents' open tool calls, so it can be resumed after the next start. (Stop ends it for good.)"""
        if not self.running():
            return
        self.shutting_down = True
        self.run_task.cancel()
        await asyncio.wait({self.run_task}, timeout=15)

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
        self._load_interrupted()

    def _load_interrupted(self) -> None:
        """Offer the open conversation's interrupted operation, and the approvals it was waiting for."""
        self.pending = {k: v for k, v in self.pending.items() if "future" in v}
        op = self.harness.interrupted_operation() if self.harness.conversation else None
        self.interrupted = op
        for r in (op or {}).get("approvals", []):
            if r["status"] == "pending":
                self.pending[r["id"]] = {"id": r["id"], "tool": r["tool"], "arguments": r["arguments"],
                                         "rationale": r["rationale"], "why": r["why"], "requested": r["requested"],
                                         "agent_id": r["agent_id"], "restored": True}

    def interrupted_public(self) -> dict[str, Any] | None:
        op = self.interrupted
        if not op or self.running():
            return None
        return {"id": op["id"], "label": op["label"], "playbook": op["playbook"], "kind": op["kind"],
                "started": op["started"], "resumable": bool(op.get("resumable")),
                "waiting": sum(1 for p in self.pending.values() if p.get("restored"))}

    def switch(self, action) -> None:
        if self.running():
            raise ValueError("an operation is running - stop it first")
        action()
        self.load_history()
        conv = self.harness.conversation
        self.emit("conversation_switched", {"id": conv["id"] if conv else None})

    def stop(self) -> bool:
        """The analyst's Stop: deny what is waiting, cancel the operation and every subagent working for it."""
        if not self.running():
            return False
        for p in list(self.pending.values()):
            fut = p.get("future")
            if fut and not fut.done():
                fut.set_result((False, "operation stopped by analyst"))
        self.run_task.cancel()
        for sa in self.harness.subagents.values():
            if sa.job and not sa.job.done():
                sa.job.cancel()
        return True

    # ---- state ----------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        h = self.harness
        self.cfg.reload_models()  # edits to config/models.yaml show up without a restart
        playbooks = sorted(f.name[:-3] for f in resources.files("compensated_anarchist").joinpath("playbooks").iterdir()
                           if f.name.endswith(".md"))
        return {
            "case": h.case.data,
            "evidence_folder": str(h.case_evidence_dir),
            "vault_folder": str(h.vault_dir / "velociraptor"),
            "plans_folder": str(h.hunt_plans_dir),
            "vuln_folder": str(h.vuln_dir),
            "cte_folder": str(h.cte_dir),
            "reports_folder": str(h.reports_dir),
            "report_examples_folder": str(h.report_examples_dir),
            "gated": h.gate_reason,
            "session": h.session,
            "operator": self.cfg.operator,
            "posture": h.roe.posture,
            "model": h.model_name,
            "models": [p.public() for p in self.cfg.models.values()],
            "models_files": [str(f) for f in self.cfg.model_files],
            "models_error": self.cfg.models_error,
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
            "learning": self.learning_counts(),
            "memory": h.memory.stats(),
            "running": bool(self.run_task and not self.run_task.done()),
            "run_label": self.run_label,
            "pending": [self._public(p) for p in self.pending.values()],
            "interrupted": self.interrupted_public(),
            "playbooks": playbooks,
            "memory_kinds": KINDS,
            "last_seq": self.seq,
        }

    # ---- run state (scripts/start.sh and scripts/stop.sh) ---------------------------------
    def write_run_state(self) -> None:
        """<run_dir>/dashboard.json (0600): pid, URL and this start's access token, for start.sh to print."""
        if not self.run_dir or not self.url:
            return
        self.run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.run_dir, 0o700)
        state = {"pid": os.getpid(), "url": self.url, "token": self.token, "case": self.harness.case.id,
                 "model": self.harness.model_name, "posture": self.harness.roe.posture,
                 "connectors": self.harness.mcp.status, "started": time.time()}
        tmp = self.run_dir / "dashboard.json.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
        os.replace(tmp, self.run_dir / "dashboard.json")

    def clear_run_state(self) -> None:
        if self.run_dir:
            (self.run_dir / "dashboard.json").unlink(missing_ok=True)

    # ---- auth ---------------------------------------------------------------------------
    def new_session(self, user: str, client: str) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        self.sessions = {k: v for k, v in self.sessions.items() if now - v["seen"] <= self.idle_s}  # drop idle ones
        self.sessions[sid] = {"user": user, "client": client, "created": now, "seen": now}
        return sid

    def session(self, request: Request, touch: bool = False) -> dict[str, Any] | None:
        """The caller's live session, or None. `touch` marks analyst activity (writes, the page's activity ping);
        background reads (polling, the event stream) do not keep a session alive."""
        s = self.sessions.get(request.cookies.get(COOKIE, "") or "-")
        if not s:
            return None
        now = time.time()
        if now - s["seen"] > self.idle_s:
            self.sessions.pop(request.cookies.get(COOKIE, ""), None)
            self.harness.audit.record("dashboard_session_expired", user=s["user"], client=s["client"])
            return None
        if touch:
            s["seen"] = now
        return s

    def authed(self, request: Request, touch: bool = False) -> bool:
        return self.session(request, touch) is not None


def create_app(dash: Dashboard) -> Starlette:
    static = resources.files("compensated_anarchist").joinpath("web/static")

    def guard(handler, write: bool = False):
        async def wrapped(request: Request) -> Response:
            if not dash.authed(request, touch=write):
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
                             "consent_text": dash.ui["consent_text"], "authed": dash.authed(request),
                             "account": account.exists(dash.account_path)})

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
        if not account.exists(dash.account_path):
            return JSONResponse({"error": "no dashboard account yet: run `canarchist account create` on the host "
                                          "(scripts/start.sh asks for it)"}, 403)
        username, password = str(d.get("username", ""))[:128], str(d.get("password", ""))[:1024]
        token_ok = hmac.compare_digest(str(d.get("token", "")).encode(), dash.token.encode())
        account_ok = await asyncio.to_thread(account.verify, dash.account_path, username, password)  # always checked
        if not (token_ok and account_ok):
            recent.append(now)
            dash.harness.audit.record("dashboard_login_failed", client=client, username=username[:64],
                                      token_ok=token_ok)
            await asyncio.sleep(0.4)
            return JSONResponse({"error": "Sign-in failed: check the access token (it changes at every start), "
                                          "the username and the password"}, 401)
        dash.login_failures.pop(client, None)
        sid = dash.new_session(username, client)
        dash.harness.audit.record("dashboard_login", client=client, user=username, consent=bool(dash.ui["consent_text"]))
        resp = JSONResponse({"ok": True, "user": username})
        resp.set_cookie(COOKIE, sid, httponly=True, samesite="strict", secure=request.url.scheme == "https")
        return resp

    async def api_logout(request: Request) -> Response:
        s = dash.sessions.pop(request.cookies.get(COOKIE, "") or "-", None)
        if s:
            dash.harness.audit.record("dashboard_logout", user=s["user"], client=s["client"])
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE)
        return resp

    async def activity(request: Request) -> Response:
        return JSONResponse({"ok": True})  # guard(write=True) already marked the analyst as active

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
                    if await request.is_disconnected() or not dash.authed(request):  # signed out or idled out
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
        """The latest final report, else the latest verified draft, else report.md from before the report writer."""
        h = dash.harness
        drafts = sorted(h.reports_dir.glob("report_*.md"), key=lambda q: q.stat().st_mtime) if h.reports_dir.is_dir() else []
        finals = [q for q in drafts if q.name.endswith("_final.md")]
        p = finals[-1] if finals else drafts[-1] if drafts else h.case.dir / "report.md"
        text = p.read_text(encoding="utf-8") if p.exists() else ""
        if request.query_params.get("format") == "json":  # the dashboard's Report tab: which file, for its buttons
            return JSONResponse({"name": p.name if p.exists() and p.parent == h.reports_dir else "", "text": text,
                                 "final": p.name.endswith("_final.md")})
        return PlainTextResponse(text)

    async def source(request: Request) -> Response:
        """A report citation's source ([FIN-0001], [EV-12], [FILE:hunt_plan_x.md], ...) from this case's mission data."""
        sid = request.path_params["sid"]
        src = await asyncio.to_thread(dash.harness.mission_data().get, sid) if reports.SOURCE_ID.match(sid) else None
        if not src:
            return JSONResponse({"error": f"{sid[:80]} is not in this case's mission data"}, 404)
        limit = 200_000
        text = src.text if len(src.text) <= limit else src.text[:limit] + f"\n... [{len(src.text) - limit} more characters]"
        return JSONResponse({"id": src.id, "kind": src.kind, "line": src.line, "text": text})

    # -- hunt plans folder: list, view/download, open in an editor --
    async def plans(request: Request) -> Response:
        h = dash.harness
        host = await asyncio.to_thread(dash.host_open, request)
        files = sorted((f for d in h.plan_dirs for f in huntplans.entries(d)), key=lambda f: -f["mtime"])
        return JSONResponse({"folder": str(h.hunt_plans_dir), "vuln_folder": str(h.vuln_dir), "cte_folder": str(h.cte_dir),
                             "reports_folder": str(h.reports_dir), "examples_folder": str(h.report_examples_dir), "files": files,
                             "host": host, "links": dash.editor_cfg["links"], "vscode_remote": dash.editor_cfg["vscode_remote"]})

    def plan_path(request: Request) -> Path | None:
        """A file directly in one of the case's plan and report folders (never raw/, older/ or maps/)."""
        name = request.path_params["name"]
        return next((p for d in dash.harness.plan_dirs if (p := huntplans.find(d, name))), None)

    NO_PLAN = {"error": "no such file in this case's plans and reports folders"}

    async def plan_file(request: Request) -> Response:
        path = plan_path(request)
        if not path:
            return JSONResponse(NO_PLAN, 404)
        if path.stat().st_size > 20 * 1024 * 1024:
            raise ValueError("file too large to show here; open it in an editor")
        data = path.read_bytes()
        if request.query_params.get("download"):
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.name)
            media = "application/json" if path.suffix == ".json" else "text/markdown; charset=utf-8"
            return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="{safe}"'})
        return Response(data, media_type="text/plain; charset=utf-8")

    async def plan_docx(request: Request) -> Response:
        """A markdown plan or report from the case, as a Word document (stdlib writer). Audited: it leaves the case."""
        path = plan_path(request)
        if not path or path.suffix != ".md":
            return JSONResponse({"error": "only a markdown file in this case's plans and reports folders can be exported"}, 404)
        if path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError("file too large to export")
        text = path.read_text(encoding="utf-8", errors="replace")
        draft = re.match(r"report_.+_v\d+\.md$", path.name) is not None
        notice = ("DRAFT - not yet approved by the analyst as the final report" if draft else "")
        data = await asyncio.to_thread(docx.to_docx, text, huntplans.title(path) or path.stem, notice)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.stem) + ".docx"
        s = dash.session(request)
        dash.harness.audit.record("file_exported", file=str(path), format="docx", draft=draft, bytes=len(data),
                                  user=s["user"] if s else "?")
        return Response(data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": f'attachment; filename="{safe}"'})

    async def plan_open(request: Request) -> Response:
        d = await body(request)
        path = plan_path(request)
        if not path:
            return JSONResponse(NO_PLAN, 404)
        host = await asyncio.to_thread(dash.host_open, request)
        if not host["available"]:
            return JSONResponse({"error": f"can't open it on the host: {host['why']}"}, 403)
        editor = str(d.get("editor") or "")
        msg = await asyncio.to_thread(editors.open_file, editor, path)
        dash.harness.audit.record("dashboard_open_file", file=str(path), editor=editor,
                                  client=request.client.host if request.client else "?")
        return JSONResponse({"ok": True, "message": msg})

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
        if not dash.start_run(playbook or "mission", lambda: dash.harness.mission(text, str(d.get("text", "")), playbook),
                              playbook=playbook):
            return JSONResponse({"error": "an operation is already running - wait or press Stop"}, 409)
        return JSONResponse({"ok": True})

    async def operation_resume(request: Request) -> Response:
        dash.resume_run(user_of(request))
        return JSONResponse({"ok": True})

    async def operation_end(request: Request) -> Response:
        return JSONResponse({"ok": dash.end_interrupted(user_of(request))})

    async def stop(request: Request) -> Response:
        return JSONResponse({"ok": dash.stop()})

    async def approval(request: Request) -> Response:
        d = await body(request)
        ok = dash.resolve(request.path_params["aid"], bool(d.get("approve")), str(d.get("note", ""))[:2000], user_of(request))
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
        mid, action = int(request.path_params["mid"]), str(d["action"])
        mem = dash.harness.memory
        if action == "edit":  # the analyst's correction; "approve": true also approves it in the same step
            ok = mem.edit(mid, str(d.get("title", "")), str(d.get("content", "")), user_of(request))
            status = "approved" if ok and d.get("approve") else ""
            if status:
                mem.set_status(mid, status, user_of(request))
        else:
            status = {"promote": "approved", "reject": "rejected", "retire": "retired"}[action]
            ok = mem.set_status(mid, status, user_of(request))
        dash.emit("memory_updated", {"id": mid, "status": status or "edited"})
        return JSONResponse({"ok": ok})

    async def learning(request: Request) -> Response:
        """The review queue: memory candidates and skill changes, from this conversation, this case or anywhere."""
        from ..skills import needs_revision, track_record

        scope = request.query_params.get("scope", "conversation")
        if scope not in ("conversation", "case", "all"):
            raise ValueError("scope: conversation, case or all")
        mems, versions, proposals, blocked = dash.learning(scope)
        st = dash.harness.skills
        names = {v["name"] for v in versions}
        skills = [r | {"track_record": track_record(r), "needs_revision": needs_revision(r)}
                  for r in st.list(include_retired=True) if r["name"] in names]
        return JSONResponse({"scope": scope, "case": dash.harness.case.id, "memories": mems,
                             "pending": [v | {"diff": st.diff(v["id"])} for v in versions], "skills": skills,
                             "tools": proposals, "blocked": blocked, "sandbox": dash.harness.onboarding.sandbox.describe(False),
                             "counts": dash.learning_counts()})

    async def onboarded(request: Request) -> Response:
        cat = dash.harness.onboarding.catalog
        return JSONResponse({"tools": cat.tools(), "proposals": len(cat.proposals())})

    async def tool_decision(request: Request) -> Response:
        d = await body(request)
        action = str(d.get("action"))
        if action not in ("approve", "reject"):
            raise ValueError("action: approve or reject")
        meta = await asyncio.to_thread(dash.harness.onboarding.decide, request.path_params["name"], int(request.path_params["n"]),
                                       action == "approve", user_of(request), str(d.get("note", ""))[:1000])
        dash.emit("skills_updated", {})  # the usage skills came with it; the Learning page re-reads
        return JSONResponse({"ok": True, "status": meta["status"]})

    async def tool_retest(request: Request) -> Response:
        """Re-run a blocked tool's golden trials against its changed binary, in the sandbox, for the analyst."""
        return JSONResponse(await dash.harness.onboarding.retest(request.path_params["name"]))

    async def tool_trust(request: Request) -> Response:
        d = await body(request)
        dash.harness.onboarding.trust(request.path_params["name"], str(d.get("sha256", "")), user_of(request))
        dash.emit("skills_updated", {})
        return JSONResponse({"ok": True})

    async def tool_retire(request: Request) -> Response:
        dash.harness.onboarding.catalog.retire(request.path_params["name"], user_of(request))
        dash.emit("skills_updated", {})
        return JSONResponse({"ok": True})

    async def retro(request: Request) -> Response:
        if not dash.start_run("after-action review", dash.harness.retro, kind="retro"):
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

    def user_of(request: Request) -> str:
        s = dash.session(request)
        return s["user"] if s else "?"

    async def setting_startup_get(request: Request) -> Response:
        return JSONResponse(await asyncio.to_thread(dash.startup_info))

    async def setting_posture(request: Request) -> Response:
        d = await body(request)
        dash.set_posture(str(d.get("posture", "")), user_of(request))
        return JSONResponse({"ok": True, "posture": dash.harness.roe.posture})

    async def setting_case(request: Request) -> Response:
        d = await body(request)
        await dash.switch_case(str(d.get("case", "")), user_of(request))
        return JSONResponse({"ok": True, "case": dash.harness.case.id})

    async def setting_address(request: Request) -> Response:
        d = await body(request)
        url = dash.move_address(str(d.get("address", "")), user_of(request))  # on the loop: it schedules the restart
        return JSONResponse({"ok": True, "url": url, "restarting": True})

    # -- subagents --
    async def subagent_steer(request: Request) -> Response:
        d = await body(request)
        dash.harness.steer_subagent(request.path_params["sid"], str(d.get("message", "")), user_of(request))
        return JSONResponse({"ok": True})

    async def subagent_stop(request: Request) -> Response:
        dash.harness.stop_subagent(request.path_params["sid"], user_of(request))
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
        dash.owner_q = asyncio.Queue()  # bound to this event loop
        ready = asyncio.get_running_loop().create_future()
        owner = asyncio.create_task(dash.own_harness(ready))
        await ready
        try:
            yield
        finally:
            await dash._ask_owner("close")
            await owner

    routes = [
        Route("/", index), Route("/login", login_page), Route("/static/{name}", asset),
        Route("/api/public", public_info),
        Route("/api/login", api_login, methods=["POST"]),
        Route("/api/logout", guard(api_logout, True), methods=["POST"]),
        Route("/api/activity", guard(activity, True), methods=["POST"]),
        Route("/api/subagents/{sid}/steer", guard(subagent_steer, True), methods=["POST"]),
        Route("/api/subagents/{sid}/stop", guard(subagent_stop, True), methods=["POST"]),
        Route("/api/state", guard(get_state)),
        Route("/api/events", guard(events_stream)),
        Route("/api/events/poll", guard(events_poll)),
        Route("/api/memory", guard(memory_list)),
        Route("/api/audit", guard(audit)),
        Route("/api/tools", guard(tools)),
        Route("/api/report", guard(report)),
        Route("/api/plans", guard(plans)),
        Route("/api/plans/{name}", guard(plan_file)),
        Route("/api/plans/{name}/open", guard(plan_open, True), methods=["POST"]),
        Route("/api/plans/{name}/docx", guard(plan_docx)),
        Route("/api/source/{sid}", guard(source)),
        Route("/api/message", guard(message, True), methods=["POST"]),
        Route("/api/stop", guard(stop, True), methods=["POST"]),
        Route("/api/operation/resume", guard(operation_resume, True), methods=["POST"]),
        Route("/api/operation/end", guard(operation_end, True), methods=["POST"]),
        Route("/api/approvals/{aid}", guard(approval, True), methods=["POST"]),
        Route("/api/verdict", guard(verdict, True), methods=["POST"]),
        Route("/api/remember", guard(remember, True), methods=["POST"]),
        Route("/api/memory/{mid:int}", guard(memory_action, True), methods=["POST"]),
        Route("/api/learning", guard(learning)),
        Route("/api/tools/onboarded", guard(onboarded)),
        Route("/api/tools/onboarded/{name}/retire", guard(tool_retire, True), methods=["POST"]),
        Route("/api/tools/onboarded/{name}/retest", guard(tool_retest, True), methods=["POST"]),
        Route("/api/tools/onboarded/{name}/trust", guard(tool_trust, True), methods=["POST"]),
        Route("/api/tools/proposals/{name}/{n:int}", guard(tool_decision, True), methods=["POST"]),
        Route("/api/retro", guard(retro, True), methods=["POST"]),
        Route("/api/rate", guard(rate, True), methods=["POST"]),
        Route("/api/model", guard(model, True), methods=["POST"]),
        Route("/api/settings/classification", guard(setting_classification, True), methods=["POST"]),
        Route("/api/settings/startup", guard(setting_startup_get)),
        Route("/api/settings/posture", guard(setting_posture, True), methods=["POST"]),
        Route("/api/settings/case", guard(setting_case, True), methods=["POST"]),
        Route("/api/settings/address", guard(setting_address, True), methods=["POST"]),
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
          new_conversation: bool = False, run_dir: str = "") -> None:
    import uvicorn

    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not (tls_cert and tls_key) and not allow_plaintext:
        raise SystemExit("refusing to serve the dashboard on a non-loopback address without TLS "
                         "(--tls-cert/--tls-key), or pass --allow-plaintext if you really mean it")
    acct = account.default_path(cfg)
    if not account.exists(acct):
        raise SystemExit("no dashboard account yet: run `canarchist account create` on this host first "
                         "(scripts/start.sh asks for it)")
    dash = Dashboard(cfg, case_id, model, posture, conversation_id=conversation_id, new_conversation=new_conversation,
                     account_path=acct, run_dir=Path(run_dir) if run_dir else None)
    scheme = "https" if tls_cert else "http"
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    dash.url = f"{scheme}://{shown}:{port}"
    dash.bind = {"host": host, "port": port}
    print(f"\n  Compensated Anarchist dashboard  case={case_id}\n"
          f"  open: {dash.url}/login?token={dash.token}\n"
          f"  sign in with this start's access token plus the dashboard account's username and password.\n"
          f"  (the token is new at every start; keep it private. Ctrl+C to stop.)\n", flush=True)
    server = uvicorn.Server(uvicorn.Config(create_app(dash), host=host, port=port, log_level="warning",
                                          ssl_certfile=tls_cert or None, ssl_keyfile=tls_key or None,
                                          timeout_graceful_shutdown=3))
    dash.server = server
    server.run()
    if dash.relaunch:  # the Settings page moved the address: same process, same token, new socket
        print(f"\n  moving to the new address; the access token stays the same\n", flush=True)
        os.execv(sys.executable, [sys.executable, *dash.relaunch])
