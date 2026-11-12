"""Accessibility: WCAG AA contrast of the dashboard's colors, and a keyboard-only walk-through in a real browser.

The browser test drives headless Chrome over its DevTools pipe (--remote-debugging-pipe, standard library only),
against a test dashboard with a long conversation, a cited report and a pending approval. It checks the rendered page
in both themes: every control has a name, ids are unique, ARIA references resolve, no control sits inside another,
text contrast meets AA, and Tab, arrow keys, Enter and Escape reach and operate everything with a visible focus ring.
"""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ROOT, TEST_PASSWORD, TEST_USER, ScriptedBackend, write_config  # noqa: E402

STATIC = ROOT / "compensated_anarchist" / "web" / "static"


# ---------------------------------------------------------------------------
# WCAG contrast of the color tokens (both themes)
# ---------------------------------------------------------------------------
def _tokens() -> tuple[dict[str, str], dict[str, str]]:
    css = (STATIC / "app.css").read_text()

    def block(sel: str) -> dict[str, str]:
        m = re.search(re.escape(sel) + r"\s*\{(.*?)\n\}", css, re.S)
        return dict(re.findall(r"--([\w-]+):\s*([^;]+);", m.group(1)))
    dark = block(":root")
    return dark, {**dark, **block(':root[data-theme="light"]')}


def _rgba(v: str) -> tuple[float, ...]:
    v = v.strip()
    if v.startswith("#"):
        return tuple(int(v[i:i + 2], 16) for i in (1, 3, 5)) + (1.0,)
    m = re.match(r"rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)", v)
    return (int(m[1]), int(m[2]), int(m[3]), float(m[4]))


def _over(top: tuple[float, ...], under: tuple[float, ...]) -> tuple[float, ...]:
    a = top[3]
    return tuple(top[i] * a + under[i] * (1 - a) for i in range(3)) + (1.0,)


def contrast(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    def lum(c):
        ch = [x / 255 for x in c[:3]]
        ch = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in ch]
        return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2]
    hi, lo = sorted([lum(a), lum(b)], reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# (text token, backgrounds it is shown on); tinted backgrounds are composited over the panel and the page
TEXT_PAIRS = [("text", ["bg", "bg-2", "panel", "elev", "hover"]), ("text-2", ["bg", "bg-2", "panel", "elev", "hover"]),
              ("text-3", ["bg", "bg-2", "panel", "elev", "hover"]), ("red-hi", ["bg", "panel", "elev", "red-bg"]),
              ("ok", ["bg", "panel", "ok-bg"]), ("warn", ["bg", "panel", "warn-bg"]), ("sev-critical", ["panel", "red-bg"]),
              ("sev-high", ["panel"]), ("sev-medium", ["panel"]), ("sev-low", ["panel"])]


def test_color_tokens_meet_wcag_aa():
    failures = []
    for theme, t in zip(("dark", "light"), _tokens()):
        checks = [(fg, bgs, 4.5) for fg, bgs in TEXT_PAIRS] + [("#ffffff", ["red"], 4.5),  # white on the primary red
                                                                ("red", ["bg", "bg-2", "panel", "elev"], 3.0)]  # focus ring
        for fg, bgs, need in checks:
            for b in bgs:
                for base in ("panel", "bg"):
                    bc = _rgba(t[b])
                    bc = _over(bc, _rgba(t[base])) if bc[3] < 1 else bc
                    fc = _rgba(fg if fg.startswith("#") else t[fg])
                    fc = _over(fc, bc) if fc[3] < 1 else fc
                    if (r := contrast(fc, bc)) < need:
                        failures.append(f"{theme}: {fg} on {b} (over {base}) {r:.2f} < {need}")
    assert not failures, "\n".join(failures)


def test_classification_banner_presets_are_readable():
    js = (STATIC / "app.js").read_text()
    presets = re.findall(r'\{ id: "(\w+)", label: "[^"]+", text: "([^"]*)", background: "(#\w{6})", color: "(#\w{6})" \}', js)
    assert len(presets) >= 6
    for pid, text, bg, fg in presets:
        if text:
            assert contrast(_rgba(fg), _rgba(bg)) >= 4.5, f"marking preset {pid}"


# ---------------------------------------------------------------------------
# keyboard-only walk-through and rendered-page audit in headless Chrome
# ---------------------------------------------------------------------------
CHROME = next((c for c in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser") if shutil.which(c)), None)


class Chrome:
    """Chrome DevTools Protocol over --remote-debugging-pipe: JSON messages separated by NUL on fds 3 (in) and 4 (out)."""

    def __init__(self, profile: Path):
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        cmd = (f'exec 3<&{r1} 4>&{w2}; exec "$0" --headless=new --remote-debugging-pipe --no-first-run '
               f'--no-default-browser-check --disable-gpu --disable-extensions --disable-sync --mute-audio '
               f'--user-data-dir="$1" about:blank')
        self.proc = subprocess.Popen(["bash", "-c", cmd, shutil.which(CHROME), str(profile)], pass_fds=(r1, w2),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(r1)
        os.close(w2)
        self.w, self.r, self.buf, self.n = w1, r2, b"", 0
        self.sid = ""

    def send(self, method: str, params: dict | None = None, session: bool = True, timeout: float = 20):
        self.n += 1
        msg = {"id": self.n, "method": method, "params": params or {}}
        if session and self.sid:
            msg["sessionId"] = self.sid
        data = json.dumps(msg).encode() + b"\0"
        while data:
            data = data[os.write(self.w, data):]
        deadline = time.time() + timeout
        while True:
            while b"\0" not in self.buf:
                ready, _, _ = select.select([self.r], [], [], max(0.0, deadline - time.time()))
                if not ready:
                    raise TimeoutError(method)
                chunk = os.read(self.r, 1 << 16)
                if not chunk:
                    raise EOFError("Chrome closed the DevTools pipe")
                self.buf += chunk
            raw, _, self.buf = self.buf.partition(b"\0")
            m = json.loads(raw)
            if m.get("id") == self.n:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})

    def open(self, url: str) -> None:
        target = self.send("Target.createTarget", {"url": "about:blank"}, session=False)["targetId"]
        self.sid = self.send("Target.attachToTarget", {"targetId": target, "flatten": True}, session=False)["sessionId"]
        for m in ("Page.enable", "Runtime.enable"):
            self.send(m)
        self.send("Emulation.setDeviceMetricsOverride", {"width": 1400, "height": 900, "deviceScaleFactor": 1, "mobile": False})
        self.send("Page.navigate", {"url": url})

    def js(self, expr: str):
        r = self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in r:
            raise RuntimeError(f"{expr[:80]}: {r['exceptionDetails'].get('exception', {}).get('description', r['exceptionDetails'])}")
        return r["result"].get("value")

    def wait(self, expr: str, timeout: float = 20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                v = self.js(expr)
            except RuntimeError:
                v = None
            if v:
                return v
            time.sleep(0.1)
        raise AssertionError(f"timed out waiting for: {expr}")

    def key(self, key: str, code: str = "", vk: int = 0, mods: int = 0, text: str = "") -> None:
        base = {"key": key, "code": code or key, "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk, "modifiers": mods}
        self.send("Input.dispatchKeyEvent", {"type": "keyDown", **base, **({"text": text} if text else {})})
        self.send("Input.dispatchKeyEvent", {"type": "keyUp", **base})
        time.sleep(0.05)

    def tab(self, back: bool = False) -> None:
        self.key("Tab", "Tab", 9, 8 if back else 0)

    def close(self) -> None:
        try:
            self.send("Browser.close", session=False, timeout=5)
        except (RuntimeError, TimeoutError, EOFError, OSError):
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        os.close(self.w)
        os.close(self.r)


# Page-side helpers: accessible names, visibility, and the rendered-page audit (text contrast included).
AUDIT_JS = r"""
window.__a11y = (() => {
  const vis = (n) => { const r = n.getBoundingClientRect(); const cs = getComputedStyle(n);
    return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none" && !n.closest("[hidden],[inert]"); };
  const txt = (n) => (n ? n.textContent : "").replace(/\s+/g, " ").trim();
  function name(n) {
    const l = n.getAttribute("aria-label"); if (l && l.trim()) return l.trim();
    const lb = n.getAttribute("aria-labelledby"); if (lb) return lb.split(/\s+/).map((id) => txt(document.getElementById(id))).join(" ").trim();
    if (n.id) { const lab = document.querySelector(`label[for="${CSS.escape(n.id)}"]`); if (lab && txt(lab)) return txt(lab); }
    const wrap = n.closest("label"); if (wrap && txt(wrap)) return txt(wrap);
    if (["INPUT", "TEXTAREA", "SELECT"].includes(n.tagName)) return (n.getAttribute("title") || "").trim();
    return txt(n) || (n.getAttribute("title") || "").trim();
  }
  const desc = (n) => `${n.tagName.toLowerCase()}${n.id ? "#" + n.id : ""}${n.className && typeof n.className === "string" ? "." + n.className.trim().split(/\s+/).join(".") : ""} "${txt(n).slice(0, 40)}"`;
  const parse = (c) => { const m = /rgba?\(([^)]+)\)/.exec(c); if (!m) return null; const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
  const lum = (c) => { const f = (x) => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
  const ratio = (a, b) => { const [h, l] = [lum(a), lum(b)].sort((x, y) => y - x); return (h + 0.05) / (l + 0.05); };
  function background(n) {
    const layers = [];
    for (let x = n; x; x = x.parentElement) {
      const cs = getComputedStyle(x);
      if (cs.backgroundImage !== "none" || parseFloat(cs.opacity) < 1) return null;
      const c = parse(cs.backgroundColor); if (!c) return null;
      if (c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
    }
    let base = [255, 255, 255];
    for (const c of layers.reverse()) base = base.map((v, i) => c[i] * c[3] + v * (1 - c[3]));
    return base;
  }
  const INTERACTIVE = "button, a[href], input:not([type=hidden]), select, textarea, [role=button], [role=tab], [role=menuitem], [role=option], [tabindex]:not([tabindex='-1'])";
  function audit() {
    const out = { unnamed: [], dupIds: [], badRefs: [], nested: [], contrast: [] };
    const inter = [...document.querySelectorAll(INTERACTIVE)].filter(vis);
    for (const n of inter) {
      if (!name(n)) out.unnamed.push(desc(n));
      const outer = n.parentElement && n.parentElement.closest("button, a[href]");
      if (outer && n.matches("button, a[href], input, select, textarea, [role=button]")) out.nested.push(desc(n) + " in " + desc(outer));
    }
    const seen = {};
    for (const n of document.querySelectorAll("[id]")) seen[n.id] = (seen[n.id] || 0) + 1;
    out.dupIds = Object.entries(seen).filter(([, c]) => c > 1).map(([k]) => k);
    for (const attr of ["aria-controls", "aria-labelledby", "aria-describedby", "aria-activedescendant"])
      for (const n of document.querySelectorAll(`[${attr}]`))
        for (const id of n.getAttribute(attr).split(/\s+/).filter(Boolean)) if (!document.getElementById(id)) out.badRefs.push(`${desc(n)} ${attr}=${id}`);
    for (const n of document.querySelectorAll("body *")) {
      if (![...n.childNodes].some((c) => c.nodeType === 3 && c.textContent.trim())) continue;
      if (!vis(n) || n.closest(".cls-banner, .cls-mock, [disabled], [aria-disabled=true], .sr-only, svg")) continue;
      const cs = getComputedStyle(n), fg = parse(cs.color), bg = background(n);
      if (!fg || !bg) continue;
      const f = fg.slice(0, 3).map((v, i) => v * fg[3] + bg[i] * (1 - fg[3]));
      const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight, 10) >= 700;
      const need = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
      const r = ratio(f, bg);
      if (r < need - 0.01) out.contrast.push(`${desc(n)} ${r.toFixed(2)} < ${need}`);
    }
    return out;
  }
  function focused() {
    const a = document.activeElement;
    if (!a || a === document.body) return { tag: "BODY" };
    const cs = getComputedStyle(a);
    const ring = (cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) > 0) || (cs.boxShadow && cs.boxShadow !== "none");
    return { tag: a.tagName, desc: desc(a), name: name(a), ring, visible: vis(a), dialog: !!a.closest("[role=dialog]"),
             custom: a.matches(".menu-item, .pal-item, .conv, .tab, input, textarea, select") };
  }
  return { audit, focused, name };
})(); true
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Served:
    """A dashboard served on 127.0.0.1 from a background thread, signed in from headless Chrome."""

    def __init__(self, dash, tmp: Path):
        import uvicorn

        from compensated_anarchist.web.app import create_app
        self.server = uvicorn.Server(uvicorn.Config(create_app(dash), host="127.0.0.1", port=_free_port(), log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.tmp = tmp

    def __enter__(self) -> Chrome:
        self.thread.start()
        deadline = time.time() + 30
        while not self.server.started and time.time() < deadline:
            time.sleep(0.1)
        assert self.server.started, "dashboard did not start"
        self.chrome = Chrome(self.tmp / f"chrome-{time.time_ns()}")
        c = self.chrome
        c.open(f"http://127.0.0.1:{self.server.config.port}/login?token=test-token")
        c.wait("document.readyState === 'complete' && !!document.getElementById('username')")
        c.js(f"document.getElementById('username').value = {json.dumps(TEST_USER)};"
             f"document.getElementById('password').value = {json.dumps(TEST_PASSWORD)};"
             "document.getElementById('login-btn').click(); true")
        c.wait("location.pathname === '/' && typeof S !== 'undefined' && !!S.st")
        c.js(AUDIT_JS)
        return c

    def __exit__(self, *exc) -> None:
        self.chrome.close()
        self.server.should_exit = True
        self.thread.join(20)


def screenshot(chrome: Chrome, path: Path) -> None:
    import base64
    path.write_bytes(base64.b64decode(chrome.send("Page.captureScreenshot", {"format": "png"})["data"]))


@pytest.mark.skipif(CHROME is None, reason="no Chrome/Chromium on this host")
def test_keyboard_walkthrough_and_rendered_audit(tmp_path, monkeypatch):
    import uvicorn

    from compensated_anarchist import agent as agent_mod
    from compensated_anarchist.config import load_config
    from compensated_anarchist.history import ChatStore
    from compensated_anarchist.web.app import Dashboard, create_app

    cfg = load_config(write_config(tmp_path))
    cfg.orchestration["lead_tools"] = ["*"]  # the lead asks for an approval itself (keeps the scenario short)
    # a long conversation already on record, with citations in it
    store = ChatStore(cfg.history_db)
    conv = store.create("A11Y-1", "Long running hunt")
    t0 = time.time() - 7200
    for i in range(110):
        store.append(conv["id"], "s0", "analyst_message", {"text": f"Question {i}: what about host ws{i:02d}?", "playbook": ""}, t0 + i * 10)
        store.append(conv["id"], "s0", "text", {"agent": "lead", "agent_id": "lead", "final": True,
                                                "text": f"Answer {i}: nothing new on ws{i:02d} [FIN-0001]."}, t0 + i * 10 + 5)
    fake = ScriptedBackend({"lead": [("Action brief: quarantine ws01, active C2 [FIN-0001].",
                                      [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})]),
                                     ("And once more, to be sure.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})]),
                                     ("Contained ws01; the second request was denied.", [])]})
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    dash = Dashboard(cfg, "A11Y-1", token="test-token")
    h = dash.harness
    h.case.add_finding("Beaconing from ws01", "high", "ws01 beacons to 203.0.113.9 every 60 s.", ["T1071.001"], ["ws01"])
    h.case.add_ioc("ip", "203.0.113.9", "C2 address", "high")
    h.skills.propose("zeek-beacon-triage", "network_analyst", "Triage a beacon candidate from Zeek conn logs.",
                     "1. Count connections per pair.\n2. Check the interval and jitter.", "first version", author="SA-001")
    (h.reports_dir / "report_ws01_v1.md").write_text("# Incident report\n\nws01 beaconed to 203.0.113.9 [FIN-0001, IOC-0001].\n")
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(dash), host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 30
    while not server.started and time.time() < deadline:
        time.sleep(0.1)
    assert server.started, "dashboard did not start"
    chrome = Chrome(tmp_path / "chrome-profile")
    try:
        base = f"http://127.0.0.1:{port}"
        chrome.open(f"{base}/login?token=test-token")
        chrome.wait("document.readyState === 'complete' && !!document.getElementById('username')")
        chrome.js(AUDIT_JS)
        login = chrome.js("__a11y.audit()")
        assert not login["unnamed"] and not login["contrast"] and not login["badRefs"], login
        chrome.js(f"document.getElementById('username').value = {json.dumps(TEST_USER)};"
                  f"document.getElementById('password').value = {json.dumps(TEST_PASSWORD)};"
                  "document.getElementById('login-btn').click(); true")
        chrome.wait("location.pathname === '/' && !!document.querySelector('.feed .turn')")
        chrome.js(AUDIT_JS)

        # long conversation: only the newest turns are in the page; the rest come back on request
        n_turns = chrome.wait("document.querySelectorAll('.feed .turn').length")
        assert n_turns <= 60, n_turns
        assert chrome.js("!!document.querySelector('.feed-more')")
        chrome.js("document.querySelector('.feed-more').click(); true")
        assert chrome.wait(f"document.querySelectorAll('.feed .turn').length > {n_turns}")

        # an approval request: announced once to screen readers, reviewable from the keyboard
        chrome.js("api('/api/message', {text: 'contain ws01'}).then(() => true)")
        chrome.wait("document.getElementById('announcer').textContent.includes('Approval needed')")

        # the rendered page, dark then light: names, ids, ARIA references, nesting, contrast
        for theme in ("dark", "light"):
            chrome.js(f"document.documentElement.dataset.theme = '{theme}'; true")
            time.sleep(0.2)
            found = chrome.js("__a11y.audit()")
            assert not any(found.values()), f"{theme}: {json.dumps(found, indent=1)}"

        # keyboard only: Tab through the page; every stop is visible, named and shows focus
        # start from the top of the page (Chrome continues Tab from the last focused element otherwise)
        chrome.js("const a = document.createElement('span'); a.tabIndex = -1; document.body.prepend(a); a.focus(); true")
        chrome.tab()
        assert "Skip to the message box" in chrome.js("__a11y.focused().name")
        chrome.key("Enter", "Enter", 13, text="\r")
        assert chrome.wait("document.activeElement && document.activeElement.id === 'composer'")
        stops, seen = [], set()
        for _ in range(120):
            chrome.tab()
            f = chrome.js("__a11y.focused()")
            stops.append(f)
            seen.add(f.get("desc"))
        # past the last control Tab leaves the page for the browser's own UI, then comes back to the skip link
        wraps = [i for i, f in enumerate(stops) if f["tag"] == "BODY"]
        assert wraps and all(i + 1 < len(stops) and "Skip to" in stops[i + 1]["name"] for i in wraps[:-1] if i + 1 < len(stops)), \
            "focus fell to the page: " + json.dumps([f.get("desc", "BODY") for f in stops], indent=0)
        stops = [f for f in stops if f["tag"] != "BODY"]
        hidden = [f["desc"] for f in stops if not f["visible"]]
        assert not hidden, f"focus went to something invisible: {hidden}"
        unnamed = [f["desc"] for f in stops if not f["name"]]
        assert not unnamed, f"focus stops without a name: {unnamed}"
        no_ring = sorted({f["desc"] for f in stops if not f["ring"] and not f["custom"]})
        assert not no_ring, f"no visible focus ring: {no_ring}"
        assert len(seen) > 25, f"Tab reached only {len(seen)} controls"
        assert any("Review" in (f["name"] or "") for f in stops)  # the approval banner's button
        assert any(f.get("tag") == "SPAN" and "FIN-0001" in f["desc"] for f in stops)  # citations are in the Tab order

        # a citation opens its source from the keyboard; Escape closes it and gives focus back
        chrome.js("document.querySelector('.feed .cite').focus(); true")
        chrome.key("Enter", "Enter", 13, text="\r")
        assert "FIN-0001" in chrome.wait("document.querySelector('[role=dialog] h2') && document.querySelector('[role=dialog] h2').textContent")
        assert "203.0.113.9" in chrome.js("document.querySelector('.source-text').textContent")
        chrome.key("Escape", "Escape", 27)
        assert chrome.wait("!document.querySelector('[role=dialog]') && document.activeElement.classList.contains('cite')")

        # the approval dialog: opened with Enter, focus stays inside it, Escape returns focus to the button
        chrome.js("[...document.querySelectorAll('.banner .btn-primary')].find((b) => b.textContent === 'Review').focus(); true")
        chrome.key("Enter", "Enter", 13, text="\r")
        chrome.wait("!!document.querySelector('[role=dialog]')")
        for _ in range(15):
            chrome.tab()
            assert chrome.js("__a11y.focused().dialog"), "focus escaped the dialog"
        chrome.key("Escape", "Escape", 27)
        assert chrome.wait("!document.querySelector('[role=dialog]') && document.activeElement.textContent === 'Review'")

        # the command palette: Ctrl+K, arrow keys move the active option, Escape closes it
        chrome.key("k", "KeyK", 75, mods=2)
        chrome.wait("!!document.querySelector('.palette')")
        first = chrome.js("document.querySelector('.palette input').getAttribute('aria-activedescendant')")
        chrome.key("ArrowDown", "ArrowDown", 40)
        assert chrome.js("document.querySelector('.palette input').getAttribute('aria-activedescendant')") != first
        chrome.key("Escape", "Escape", 27)
        chrome.wait("!document.querySelector('.palette')")

        # case panel tabs: arrow keys move between them; the report's citations work there too
        chrome.js("S.insp.open = true; S.insp.tab = 'findings'; renderInsp(); document.getElementById('case-tab-findings').focus(); true")
        chrome.key("ArrowRight", "ArrowRight", 39)
        assert chrome.wait("document.activeElement.id === 'case-tab-iocs' && document.activeElement.getAttribute('aria-selected') === 'true'")
        chrome.key("End", "End", 35)
        assert chrome.wait("document.activeElement.id === 'case-tab-report'")
        chrome.wait("!!document.querySelector('#case-panel .cite')")
        assert chrome.js("[...document.querySelectorAll('#case-panel .cite')].map((c) => c.textContent).join(',')") == "FIN-0001,IOC-0001"
        assert chrome.js("[...document.querySelectorAll('#case-panel button')].some((b) => b.textContent.includes('Word'))")
        if os.environ.get("CA_SCREENSHOTS"):
            shot = Path(os.environ["CA_SCREENSHOTS"])
            screenshot(chrome, shot / "report_tab.png")
            chrome.js("document.querySelector('#case-panel .cite').click(); true")
            chrome.wait("!!document.querySelector('.source-view')")
            screenshot(chrome, shot / "citation_source.png")
            chrome.key("Escape", "Escape", 27)
        found = chrome.js("__a11y.audit()")
        assert not any(found.values()), json.dumps(found, indent=1)

        # keyboard only: approve the request, then deny the next one
        def press_in_dialog(label: str) -> None:
            for _ in range(20):
                if chrome.js("document.activeElement.textContent.trim()") == label:
                    chrome.key("Enter", "Enter", 13, text="\r")
                    return
                chrome.tab()
            raise AssertionError(f"Tab never reached {label}")

        def review_with_keyboard() -> None:
            chrome.js("[...document.querySelectorAll('.banner .btn-primary')].find((b) => b.textContent === 'Review').focus(); true")
            chrome.key("Enter", "Enter", 13, text="\r")
            chrome.wait("!!document.querySelector('[role=dialog]')")

        first = chrome.js("S.bannerId")
        review_with_keyboard()
        press_in_dialog("Approve")
        assert chrome.wait("document.activeElement.textContent === 'Confirm approval'")  # armed; Enter again confirms
        chrome.key("Enter", "Enter", 13, text="\r")
        chrome.wait(f"!document.querySelector('[role=dialog]') && !S.pending.has({json.dumps(first)})")
        chrome.wait(f"S.pending.size === 1 && S.bannerId !== {json.dumps(first)}")  # the second request
        review_with_keyboard()
        press_in_dialog("Deny")
        chrome.wait("!S.running")
        rows = dash.harness.history.approvals(dash.harness.conversation["id"], ("approved", "denied"))
        assert [r["status"] for r in rows] == ["approved", "denied"] and all(r["decided_by"] == TEST_USER for r in rows)

        # keyboard only: review a skill proposal (palette -> Skills -> Approve, confirm)
        chrome.key("k", "KeyK", 75, mods=2)
        chrome.wait("!!document.querySelector('.palette input')")
        chrome.js("const i = document.querySelector('.palette input'); i.value = 'skills go to'; i.dispatchEvent(new Event('input')); true")
        chrome.key("Enter", "Enter", 13, text="\r")
        chrome.wait("location.hash === '#/skills' && !!document.querySelector('.diff')")
        assert not any(chrome.js("__a11y.audit()").values())
        chrome.js("document.getElementById('skills-tab-review').focus(); true")
        for _ in range(30):
            chrome.tab()
            if chrome.js("document.activeElement.textContent.trim()") == "Approve":
                break
        chrome.key("Enter", "Enter", 13, text="\r")
        chrome.key("Enter", "Enter", 13, text="\r")
        chrome.wait("document.querySelector('.page').textContent.includes('Nothing waiting for review')")
        assert dash.harness.skills.get("zeek-beacon-triage")["active_version"] == 1
        chrome.js("location.hash = '#/'; true")
        chrome.wait("!document.getElementById('view-ops').hidden")

        # menus say they open a menu, and Escape gives focus back to their button
        chrome.js("document.querySelector('[aria-label=\"Conversation actions\"]').focus(); true")
        chrome.key("Enter", "Enter", 13, text="\r")
        chrome.wait("!!document.querySelector('.menu')")
        assert chrome.js("document.querySelector('[aria-label=\"Conversation actions\"]').getAttribute('aria-expanded')") == "true"
        chrome.key("Escape", "Escape", 27)
        assert chrome.wait("!document.querySelector('.menu') && document.activeElement.getAttribute('aria-label') === 'Conversation actions'")
    finally:
        chrome.close()
        server.should_exit = True
        th.join(20)
