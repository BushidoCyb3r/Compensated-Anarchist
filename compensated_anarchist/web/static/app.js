// Compensated Anarchist dashboard.
// SECURITY: agent output, tool output, logs and case data are attacker-influenced. Every string is
// inserted with textContent / DOM nodes - never innerHTML - so nothing in that data can execute.
"use strict";

const S = { state: null, lastSeq: 0, tab: "approvals", pending: new Map(), activeExperts: new Set(), es: null,
            memStatus: "candidate", roeFilter: "" };
const SEV = ["critical", "high", "medium", "low", "informational"];

// ---------------------------------------------------------------- helpers
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false)
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}
const $ = (id) => document.getElementById(id);
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
function fmtTime(ts) { return new Date(ts * 1000).toISOString().slice(11, 19) + "Z"; }
function toast(msg, err) {
  const t = el("div", { class: "toast" + (err ? " err" : ""), text: msg });
  document.body.append(t); setTimeout(() => t.remove(), err ? 7000 : 3500);
}
async function api(path, body) {
  const opts = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.method = "POST"; opts.body = JSON.stringify(body);
    opts.headers["Content-Type"] = "application/json"; opts.headers["X-CA-Request"] = "1";
  }
  const r = await fetch(path, opts);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || ("HTTP " + r.status));
  return data;
}
function nearBottom(n) { return n.scrollHeight - n.scrollTop - n.clientHeight < 120; }

// ---------------------------------------------------------------- minimal safe markdown -> DOM
function inline(text) {
  const frag = document.createDocumentFragment();
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) frag.append(document.createTextNode(text.slice(last, m.index)));
    const t = m[0];
    frag.append(t.startsWith("**") ? el("strong", { text: t.slice(2, -2) }) : el("code", { text: t.slice(1, -1) }));
    last = m.index + t.length;
  }
  if (last < text.length) frag.append(document.createTextNode(text.slice(last)));
  return frag;
}
function md(src) {
  const root = el("div", { class: "md" });
  const lines = String(src || "").replace(/\r/g, "").split("\n");
  let i = 0, list = null, para = [];
  const flush = () => { if (para.length) { root.append(el("p", {}, inline(para.join(" ")))); para = []; } list = null; };
  while (i < lines.length) {
    const ln = lines[i];
    if (ln.startsWith("```")) {
      flush(); const buf = []; i++;
      while (i < lines.length && !lines[i].startsWith("```")) buf.push(lines[i++]);
      root.append(el("pre", { text: buf.join("\n") })); i++; continue;
    }
    const h = ln.match(/^(#{1,4})\s+(.*)$/);
    if (h) { flush(); root.append(el("h" + Math.min(h[1].length, 4), {}, inline(h[2]))); i++; continue; }
    if (/^\s*\|.*\|\s*$/.test(ln)) {
      flush(); const tbl = el("table"); let header = true;
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        const cells = lines[i].trim().slice(1, -1).split("|").map((c) => c.trim());
        if (cells.every((c) => /^:?-{2,}:?$/.test(c))) { i++; header = false; continue; }
        tbl.append(el("tr", {}, cells.map((c) => el(header ? "th" : "td", {}, inline(c)))));
        header = false; i++;
      }
      root.append(tbl); continue;
    }
    const li = ln.match(/^\s*([-*]|\d+\.)\s+(.*)$/);
    if (li) {
      if (para.length) { root.append(el("p", {}, inline(para.join(" ")))); para = []; }
      const ordered = /\d+\./.test(li[1]);
      if (!list || list.tagName !== (ordered ? "OL" : "UL")) { list = el(ordered ? "ol" : "ul"); root.append(list); }
      list.append(el("li", {}, inline(li[2]))); i++; continue;
    }
    if (!ln.trim()) { flush(); i++; continue; }
    list = null; para.push(ln.trim()); i++;
  }
  flush();
  return root;
}

// ---------------------------------------------------------------- state / chrome
async function refreshState() {
  S.state = await api("/api/state");
  const st = S.state;
  $("case-chip").textContent = "case " + st.case.id;
  const pc = $("posture-chip"); pc.textContent = st.posture.toUpperCase(); pc.className = "chip posture " + st.posture;
  $("operator-chip").textContent = "operator " + st.operator;
  $("mission").textContent = st.case.mission ? "Mission: " + st.case.mission.slice(0, 300) : "No mission yet — task the lead below.";
  const ms = clear($("model-select"));
  for (const m of st.models) ms.append(el("option", { value: m.name, selected: m.name === st.model, text: `${m.name} (${m.model})` }));
  ms.disabled = st.running;
  setRunning(st.running, st.run_label);
  const conn = clear($("connectors"));
  const entries = Object.entries(st.connectors);
  if (!entries.length) conn.append(el("li", { class: "muted small", text: "none enabled (harness.yaml)" }));
  for (const [name, status] of entries) {
    const ok = status.startsWith("connected");
    conn.append(el("li", {}, el("span", { class: "dot " + (ok ? "on" : "off") }),
      el("span", {}, name, el("span", { class: "status", text: status }))));
  }
  renderExperts();
  const pbs = clear($("playbooks")); const pbsel = $("playbook-select"); const cur = pbsel.value;
  clear(pbsel).append(el("option", { value: "", text: "no playbook" }));
  for (const p of st.playbooks) {
    pbs.append(el("button", { type: "button", text: p.replace(/_/g, " "), onclick: () => { pbsel.value = p; $("input").focus(); } }));
    pbsel.append(el("option", { value: p, text: p.replace(/_/g, " "), selected: p === cur }));
  }
  const mem = Object.entries(st.memory);
  $("memory-stats").textContent = mem.length ? mem.map(([k, v]) => `${k}: ${v}`).join("  ·  ") : "empty";
  S.pending = new Map(st.pending.map((p) => [p.id, p]));
  renderTabs(); renderPanel();
}
function renderExperts() {
  const ul = clear($("experts"));
  for (const e of S.state.experts) {
    const active = S.activeExperts.has(e.name);
    ul.append(el("li", { class: active ? "active" : "", title: e.description },
      el("span", { class: "dot " + (active ? "busy" : "on") }),
      el("span", {}, el("span", { class: "title", text: e.title }), el("span", { class: "sub", text: `${e.name} · ${e.model}` }))));
  }
}
function setRunning(running, label) {
  const ri = $("run-indicator");
  ri.textContent = running ? "running: " + (label || "operation") : "idle";
  ri.className = "run " + (running ? "busy" : "idle");
  $("stop-btn").classList.toggle("hidden", !running);
  $("send-btn").disabled = running; $("retro-btn").disabled = running; $("model-select").disabled = running;
}

// ---------------------------------------------------------------- feed
const feed = () => $("feed");
function addFeed(node) { const f = feed(); const stick = nearBottom(f); f.append(node); if (stick) f.scrollTop = f.scrollHeight; }
function argsStr(a) { try { return JSON.stringify(a); } catch { return String(a); } }

function onEvent(ev) {
  if (ev.seq <= S.lastSeq) return;
  S.lastSeq = ev.seq;
  const d = ev.data || {};
  switch (ev.kind) {
    case "analyst_message":
      addFeed(el("div", { class: "msg analyst" }, el("div", { class: "who", text: "analyst" + (d.playbook ? " · playbook " + d.playbook : "") }),
        el("div", { text: d.text || "(playbook)" }))); break;
    case "text":
      if (d.agent === "lead") addFeed(el("div", { class: "msg lead" + (d.final ? "" : " interim") },
        el("div", { class: "who", text: d.final ? "DCO lead" : "DCO lead · working" }), md(d.text)));
      else if (!d.final) addFeed(el("div", { class: "tl" }, el("span", { class: "agent", text: d.agent }), el("span", { text: d.text.slice(0, 400) })));
      break;  // an expert's final text arrives as its report card (expert_done)
    case "delegate":
      S.activeExperts.add(d.expert); if (S.state) renderExperts();
      addFeed(el("div", { class: "card" }, el("strong", { text: "→ " + (d.title || d.expert) }), " ", el("span", { class: "muted", text: d.task })));
      break;
    case "expert_done":
      S.activeExperts.delete(d.expert); if (S.state) renderExperts();
      addFeed(el("div", { class: "card " + (d.ok ? "done" : "failed") },
        el("details", {}, el("summary", { text: (d.ok ? "✓ report from " : "✗ failed: ") + d.expert }), d.ok ? md(d.report) : el("pre", { text: d.error || "" }))));
      break;
    case "decision": {
      if (d.tool === "delegate" && d.allowed) break;  // shown as a delegation card
      const line = el("div", { class: "tl" + (d.allowed ? "" : " denied") },
        el("span", { class: "agent", text: d.agent }), el("span", { class: "tool", text: d.tool }),
        el("span", { class: "tier " + d.tier, text: d.tier }), el("span", { class: "args", text: argsStr(d.args), title: argsStr(d.args) }));
      if (!d.allowed) line.append(el("span", { class: "reason", text: d.reason }));
      addFeed(line); break;
    }
    case "result":
      if (d.tool === "delegate" && !d.error) break;
      addFeed(el("div", { class: "tl result" }, el("details", {},
        el("summary", { text: `↳ ${d.agent} ${d.tool}: ${d.chars} chars, ${d.seconds}s${d.error ? " — ERROR" : ""}` }),
        el("pre", { text: d.preview || "" }))));
      if (String(d.tool).startsWith("case_")) scheduleRefresh();
      break;
    case "approval_request":
      S.pending.set(d.id, d);
      addFeed(el("div", { class: "sysline warn", text: `⚠ approval requested: ${d.tool} — see Approvals` }));
      if (!S.replaying) { S.tab = "approvals"; history.replaceState(null, "", "#approvals"); }
      renderTabs(); renderPanel(); attention(); break;
    case "approval_resolved":
      S.pending.delete(d.id);
      addFeed(el("div", { class: "sysline", text: `${d.approved ? "✓ approved" : "✗ denied"}${d.note ? ": " + d.note : ""}` }));
      renderTabs(); if (S.tab === "approvals") renderPanel(); attention(); break;
    case "run_start": setRunning(true, d.label); break;
    case "run_end":
      setRunning(false); S.activeExperts.clear(); if (S.state) renderExperts();
      if (!d.ok) addFeed(el("div", { class: "msg lead error" }, el("div", { class: "who", text: d.stopped ? "stopped" : "error" }), el("div", { text: d.text })));
      else addFeed(el("div", { class: "sysline", text: `operation complete (${d.seconds}s)` }));
      scheduleRefresh(); break;
    case "compact": addFeed(el("div", { class: "sysline", text: `${d.agent}: compacted ${d.dropped} old messages` })); break;
    case "case_updated": case "memory_updated": case "model_switched": case "rated": case "ready": scheduleRefresh(); break;
  }
}
let refreshTimer = null;
function scheduleRefresh() { clearTimeout(refreshTimer); refreshTimer = setTimeout(() => refreshState().catch(() => {}), 400); }
function attention() {
  const n = S.pending.size;
  document.title = (n ? `(${n}) APPROVAL · ` : "") + "Compensated Anarchist";
}

function connect() {
  if (S.es) S.es.close();
  const es = new EventSource("/api/events?after=" + S.lastSeq);
  S.es = es;
  es.onopen = () => { $("conn-dot").className = "dot on"; };
  es.onerror = () => { $("conn-dot").className = "dot off"; es.close(); setTimeout(connect, 2500); };
  es.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch (e) { console.error(e); } };
}

// ---------------------------------------------------------------- right panel
const TABS = [["approvals", "Approvals"], ["findings", "Findings"], ["iocs", "IOCs"], ["timeline", "Timeline"],
  ["evidence", "Evidence"], ["memory", "Memory"], ["audit", "Audit"], ["roe", "ROE"], ["report", "Report"]];
function renderTabs() {
  const nav = clear($("tabs"));
  for (const [id, label] of TABS) {
    const b = el("button", { type: "button", class: S.tab === id ? "active" : "",
      onclick: () => { S.tab = id; history.replaceState(null, "", "#" + id); renderTabs(); renderPanel(); } }, label);
    const c = S.state && S.state.case;
    const count = id === "approvals" ? S.pending.size : c ? ({ findings: c.findings.length, iocs: c.iocs.length,
      timeline: c.timeline.length, evidence: c.evidence.length })[id] : 0;
    if (id === "approvals" && count) b.append(el("span", { class: "badge", text: count }));
    else if (count) b.append(el("span", { class: "muted", text: " " + count }));
    nav.append(b);
  }
}
async function renderPanel() {
  const p = clear($("panel"));
  if (!S.state) return;
  const c = S.state.case;
  try {
    switch (S.tab) {
      case "approvals": return renderApprovals(p);
      case "findings": return renderFindings(p, c.findings);
      case "iocs": return table(p, ["ID", "Type", "Value", "Conf.", "Context"], c.iocs.map((i) =>
        [i.id, i.type, el("span", { class: "mono", text: i.value }), i.confidence, i.context]));
      case "timeline": return table(p, ["Time (UTC)", "Host", "Event", "ATT&CK"], c.timeline.map((e) =>
        [e.event_time, e.host, e.description, e.attack_technique]));
      case "evidence": return table(p, ["ID", "Path", "SHA-256", "Description"], c.evidence.map((e) =>
        [e.id, el("span", { class: "mono", text: e.path }), el("span", { class: "mono", text: e.hashes.sha256 }), e.description]));
      case "memory": return renderMemory(p);
      case "audit": return renderAudit(p);
      case "roe": return renderRoe(p);
      case "report": return renderReport(p);
    }
  } catch (e) { p.append(el("div", { class: "empty", text: "error: " + e.message })); }
}
function table(p, cols, rows) {
  if (!rows.length) return p.append(el("div", { class: "empty", text: "nothing recorded yet" }));
  p.append(el("table", { class: "grid" }, el("tr", {}, cols.map((c) => el("th", { text: c }))),
    rows.map((r) => el("tr", {}, r.map((v) => el("td", {}, v instanceof Node ? v : String(v ?? "")))))));
}
function renderApprovals(p) {
  if (!S.pending.size) return p.append(el("div", { class: "empty", text: "No actions awaiting approval." }));
  for (const a of S.pending.values()) {
    const prot = /PROTECTED/.test(a.why);
    const note = el("input", { placeholder: "note / reason (recorded in audit, feeds learning)" });
    const approve = el("button", { type: "button", class: "ok", text: "Approve" });
    let armed = false;
    approve.addEventListener("click", async () => {
      if (!armed) { armed = true; approve.textContent = "Confirm approve"; setTimeout(() => { armed = false; approve.textContent = "Approve"; }, 4000); return; }
      await decide(a.id, true, note.value);
    });
    p.append(el("div", { class: "approval" + (prot ? " protected" : "") },
      el("div", { class: "why", text: a.why }),
      el("div", { class: "tool", text: a.tool }),
      el("pre", { text: JSON.stringify(a.arguments, null, 2) }),
      a.rationale ? el("div", { class: "rationale" }, md(a.rationale)) : el("div", { class: "muted small", text: "(no rationale given)" }),
      note,
      el("div", { class: "row" }, approve,
        el("button", { type: "button", class: "danger", text: "Deny", onclick: () => decide(a.id, false, note.value) }),
        el("span", { class: "muted small", text: "requested " + fmtTime(a.requested) }))));
  }
}
async function decide(id, approve, note) {
  try { await api("/api/approvals/" + encodeURIComponent(id), { approve, note }); }
  catch (e) { toast(e.message, true); }
}
function renderFindings(p, findings) {
  if (!findings.length) return p.append(el("div", { class: "empty", text: "No findings yet." }));
  const sorted = [...findings].sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
  for (const f of sorted) {
    const note = el("input", { placeholder: "verdict note", class: "small" });
    const vb = (v, label, cls) => el("button", { type: "button", class: "small " + (cls || ""), text: label,
      onclick: async () => { try { await api("/api/verdict", { finding_id: f.id, verdict: v, note: note.value }); toast(`${f.id} → ${label}`); } catch (e) { toast(e.message, true); } } });
    p.append(el("div", { class: "finding" },
      el("div", { class: "head" }, el("span", { class: "sev " + f.severity, text: f.severity }), el("strong", { text: f.id }),
        el("span", { text: f.title }), el("span", { class: "verdict " + f.verdict, text: "verdict: " + f.verdict })),
      el("div", { class: "small muted", text: `confidence ${f.confidence} · ATT&CK ${f.attack_techniques.join(", ") || "n/a"} · assets ${f.affected_assets.join(", ") || "n/a"}` }),
      el("details", {}, el("summary", { class: "small", text: "details" }), md(f.description),
        f.recommended_actions.length ? el("ul", {}, f.recommended_actions.map((a) => el("li", { text: a }))) : null),
      el("div", { class: "row" }, vb("tp", "True positive", "danger"), vb("fp", "False positive", "ok"), vb("benign", "Benign"),
        vb("inconclusive", "Inconclusive")), note));
  }
}
async function renderMemory(p) {
  const status = el("select", { onchange: (e) => { S.memStatus = e.target.value; renderPanel(); } },
    ["candidate", "approved", "rejected", "retired", ""].map((s) => el("option", { value: s, selected: s === S.memStatus, text: s || "all" })));
  p.append(el("div", { class: "row" }, el("span", { class: "small muted", text: "status" }), status));
  const kind = el("select", {}, S.state.memory_kinds.map((k) => el("option", { value: k, text: k })));
  const title = el("input", { placeholder: "title" }); const content = el("textarea", { rows: 3, placeholder: "knowledge to remember" });
  p.append(el("details", {}, el("summary", { class: "small", text: "+ add analyst knowledge (approved immediately)" }),
    el("div", { class: "row" }, kind, title), content,
    el("button", { type: "button", text: "Save", onclick: async () => {
      try { await api("/api/remember", { kind: kind.value, title: title.value, content: content.value }); title.value = content.value = ""; renderPanel(); toast("saved"); }
      catch (e) { toast(e.message, true); } } })));
  const rows = await api("/api/memory?status=" + encodeURIComponent(S.memStatus));
  if (!rows.length) return p.append(el("div", { class: "empty", text: "nothing here" }));
  for (const m of rows) {
    const act = (a) => el("button", { type: "button", class: "small" + (a === "promote" ? " ok" : a === "reject" ? " danger" : ""), text: a,
      onclick: async () => { try { await api("/api/memory/" + m.id, { action: a }); renderPanel(); } catch (e) { toast(e.message, true); } } });
    p.append(el("div", { class: "mem" },
      el("div", {}, el("span", { class: "title", text: `M${m.id} ` + m.title })),
      el("div", { class: "small muted", text: `${m.kind} · ${m.status} · from ${m.source}${m.case_id ? " / " + m.case_id : ""} · +${m.helpful}/−${m.unhelpful} · used ${m.uses}` }),
      el("div", { class: "content", text: m.content }),
      el("div", { class: "row" }, m.status !== "approved" ? act("promote") : null, m.status !== "rejected" ? act("reject") : null,
        m.status === "approved" ? act("retire") : null)));
  }
}
async function renderAudit(p) {
  const a = await api("/api/audit?limit=300");
  p.append(el("div", { class: a.verified ? "verified" : "broken", text: (a.verified ? "✓ " : "✗ ") + a.message }));
  table(p, ["Time", "Event", "Detail"], a.records.map((r) => {
    const d = r.data || {};
    const detail = d.tool ? `${d.agent || ""} ${d.tool} ${d.tier ? "[" + d.tier + "]" : ""} ${d.allowed === false ? "DENIED " + (d.reason || "") : ""}`
      : JSON.stringify(d).slice(0, 220);
    return [r.ts.slice(11, 19), r.event, detail];
  }));
}
async function renderRoe(p) {
  const rows = await api("/api/tools");
  const filter = el("input", { placeholder: "filter tools…", value: S.roeFilter, oninput: (e) => { S.roeFilter = e.target.value; draw(); } });
  const holder = el("div"); p.append(filter, holder);
  function draw() {
    clear(holder);
    const f = S.roeFilter.toLowerCase();
    table(holder, ["Tier", "Tool", "Rule"], rows.filter((r) => !f || r.name.toLowerCase().includes(f))
      .map((r) => [el("span", { class: "tier " + r.tier, text: r.tier }), el("span", { class: "mono", text: r.name, title: r.description }), r.why]));
  }
  draw();
}
async function renderReport(p) {
  const text = await api("/api/report");
  p.append(el("div", { class: "row" }, el("button", { type: "button", text: "Ask reporter to (re)write report",
    onclick: () => send("Task the reporter expert to write the incident report from the case record now.") })));
  p.append(text ? md(text) : el("div", { class: "empty", text: "No report yet." }));
}

// ---------------------------------------------------------------- actions
async function send(text, playbook) {
  try { await api("/api/message", { text, playbook: playbook || "" }); }
  catch (e) { toast(e.message, true); }
}
function wire() {
  $("composer").addEventListener("submit", async (e) => {
    e.preventDefault();
    const t = $("input").value.trim(); const pb = $("playbook-select").value;
    if (!t && !pb) return;
    await send(t, pb); $("input").value = ""; $("playbook-select").value = "";
  });
  $("input").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) $("composer").requestSubmit(); });
  $("stop-btn").addEventListener("click", async () => { try { await api("/api/stop", {}); } catch (e) { toast(e.message, true); } });
  $("retro-btn").addEventListener("click", async () => { try { await api("/api/retro", {}); } catch (e) { toast(e.message, true); } });
  $("rate-btn").addEventListener("click", async () => {
    const r = $("rate-select").value; if (!r) return toast("pick a rating", true);
    try { await api("/api/rate", { rating: Number(r), note: $("rate-note").value }); toast("session rated " + r); $("rate-note").value = ""; }
    catch (e) { toast(e.message, true); }
  });
  $("model-select").addEventListener("change", async (e) => {
    try { await api("/api/model", { name: e.target.value }); toast("lead model: " + e.target.value); }
    catch (err) { toast(err.message, true); refreshState(); }
  });
}

(async function main() {
  const h = location.hash.slice(1);
  if (TABS.some(([id]) => id === h)) S.tab = h;
  wire();
  try {
    const hist = await api("/api/events/poll?after=0");   // replay this session's history
    await refreshState();
    S.replaying = true;
    for (const ev of hist) onEvent(ev);
    S.replaying = false;
  } catch (e) { toast("cannot load: " + e.message, true); return; }
  connect();
})();
