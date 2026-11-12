// Compensated Anarchist dashboard - single-page app, no dependencies, works air-gapped.
// SECURITY: agent output, tool output, logs and case data are attacker-influenced. Everything below is built
// with DOM APIs and textContent - never innerHTML - so nothing in that data can execute or inject markup.
// Inline style attributes are blocked by the CSP; dynamic styling goes through CSSOM (element.style).
"use strict";

/* ================================================================ utilities */
const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k === "css") Object.assign(n.style, v);
      else if (k === "value") n.value = v;
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const c of kids.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function svgEl(tag, attrs) { const n = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v)); return n; }

const ICONS = {
  plus: [["path", { d: "M12 5v14" }], ["path", { d: "M5 12h14" }]],
  search: [["circle", { cx: 11, cy: 11, r: 6.5 }], ["path", { d: "m16 16 4 4" }]],
  chevR: [["path", { d: "m9 6 6 6-6 6" }]],
  chevL: [["path", { d: "m15 6-6 6 6 6" }]],
  chevD: [["path", { d: "m6 9 6 6 6-6" }]],
  chevU: [["path", { d: "m6 15 6-6 6 6" }]],
  panel: [["rect", { x: 3, y: 4, width: 18, height: 16, rx: 2 }], ["path", { d: "M15 4v16" }]],
  more: [["path", { d: "M6 12h.01" }], ["path", { d: "M12 12h.01" }], ["path", { d: "M18 12h.01" }]],
  shield: [["path", { d: "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" }]],
  check: [["path", { d: "m5 12.5 4.5 4.5L19 7.5" }]],
  x: [["path", { d: "M6 6l12 12" }], ["path", { d: "M18 6 6 18" }]],
  up: [["path", { d: "M12 19V5" }], ["path", { d: "m6 11 6-6 6 6" }]],
  stop: [["rect", { x: 7, y: 7, width: 10, height: 10, rx: 1.5 }]],
  book: [["path", { d: "M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5z" }], ["path", { d: "M5 19.5A1.5 1.5 0 0 0 6.5 21H19" }]],
  db: [["ellipse", { cx: 12, cy: 6, rx: 7, ry: 2.8 }], ["path", { d: "M5 6v12c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8V6" }], ["path", { d: "M5 12c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8" }]],
  file: [["path", { d: "M7 3h7l5 5v13H7z" }], ["path", { d: "M14 3v5h5" }], ["path", { d: "M10 13h6" }], ["path", { d: "M10 17h6" }]],
  plug: [["path", { d: "M9 3v5" }], ["path", { d: "M15 3v5" }], ["path", { d: "M6 8h12v3a6 6 0 0 1-12 0z" }], ["path", { d: "M12 17v4" }]],
  sliders: [["path", { d: "M4 7h10" }], ["path", { d: "M18 7h2" }], ["path", { d: "M16 5v4" }], ["path", { d: "M4 17h4" }], ["path", { d: "M12 17h8" }], ["path", { d: "M10 15v4" }]],
  chat: [["path", { d: "M4 5h16v11H9l-5 4z" }]],
  steer: [["path", { d: "M4 5h16v11H9l-5 4z" }], ["path", { d: "M12 8v5" }], ["path", { d: "M9.5 10.5h5" }]],
  users: [["circle", { cx: 9, cy: 8, r: 3.2 }], ["path", { d: "M3.5 19a5.5 5.5 0 0 1 11 0" }], ["path", { d: "M16 5.2a3.2 3.2 0 0 1 0 5.6" }], ["path", { d: "M17.5 14.3A5.5 5.5 0 0 1 20.5 19" }]],
  flag: [["path", { d: "M5 21V4" }], ["path", { d: "M5 4h11l-2 4 2 4H5" }]],
  copy: [["rect", { x: 9, y: 9, width: 11, height: 11, rx: 2 }], ["path", { d: "M5 15V5a2 2 0 0 1 2-2h8" }]],
  refresh: [["path", { d: "M20 11a8 8 0 1 0-2.3 5.7" }], ["path", { d: "M20 4v7h-7" }]],
  list: [["path", { d: "M9 6h11" }], ["path", { d: "M9 12h11" }], ["path", { d: "M9 18h11" }], ["path", { d: "M4.5 6h.01" }], ["path", { d: "M4.5 12h.01" }], ["path", { d: "M4.5 18h.01" }]],
  terminal: [["rect", { x: 3, y: 4, width: 18, height: 16, rx: 2 }], ["path", { d: "m7 9 3 3-3 3" }], ["path", { d: "M12 15h5" }]],
  monitor: [["rect", { x: 3, y: 4, width: 18, height: 12, rx: 2 }], ["path", { d: "M8 20h8" }], ["path", { d: "M12 16v4" }]],
  globe: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M3 12h18" }], ["path", { d: "M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z" }]],
  box: [["path", { d: "M4 7.5 12 3l8 4.5v9L12 21l-8-4.5z" }], ["path", { d: "M4 7.5 12 12l8-4.5" }], ["path", { d: "M12 12v9" }]],
  alert: [["path", { d: "M12 4 21 20H3z" }], ["path", { d: "M12 10v4" }], ["path", { d: "M12 17.5v.01" }]],
  trash: [["path", { d: "M4 7h16" }], ["path", { d: "M9 7V4h6v3" }], ["path", { d: "M6 7l1 13h10l1-13" }]],
  edit: [["path", { d: "M4 20h4L19 9l-4-4L4 16z" }]],
  logout: [["path", { d: "M15 4h4v16h-4" }], ["path", { d: "M10 8l-4 4 4 4" }], ["path", { d: "M6 12h10" }]],
  menu: [["path", { d: "M4 7h16" }], ["path", { d: "M4 12h16" }], ["path", { d: "M4 17h16" }]],
  star: [["path", { d: "m12 4 2.5 5.2 5.5.8-4 3.9.9 5.6-4.9-2.7-4.9 2.7.9-5.6-4-3.9 5.5-.8z" }]],
  keyboard: [["rect", { x: 3, y: 6, width: 18, height: 12, rx: 2 }], ["path", { d: "M7 10h.01M11 10h.01M15 10h.01M7 14h10" }]],
  sun: [["circle", { cx: 12, cy: 12, r: 4 }], ["path", { d: "M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6 7 7M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4" }]],
  external: [["path", { d: "M14 4h6v6" }], ["path", { d: "M20 4l-9 9" }], ["path", { d: "M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" }]],
  clock: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M12 7v5l3 2" }]],
  download: [["path", { d: "M12 4v11" }], ["path", { d: "m7 10 5 5 5-5" }], ["path", { d: "M5 20h14" }]],
};
function icon(name, size = 16, sw = 1.8) {
  const s = svgEl("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    "stroke-width": name === "more" ? 2.6 : sw, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" });
  for (const [tag, a] of ICONS[name] || ICONS.box) s.append(svgEl(tag, a));
  return s;
}
const LOGO_POLYS = ["48,0.5 53.5,27 48,31 42.5,27", "52.21,29.6 30.07,87.82 21,99 21.65,84.62 43.79,26.4",
  "52.06,26.06 79.94,84.28 82,99 71.82,88.16 43.94,29.94", "1,77 17.21,74.7 85.81,46.7 99,37 82.79,39.3 14.19,67.3"];
function logo(size = 24, cls = "") {
  const s = svgEl("svg", { width: size, height: size, viewBox: "0 0 100 100", class: ("logo " + cls).trim(), "aria-hidden": "true", focusable: "false" });
  s.append(svgEl("circle", { cx: 49, cy: 57, r: 33, fill: "none", stroke: "currentColor", "stroke-width": 8.5 }));
  for (const p of LOGO_POLYS) s.append(svgEl("polygon", { points: p, fill: "currentColor" }));
  return s;
}

function pad2(n) { return String(n).padStart(2, "0"); }
function fmtClock(ts) { const d = new Date(ts * 1000); return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}Z`; }
function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec || 0));
  if (sec < 60) return `${sec} s`;
  if (sec < 3600) return `${Math.floor(sec / 60)} m ${pad2(sec % 60)} s`;
  return `${Math.floor(sec / 3600)} h ${pad2(Math.floor((sec % 3600) / 60))} m`;
}
function toEpoch(v) { return typeof v === "number" ? v : Date.parse(v) / 1000; }
function fmtRel(v) {
  const s = Date.now() / 1000 - toEpoch(v);
  if (!isFinite(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 14) return `${Math.floor(s / 86400)} d ago`;
  return new Date(toEpoch(v) * 1000).toISOString().slice(0, 10);
}
function fmtChars(n) { return n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} chars`; }
function plural(n, w) { return `${n} ${w}${n === 1 ? "" : "s"}`; }
function shortTitle(t) { return String(t || "").replace(/\s*\(.*\)\s*$/, ""); }
const ACRONYMS = /\b(cte|cti|dco|ioc|ttp)\b/gi;
function humanPb(p) { const s = String(p || "").replace(/_/g, " ").replace(ACRONYMS, (m) => m.toUpperCase()); return s.charAt(0).toUpperCase() + s.slice(1); }
function firstLine(s, n = 160) { const l = String(s || "").replace(/^#+\s*/gm, "").split("\n").find((x) => x.trim()) || ""; return l.length > n ? l.slice(0, n - 1) + "…" : l; }
function isTyping(t) { return t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable); }

function pref(k, d) { try { const v = localStorage.getItem("ca." + k); return v === null ? d : v; } catch (e) { return d; } }
function setPref(k, v) { try { localStorage.setItem("ca." + k, String(v)); } catch (e) { /* storage unavailable */ } }

function toast(msg, err) {
  const t = el("div", { class: "toast" + (err ? " err" : ""), role: err ? "alert" : "status", text: msg });
  $("toasts").append(t);
  setTimeout(() => t.remove(), err ? 7000 : 3200);
}
async function api(path, body) {
  const opts = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.method = "POST"; opts.body = JSON.stringify(body);
    opts.headers["Content-Type"] = "application/json"; opts.headers["X-CA-Request"] = "1";
  }
  const r = await fetch(path, opts);
  if (r.status === 401) { location.replace("/login"); throw new Error("signed out"); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || ("HTTP " + r.status));
  return data;
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); }
  catch (e) {
    const ta = el("textarea", { class: "sr-only", value: text }); document.body.append(ta); ta.select();
    try { document.execCommand("copy"); toast("Copied"); } catch (e2) { toast("Copy failed", true); }
    ta.remove();
  }
}

/* ---------------------------------------------------------------- safe markdown -> DOM */
function inline(text) {
  const frag = document.createDocumentFragment();
  const re = /(\[[^\[\]\n]{1,400}\](?!\()|\*\*[^*\n]+\*\*|`[^`\n]+`|\*[^*\s][^*\n]*\*|(?:[\w.~-]*\/)*(?:hunt_plan_|hunt_results_|attack_layer_|vuln_report_|cte_plan_|cte_results_|report_)[\w.-]+\.(?:md|json))/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) frag.append(document.createTextNode(text.slice(last, m.index)));
    const t = m[0];
    if (t.startsWith("[")) frag.append(citeNodes(t.slice(1, -1)) || el("span", {}, "[", inline(t.slice(1, -1)), "]"));
    else if (t.startsWith("**")) frag.append(el("strong", { text: t.slice(2, -2) }));
    else if (t.startsWith("`")) frag.append(fileRef(t.slice(1, -1)) || el("code", { text: t.slice(1, -1) }));
    else if (t.startsWith("*")) frag.append(el("em", { text: t.slice(1, -1) }));
    else frag.append(fileRef(t) || document.createTextNode(t));
    last = m.index + t.length;
  }
  if (last < text.length) frag.append(document.createTextNode(text.slice(last)));
  return frag;
}
function md(src) {
  const root = el("div", { class: "md" });
  const lines = String(src || "").replace(/\r/g, "").split("\n");
  let i = 0, list = null, para = [];
  const flushPara = () => { if (para.length) { root.append(el("p", {}, inline(para.join(" ")))); para = []; } };
  const flush = () => { flushPara(); list = null; };
  while (i < lines.length) {
    const ln = lines[i];
    if (/^\s*```/.test(ln)) {
      flush(); const buf = []; i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
      root.append(el("pre", { text: buf.join("\n") })); i++; continue;
    }
    const h = ln.match(/^(#{1,4})\s+(.*)$/);
    if (h) { flush(); root.append(el("h" + Math.min(h[1].length + 1, 4), {}, inline(h[2]))); i++; continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(ln)) { flush(); root.append(el("hr")); i++; continue; }
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
    if (/^\s*>\s?/.test(ln)) {
      flush(); const buf = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^\s*>\s?/, ""));
      root.append(el("blockquote", {}, inline(buf.join(" ")))); continue;
    }
    const li = ln.match(/^\s*([-*]|\d+\.)\s+(.*)$/);
    if (li) {
      flushPara();
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

/* ---------------------------------------------------------------- report citations: each cited source opens */
// Reports cite the mission data like [FIN-0001, EV-12] or [FILE:hunt_plan_x.md]; the same ids as the report writer.
const SOURCE_ID = /^(?:(?:FIN|IOC|TIM|EVI|NOT|STA)-\d{4,}|EV-\d+|CASE|NOW|FILE:[\w.\-]+)$/i;
const SOURCE_KIND = { finding: "Finding", ioc: "Indicator", timeline: "Timeline event", evidence: "Evidence", note: "Case note",
  statement: "Your answer to an agent", case: "Case record", date: "The report's date", file: "Case file",
  analyst_message: "Your message", subagent_report: "Subagent report", text: "Agent message", result: "Tool result" };
function citeNodes(inner) {
  const parts = inner.split(/([,;]\s*|\s+and\s+)/);
  if (!parts.some((x) => SOURCE_ID.test(x.trim()))) return null;
  const span = el("span", { class: "cites" }, "[");
  for (const x of parts) span.append(SOURCE_ID.test(x.trim()) ? citeRef(x.trim()) : document.createTextNode(x));
  span.append("]");
  return span;
}
function citeRef(id) {
  // a span, not a button: citations also sit inside clickable rows, and buttons cannot nest
  const n = el("span", { class: "cite", role: "button", tabindex: "0", title: `Show the cited source ${id}` }, id);
  const go = (e) => { e.preventDefault(); e.stopPropagation(); openSource(id); };
  n.addEventListener("click", go);
  n.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") go(e); });
  return n;
}
async function openSource(id) {
  let src;
  try { src = await api("/api/source/" + encodeURIComponent(id)); } catch (e) { toast(e.message, true); return; }
  const tab = { finding: "findings", ioc: "iocs", timeline: "timeline", evidence: "evidence" }[src.kind];
  const file = src.kind === "file" ? src.id.slice(5) : "";
  const dlg = openDialog({ title: src.id, sub: SOURCE_KIND[src.kind] || src.kind, iconName: "file", wide: true, cls: "source-view",
    body: [el("div", { class: "muted small", text: src.line }), el("pre", { class: "code source-text", text: src.text || "(empty)" })],
    foot: [el("span", { class: "note", text: "Mission data: what the report cites for this fact." }),
      tab ? el("button", { type: "button", class: "btn btn-sm", onclick: () => { dlg.close(); showInCase(tab, src.id); } }, icon("panel", 14), "Show in the case panel") : null,
      file && PLAN_FILE_RE.test(file) ? el("button", { type: "button", class: "btn btn-sm", onclick: () => { dlg.close(); viewPlan(file); } }, icon("file", 14), "Open the file") : null,
      el("button", { type: "button", class: "btn btn-sm", onclick: () => dlg.close() }, "Close")] });
}
function showInCase(tab, id) {
  if (S.view !== "ops") go("ops");
  S.insp.open = true; S.insp.thread = null; S.insp.tab = tab; setPref("insp", "1");
  renderInsp(); renderHeader();
  const n = [...$("insp").querySelectorAll("[data-ref]")].find((x) => x.dataset.ref === id);
  if (n) { n.scrollIntoView({ block: "center" }); n.classList.add("flash"); n.setAttribute("tabindex", "-1"); n.focus({ preventScroll: true }); setTimeout(() => n.classList.remove("flash"), 1700); }
}

function withCaret(root) {
  let host = root.lastElementChild || root;
  if (host.tagName === "UL" || host.tagName === "OL") host = host.lastElementChild || host;
  else if (host.tagName === "TABLE") host = host.querySelector("tr:last-child > :last-child") || host;
  else if (host.tagName === "HR") host = root;
  host.append(el("span", { class: "caret", "aria-hidden": "true" }));
  return root;
}
function tailLine(s, n = 140) {
  const lines = String(s || "").split("\n").map((x) => x.replace(/^#+\s*|^\s*([-*]|\d+\.)\s+/, "").trim()).filter(Boolean);
  const l = lines.length ? lines[lines.length - 1] : "";
  return l.length > n ? "…" + l.slice(l.length - n + 1) : l;
}

/* ================================================================ state */
const S = {
  st: null, convs: [], view: "ops", lastSeq: 0, es: null, connected: false,
  replaying: false, loading: false, buffer: [], feedStart: 0,
  pending: new Map(), approvalCards: new Map(),
  subs: new Map(), turns: [], turn: null, hero: null,
  insp: { open: pref("insp", "1") === "1", tab: "findings", thread: null },
  subframeOpen: null, playbook: "", running: false, runLabel: "", telemetry: null, audit: null,
  drafts: new Map(), dialogs: [], menu: null, ui: {},
  live: new Map(),        // agent_id -> { text, seq }: the reply being streamed right now
  stopArmed: new Map(),   // subagent id -> time until which "Confirm stop" stays armed (survives re-renders)
  announced: new Set(),   // approval ids already announced to screen readers
  steerDrafts: new Map(), // subagent id -> unsent guidance text
  clsDraft: null,         // unsaved edits to the classification banner on the Settings page
  plans: null,            // /api/plans: the case's hunt plans folder and how this browser can open its files
  wasConnected: false,
  skillsTab: "review", skillsSel: null, memStatus: "candidate", roeFilter: "",
};

const TOOL_LABELS = {
  memory_search: "Searched memory", memory_record: "Saved to memory", memory_feedback: "Rated a memory",
  case_add_ioc: "Recorded IOC", case_add_finding: "Recorded finding", case_add_timeline_event: "Added timeline event",
  case_register_evidence: "Registered evidence", case_summary: "Read the case", case_add_note: "Added a note",
  case_write_report: "Wrote the report", case_set_verdict: "Set a verdict",
  skill_view: "Loaded skill", skill_create: "Proposed a new skill", skill_update: "Proposed a skill revision",
  skill_feedback: "Scored a skill", skill_list: "Listed skills", subagent_list: "Checked subagents", submit_report: "Submitted report",
  vuln_environment: "Checked the assessment toolkit", vuln_run: "Ran an assessment tool", vuln_parse: "Parsed scan output",
  vuln_report_save: "Saved the vulnerability report",
  cte_network_map: "Read the network map", cte_plan_save: "Saved the CTE plan", cte_plan_check: "Checked the CTE plan",
  cte_plan_list: "Listed CTE plans", cte_plan_read: "Read a CTE plan", cte_plan_changes: "Read your edits to a CTE plan",
  cte_navigator_layer: "Saved an ATT&CK layer", cte_atomic_tests: "Looked up Atomic Red Team tests",
  report_examples: "Listed example reports", report_example_read: "Read an example report (format only)",
  report_sources: "Listed mission data", report_source: "Read mission data", report_verify: "Checked a draft",
  report_save: "Saved a report draft", report_finalize: "Saved the final report", report_list: "Listed reports",
  report_read: "Read a report", report_changes: "Read your edits to a report", case_analyst_statement: "Recorded your answer",
};
const SERVER_NAMES = { security_onion: "Security Onion", elastic: "Elastic", splunk: "Splunk", velociraptor: "Velociraptor",
  velociraptor_admin: "Velociraptor admin", misp: "MISP", opencti: "OpenCTI" };
const PB_DESC = {
  triage: "Work through open alerts across connected sensors",
  hunt: "Hypothesis-driven hunt for a technique or actor",
  incident_response: "Scope, contain and eradicate a confirmed incident",
  compromise_assessment: "Check hosts or a segment for signs of compromise",
  forensics: "Examine disk, memory or log evidence",
  hunt_plan: "Build an ATT&CK hunt plan for named threat actors, with queries for your tools",
  vulnerability_assessment: "Scan in-scope hosts for vulnerabilities and attack chains; every action needs your approval",
  cte_plan: "Plan a threat emulation to test detection: name the adversary and the network (plans only)",
  report: "Write a report from this mission's data only, in your format; asks you for anything missing",
  code: "Write a script, parser or VQL artifact: tested on a real sample, reviewed by a second code writer, never run",
};
function toolLabel(name) {
  if (TOOL_LABELS[name]) return TOOL_LABELS[name];
  const i = name.indexOf("__");
  if (i > 0) { const srv = name.slice(0, i); return `${SERVER_NAMES[srv] || srv} · ${name.slice(i + 2).replace(/_/g, " ")}`; }
  if (name.startsWith("local_")) return "Local · " + name.slice(6).replace(/_/g, " ");
  return name.replace(/_/g, " ");
}
function toolIcon(name) {
  if (name.startsWith("memory_")) return "db";
  if (name.startsWith("case_")) return "flag";
  if (name.startsWith("skill_")) return "book";
  if (name.startsWith("subagent_")) return "users";
  const srv = name.split("__")[0];
  if (srv.startsWith("velociraptor")) return "monitor";
  if (["security_onion", "elastic", "splunk"].includes(srv)) return "search";
  if (["misp", "opencti"].includes(srv)) return "globe";
  if (name.startsWith("local_") || name.startsWith("vuln_")) return "terminal";
  return "box";
}
const ARG_KEYS = ["query", "q", "search", "value", "values", "title", "name", "path", "client_id", "artifact", "expert", "task",
  "message", "hunt_id", "flow_id", "field", "community_id", "index", "kind", "description"];
function argSummary(args) {
  if (!args || typeof args !== "object") return "";
  for (const k of ARG_KEYS) {
    const v = args[k];
    if (v === undefined || v === null || v === "") continue;
    const s = Array.isArray(v) ? v.join(", ") : String(v);
    return firstLine(s, 160);
  }
  const s = Object.values(args).find((v) => typeof v === "string" && v);
  return s ? firstLine(s, 160) : "";
}
// vuln_run: the exact command line the analyst is approving
function commandOf(tool, args) {
  if (tool !== "vuln_run" || !args) return "";
  const q = (a) => /^[\w@%+=:,./-]+$/.test(a) ? a : "'" + String(a).replace(/'/g, "'\\''") + "'";
  return [args.tool, ...(Array.isArray(args.args) ? args.args : [])].map((a) => q(String(a))).join(" ");
}
function agentOf(why) { const m = /^\[([^\]]+)\]\s*/.exec(why || ""); return m ? m[1] : ""; }
function ruleOf(why) { return String(why || "").replace(/^\[[^\]]+\]\s*/, ""); }
function targetsOf(args) {
  const out = [];
  for (const k of ["client_id", "host", "hostname", "target", "targets", "ip", "hunt_id", "artifact"]) {
    if (args && args[k] !== undefined && args[k] !== "") out.push(`${k} ${Array.isArray(args[k]) ? args[k].join(", ") : args[k]}`);
  }
  return out.join(" · ");
}
function statusChip(status, secs) {
  const map = { completed: ["chip ok", "Done"], blocked: ["chip warn", "Blocked"], needs_input: ["chip warn", "Needs input"],
    failed: ["chip red", "Failed"], stopped: ["chip", "Stopped"], interrupted: ["chip warn", "Interrupted"], queued: ["chip", "Waiting for a slot"] };
  if (status === "running") return el("span", { class: "spin", role: "img", "aria-label": "Running", title: "Running" });
  const [cls, label] = map[status] || ["chip", status || "Idle"];
  return el("span", { class: cls, text: label + (secs ? ` · ${fmtDur(secs)}` : "") });
}
function tierChip(tier) { return tier && tier !== "auto" ? el("span", { class: "tier " + tier, text: tier }) : null; }

/* ================================================================ theme / banners */
function applyTheme(mode) {
  const resolved = mode === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : mode;
  document.documentElement.dataset.theme = resolved === "light" ? "light" : "dark";
  setPref("theme", mode);
}
function applyClassification(c) {
  for (const id of ["cls-top", "cls-bottom"]) {
    const b = $(id);
    if (!c || !c.text) { b.hidden = true; continue; }
    b.textContent = c.text; b.style.background = c.background; b.style.color = c.color; b.hidden = false;
  }
}

/* ================================================================ sidebar */
function navItem(view, ic, label, extra) {
  return el("a", { class: "navi" + (S.view === view ? " on" : ""), href: view === "ops" ? "#/" : "#/" + view, "aria-current": S.view === view ? "page" : null },
    icon(ic), label, extra || null);
}
function renderSide() { keepFocus($("side"), drawSide); }
function drawSide() {
  const st = S.st; if (!st) return;
  const side = clear($("side"));
  const top = el("div", { class: "side-top" },
    el("div", { class: "brand" }, logo(30), el("div", { class: "wordmark" }, el("span", { class: "w1", text: "Compensated" }), el("span", { class: "w2", text: "Anarchist" }))),
    el("button", { type: "button", class: "btn side-btn", title: "New conversation (Ctrl+Shift+O)", onclick: newConversation, disabled: S.running }, icon("plus"), "New conversation"),
    el("button", { type: "button", class: "btn btn-ghost side-btn", onclick: openPalette }, icon("search"), "Search or run a command", el("span", { class: "kbd", text: "Ctrl K" })));
  const scroll = el("div", { class: "side-scroll" });
  scroll.append(el("div", { class: "group-head" }, el("span", { text: st.case.id }), el("span", { text: st.case.status || "open" })));
  if (!st.conversation) {
    scroll.append(el("div", { class: "conv-wrap" }, el("div", { class: "conv on" },
      el("span", { class: "conv-title" }, el("span", { class: "dot red" }), el("span", { class: "ellipsis", text: "New conversation" })),
      el("span", { class: "conv-meta", text: "Saved when you send the first message" }))));
  }
  for (const c of S.convs) scroll.append(convRow(c));
  if (!S.convs.length && st.conversation) scroll.append(el("div", { class: "conv-meta", text: "No saved conversations" }));
  const cand = Object.entries(st.memory || {}).filter(([k]) => k.endsWith("/candidate")).reduce((a, [, v]) => a + v, 0);
  const up = Object.values(st.connectors || {}).filter((v) => String(v).startsWith("connected")).length;
  const total = Object.keys(st.connectors || {}).length;
  const nav = el("div", { class: "side-nav" },
    navItem("ops", "chat", "Operations", S.pending.size ? el("span", { class: "count red", css: { marginLeft: "auto" }, text: S.pending.size }) : null),
    navItem("skills", "book", "Skills", st.skills.pending_review ? el("span", { class: "count warn", css: { marginLeft: "auto" }, text: st.skills.pending_review }) : null),
    navItem("memory", "db", "Memory", cand ? el("span", { class: "count", css: { marginLeft: "auto" }, text: cand }) : null),
    navItem("audit", "file", "Audit log", S.audit ? el("span", { class: "end", css: { color: S.audit.verified ? "var(--ok)" : "var(--red-hi)" }, text: S.audit.verified ? "Verified" : "Broken" }) : null),
    navItem("roe", "shield", "Rules of engagement"),
    navItem("connectors", "plug", "Connectors", total ? el("span", { class: "end", text: `${up} / ${total}` }) : null),
    navItem("settings", "sliders", "Settings"));
  const initials = String(st.operator || "?").split(/[\s._-]+/).filter(Boolean).map((p) => p[0]).join("").slice(0, 2).toUpperCase();
  const user = el("div", { class: "user" },
    el("span", { class: "avatar-sm", "aria-hidden": "true", text: initials }),
    el("span", { css: { display: "flex", flexDirection: "column", lineHeight: "1.25", minWidth: "0", flex: "1" } },
      el("span", { class: "ellipsis", css: { fontSize: "13px", fontWeight: "500" }, text: st.operator }),
      el("span", { class: "muted", css: { fontSize: "12px" }, text: "Operator" })),
    el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", title: "Sign out", "aria-label": "Sign out", onclick: signOut }, icon("logout", 15)));
  side.append(top, scroll, nav, user);
}
function convRow(c) {
  const active = S.st.conversation && c.id === S.st.conversation.id;
  const live = active && S.running;
  const dot = live ? (S.pending.size ? "dot warn live" : "dot red live") : "dot";
  const meta = live ? (S.pending.size ? "Waiting on you" : "Running") : `${plural(c.events, "event")} · ${fmtRel(c.updated)}`;
  return el("div", { class: "conv-wrap" },
    el("button", { type: "button", class: "conv" + (active ? " on" : ""), "aria-current": active ? "true" : null, title: c.title || "Untitled",
      onclick: () => { if (!active) openConversation(c.id); $("side").classList.remove("open"); go("ops"); } },
      el("span", { class: "conv-title" }, el("span", { class: dot }), el("span", { class: "ellipsis", text: c.title || "Untitled" })),
      el("span", { class: "conv-meta", text: meta })),
    el("div", { class: "conv-actions" },
      el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", title: "Rename", "aria-label": "Rename conversation", onclick: () => renameDialog(c) }, icon("edit", 14)),
      el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", title: "Delete", "aria-label": "Delete conversation", onclick: () => deleteDialog(c) }, icon("trash", 14))));
}

/* ================================================================ operation view */
function buildOps() {
  const v = clear($("view-ops"));
  const ui = S.ui;
  ui.title = el("h1", { class: "ellipsis" });
  ui.sub = el("div", { class: "sub ellipsis" });
  ui.posture = el("span", { class: "posture" });
  ui.gate = el("span", { class: "posture gate", hidden: true }, icon("shield", 13), "APPROVE EVERYTHING");
  ui.inspBtn = el("button", { type: "button", class: "btn btn-ghost icon-btn", "aria-label": "Toggle case panel", title: "Case panel (Ctrl+.)", onclick: toggleInsp }, icon("panel"));
  const more = el("button", { type: "button", class: "btn btn-ghost icon-btn", "aria-label": "Conversation actions", title: "Conversation actions",
    onclick: (e) => openMenu(e.currentTarget, convMenuItems()) }, icon("more"));
  const menuBtn = el("button", { type: "button", class: "btn btn-ghost icon-btn menu-btn", "aria-label": "Open sidebar", onclick: () => $("side").classList.toggle("open") }, icon("menu"));
  const top = el("header", { class: "topbar" }, menuBtn, el("div", { class: "topbar-title" }, ui.title, ui.sub), ui.gate, ui.posture, ui.inspBtn, more);
  ui.resume = el("div", { class: "banner resume", role: "region", "aria-label": "Interrupted operation", hidden: true });
  ui.banner = el("div", { class: "banner", role: "region", "aria-label": "Approval needed", hidden: true });
  ui.feed = el("div", { class: "feed", role: "log", "aria-label": "Operation feed" });
  ui.jump = el("button", { type: "button", class: "btn jump", hidden: true, onclick: scrollBottom }, icon("chevD", 15), "Jump to latest");
  ui.feedScroll = el("div", { class: "feed-scroll", onscroll: onFeedScroll }, ui.feed, ui.jump);
  ui.subframe = el("div", { class: "subframe", hidden: true });
  ui.input = el("textarea", { id: "composer", rows: 1, placeholder: "Task the lead…", "aria-label": "Message the lead", oninput: onComposerInput, onkeydown: onComposerKey });
  ui.pbPill = el("div", { class: "pb-pill", hidden: true });
  ui.pbBtn = el("button", { type: "button", class: "btn btn-ghost btn-sm", onclick: (e) => openMenu(e.currentTarget, playbookMenu()) }, icon("list", 15), "Playbook");
  ui.modelBtn = el("button", { type: "button", class: "btn btn-ghost btn-sm", title: "Model for the lead (config/models.yaml)", onclick: (e) => openModelMenu(e.currentTarget) });
  ui.sendBtn = el("button", { type: "submit", class: "btn btn-primary icon-btn", "aria-label": "Send", title: "Send" }, icon("up", 16, 2));
  const form = el("form", { class: "composer", onsubmit: (e) => { e.preventDefault(); sendOrStop(); } },
    ui.pbPill, ui.input,
    el("div", { class: "composer-bar" }, ui.pbBtn, ui.modelBtn, el("span", { class: "hint", text: "Enter to send · Shift+Enter for a new line" }), ui.sendBtn));
  ui.status = el("div", { class: "statusbar" });
  const dock = el("div", { class: "dock" }, el("div", { class: "dock-inner" }, ui.subframe, form, ui.status));
  v.append(top, ui.resume, ui.banner, ui.feedScroll, dock);
}
function renderHeader() {
  const st = S.st; if (!st) return;
  const c = st.conversation;
  S.ui.title.textContent = c ? (c.title || "Untitled") : "New conversation";
  const n = [...S.subs.values()].filter((s) => s.expert).length;
  S.ui.sub.textContent = `${st.case.id} · lead on ${modelLabel(st.model)}${n ? " · " + plural(n, "subagent") : ""}`;
  const respond = st.posture === "respond";
  clear(S.ui.posture).append(el("span", { class: "dot" + (respond ? " red" : "") }), respond ? "RESPOND" : "OBSERVE");
  S.ui.posture.className = "posture" + (respond ? " respond" : "");
  S.ui.posture.title = (respond ? "Response actions are possible (each still passes ROE and approval)" : "Observe only: response actions are denied") + ". Change it in Settings.";
  S.ui.gate.hidden = !st.gated;
  S.ui.gate.title = st.gated ? `${st.gated}. Start a new conversation to leave approval mode.` : "";
  S.ui.inspBtn.classList.toggle("on", S.insp.open);
  S.ui.inspBtn.setAttribute("aria-pressed", String(S.insp.open));
  document.title = (S.pending.size ? `(${S.pending.size}) Approval needed · ` : "") + (c ? c.title + " · " : "") + "Compensated Anarchist";
}
// Redrawn every second for its clock: the text changes in place, the Review button is never replaced (a keyboard
// user may be on it).
function renderBanner() {
  const b = S.ui.banner;
  if (!S.pending.size) { b.hidden = true; return; }
  const p = S.pending.values().next().value;
  if (!S.ui.bannerTxt) {
    S.ui.bannerTxt = el("div", { class: "txt" });
    b.append(icon("shield", 18), S.ui.bannerTxt, el("button", { type: "button", class: "btn btn-primary", onclick: () => openApproval(S.bannerId) }, "Review"));
  }
  S.bannerId = p.id;
  const tgt = targetsOf(p.arguments);
  const who = agentOf(p.why);
  const when = p.restored ? "before the dashboard restarted" : fmtRel(p.requested);
  clear(S.ui.bannerTxt).append(el("strong", { text: "Approval needed: " }), `${toolLabel(p.tool)}${tgt ? " · " + tgt : ""}`,
    el("span", { class: "muted", text: ` · requested by ${who || "an agent"} ${when}${S.pending.size > 1 ? ` · ${S.pending.size - 1} more waiting` : ""}` }));
  b.hidden = false;
  announce(p);
}
// Panels are redrawn from state; put keyboard focus back on the same control afterwards (matched by id, else by
// its role, label and text), so redraws never drop a keyboard or screen-reader user back to the page.
const FOCUSABLE = "button, a[href], input, textarea, select, [tabindex]";
function focusKey(n) {
  return n.id ? "#" + n.id : [n.tagName, n.getAttribute("role") || "", n.getAttribute("aria-label") || "", (n.textContent || "").trim().slice(0, 80), n.getAttribute("href") || ""].join("|");
}
function captureFocus(box) {
  const ae = document.activeElement;
  if (!ae || ae === document.body || !box.contains(ae)) return null;
  return { el: ae, key: focusKey(ae), sel: typeof ae.selectionStart === "number" ? [ae.selectionStart, ae.selectionEnd] : null };
}
function restoreFocus(box, f) {
  if (!f || (f.el.isConnected && box.contains(f.el))) return;
  const n = [...box.querySelectorAll(FOCUSABLE)].find((x) => focusKey(x) === f.key);
  if (!n) return;
  n.focus({ preventScroll: true });
  if (f.sel) try { n.setSelectionRange(f.sel[0], f.sel[1]); } catch (e) { /* not a text field */ }
}
function keepFocus(box, fn) { const f = captureFocus(box); fn(); restoreFocus(box, f); }
// One spoken announcement per new approval (the banner itself is redrawn every second for its clock).
function announce(p) {
  if (!p || S.announced.has(p.id)) return;
  S.announced.add(p.id);
  const tgt = targetsOf(p.arguments);
  $("announcer").textContent = `Approval needed: ${toolLabel(p.tool)}${tgt ? ", " + tgt : ""}, requested by ${agentOf(p.why) || "an agent"}.`;
}
// An operation cut off by a dashboard restart: resume it from where each agent stopped, or end it.
function renderResume() { keepFocus(S.ui.resume, drawResume); }
function drawResume() {
  const b = S.ui.resume; const op = S.st && S.st.interrupted;
  if (!op || S.running) { b.hidden = true; return; }
  const what = op.label && op.label !== "mission" ? `The ${humanPb(op.label)} operation` : "The operation";
  const how = op.waiting ? `It was waiting for your approval (${plural(op.waiting, "request")} below). Deciding it carries the operation on.`
    : op.resumable ? "Resume carries each agent on from where it stopped; tool calls that had no result are checked against the ROE again."
      : "An after-action review cannot be resumed. End it, then run it again.";
  clear(b).append(icon("clock", 18),
    el("div", { class: "txt" }, el("strong", { text: "Interrupted by a restart: " }), `${what} started ${fmtRel(op.started)} did not finish. `,
      el("span", { class: "muted", text: how })),
    op.resumable ? el("button", { type: "button", class: "btn btn-primary", onclick: resumeOp }, "Resume") : null,
    el("button", { type: "button", class: "btn", onclick: endOpDialog }, "End it"));
  b.hidden = false;
}
async function resumeOp() { try { await api("/api/operation/resume", {}); } catch (e) { toast(e.message, true); } }
function endOpDialog() {
  const dlg = openDialog({ title: "End the interrupted operation?", iconName: "stop",
    body: [el("p", { css: { margin: "0" }, text: "Tool calls that had no result are closed as not executed, and approvals it was waiting for expire. Everything found so far stays in the case and the conversation." })],
    foot: [el("span", { class: "note", text: "Recorded in the audit log." }), el("button", { type: "button", class: "btn", onclick: () => dlg.close() }, "Cancel"),
      el("button", { type: "button", class: "btn btn-primary", onclick: async () => {
        try { await api("/api/operation/end", {}); dlg.close(); toast("Ended the interrupted operation"); scheduleRefresh(); } catch (e) { toast(e.message, true); }
      } }, "End it")] });
}
function renderStatus() {
  const s = clear(S.ui.status); const st = S.st; if (!st) return;
  if (!S.connected) s.append(el("span", { class: "bad" }, el("span", { class: "dot red live" }), "Reconnecting…"));
  if (S.running) s.append(el("span", {}, el("span", { class: "spin" }), S.runLabel && S.runLabel !== "mission" ? `Running: ${humanPb(S.runLabel)}` : "Running"));
  const t = S.telemetry;
  if (t && t.context_pct !== undefined && t.context_pct !== null) {
    const bar = el("span", { class: "meter" + (t.context_pct >= 75 ? " hot" : "") }, el("span", { css: { width: Math.min(100, t.context_pct) + "%" } }));
    s.append(el("span", { title: "Share of the lead's context window in use" }, `Context ${t.context_pct}%`, bar));
  }
  if (t && t.tok_s) s.append(el("span", { title: t.ttft ? `Last reply: first token after ${t.ttft} s` : "Output speed of the last reply", text: `${t.tok_s} tok/s` }));
  const up = Object.values(st.connectors || {}).filter((v) => String(v).startsWith("connected")).length;
  const total = Object.keys(st.connectors || {}).length;
  if (total) s.append(el("span", { class: up < total ? "bad" : "", text: `Connectors ${up}/${total}` }));
  s.append(el("span", { class: S.pending.size ? "bad" : "", text: S.pending.size ? `${plural(S.pending.size, "approval")} waiting` : "No approvals waiting" }));
  if (S.audit) s.append(el("span", { class: S.audit.verified ? "good" : "bad", text: S.audit.verified ? "Audit chain verified" : "Audit chain broken" }));
}
function renderComposerState() {
  const st = S.st; if (!st) return;
  clear(S.ui.modelBtn).append(el("span", { class: "dot ok" }), modelLabel(st.model), icon("chevD", 14));
  S.ui.modelBtn.disabled = S.running;
  const btn = clear(S.ui.sendBtn);
  if (S.running) { btn.append(icon("stop", 15, 2.2)); btn.setAttribute("aria-label", "Stop the operation"); btn.title = "Stop the operation"; }
  else { btn.append(icon("up", 16, 2)); btn.setAttribute("aria-label", "Send"); btn.title = "Send"; }
  S.ui.input.placeholder = S.running ? "The lead is working. Stop it, or wait for its report."
    : st.interrupted ? "Resume or end the interrupted operation above, or send a new task (that ends it)" : "Task the lead…";
  if (S.playbook) {
    clear(S.ui.pbPill).append(icon("list", 13), `Playbook: ${humanPb(S.playbook)}`,
      el("button", { type: "button", "aria-label": "Remove playbook", onclick: () => setPlaybook("") }, icon("x", 13, 2)));
    S.ui.pbPill.hidden = false;
  } else S.ui.pbPill.hidden = true;
}
function setPlaybook(p) { S.playbook = p; renderComposerState(); S.ui.input.focus(); }
function onComposerInput() {
  const ta = S.ui.input; ta.style.height = "auto"; ta.style.height = Math.min(240, ta.scrollHeight) + "px";
  if (S.st && S.st.conversation) S.drafts.set(S.st.conversation.id, ta.value);
}
function onComposerKey(e) { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendOrStop(); } }
async function sendOrStop() {
  if (S.running) { try { await api("/api/stop", {}); } catch (e) { toast(e.message, true); } return; }
  const text = S.ui.input.value.trim();
  if (!text && !S.playbook) { S.ui.input.focus(); return; }
  await send(text, S.playbook);
}
async function send(text, playbook) {
  try {
    await api("/api/message", { text, playbook: playbook || "" });
    S.ui.input.value = ""; onComposerInput(); S.playbook = ""; renderComposerState();
    if (S.st && S.st.conversation) S.drafts.delete(S.st.conversation.id);
  } catch (e) { toast(e.message, true); }
}

/* ---------------------------------------------------------------- feed */
function mutate(fn) {
  if (S.replaying) { fn(); return; }
  const sc = S.ui.feedScroll;
  const near = sc.scrollHeight - sc.scrollTop - sc.clientHeight < 160;
  fn();
  if (near) sc.scrollTop = sc.scrollHeight; else S.ui.jump.hidden = false;
}
function onFeedScroll() { const sc = S.ui.feedScroll; if (sc.scrollHeight - sc.scrollTop - sc.clientHeight < 40) S.ui.jump.hidden = true; }
function scrollBottom() { const sc = S.ui.feedScroll; sc.scrollTop = sc.scrollHeight; S.ui.jump.hidden = true; }
function resetFeed() {
  clear(S.ui.feed); S.turns = []; S.turn = null; S.hero = null; S.subs.clear(); S.approvalCards.clear(); S.insp.thread = null;
  S.live.clear(); S.feedStart = 0;
}
// Long conversations: only the newest FEED_KEEP turns stay in the page. Older ones are detached (kept in memory, still
// updated) and come back, a batch at a time, when you scroll up to them or press "Show earlier".
const FEED_KEEP = 40, FEED_SLACK = 20, FEED_BATCH = 20;
function trimFeed() {
  if (S.turns.length - S.feedStart <= FEED_KEEP + FEED_SLACK) return;
  if (!S.replaying) { const sc = S.ui.feedScroll; if (sc.scrollHeight - sc.scrollTop - sc.clientHeight > 400) return; } // reading back
  const upTo = S.turns.length - FEED_KEEP;
  for (let i = S.feedStart; i < upTo; i++) S.turns[i].root.remove();
  S.feedStart = upTo;
  syncMore();
}
function syncMore() {
  if (!S.ui.more) {
    S.ui.more = el("button", { type: "button", class: "btn btn-sm feed-more", onclick: () => showEarlier(FEED_BATCH) });
    if ("IntersectionObserver" in window) {
      S.moreObserver = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) showEarlier(FEED_BATCH); },
        { root: S.ui.feedScroll, rootMargin: "300px 0px 0px 0px" });
    }
  }
  const b = S.ui.more, n = S.feedStart;
  if (!n) { b.remove(); if (S.moreObserver) S.moreObserver.unobserve(b); return; }
  b.textContent = `Show earlier turns (${n} more)`;
  if (!b.isConnected) { S.ui.feed.prepend(b); if (S.moreObserver) S.moreObserver.observe(b); }
}
function showEarlier(n) {
  if (!S.feedStart) return;
  const sc = S.ui.feedScroll, before = sc.scrollHeight;
  const from = Math.max(0, S.feedStart - n);
  const frag = document.createDocumentFragment();
  for (let i = from; i < S.feedStart; i++) frag.append(S.turns[i].root);
  S.turns[S.feedStart].root.before(frag);
  S.feedStart = from;
  syncMore();
  sc.scrollTop += sc.scrollHeight - before; // keep what you were reading where it was
}
function showHero() {
  if (S.hero || S.turns.length || !S.st) return;
  const pbs = (S.st.playbooks || []).map((p) => el("button", { type: "button", class: "pb-card", onclick: () => setPlaybook(p) },
    el("strong", { text: humanPb(p) }), el("span", { text: PB_DESC[p] || "Run this playbook" })));
  S.hero = el("div", { class: "hero" }, logo(76, "mark"), el("h2", { text: "What are we defending today?" }),
    el("p", { text: "Describe the alert, hunt or incident in plain language. The lead plans the work, tasks expert subagents and asks you before any response action." }),
    el("div", { class: "pb-grid" }, pbs));
  S.ui.feed.append(S.hero);
}
function newTurn(kind, data, ts) {
  if (S.hero) { S.hero.remove(); S.hero = null; }
  if (S.turn && S.turn.running) finishTurn(S.turn, ts, null, true);
  const t = { kind, started: ts, ended: null, running: true, steps: 0, tools: 0, subs: new Set(), toggled: false, open: true,
    pending: new Map(), approvals: new Map(), cardEls: new Map(), endKey: "", text: data ? data.text : "", playbook: data ? data.playbook : "" };
  t.root = el("section", { class: "turn" });
  if (kind === "analyst") {
    const who = S.st ? S.st.operator : "You";
    t.root.append(el("div", { class: "bubble-row" },
      el("div", { class: "bubble", text: data.text || `Run the ${humanPb(data.playbook)} playbook` }),
      el("div", { class: "bubble-meta", title: new Date(ts * 1000).toISOString(), text: `${who}${data.playbook ? " · playbook " + humanPb(data.playbook) : ""} · ${fmtClock(ts)}` })));
  } else if (kind === "retro") {
    t.root.append(el("div", { class: "turn-label" }, icon("refresh", 14), "After-action review"));
  } else if (kind === "resume") {
    t.root.append(el("div", { class: "turn-label" }, icon("refresh", 14), `Resumed the interrupted operation${data && data.label && data.label !== "mission" ? " · " + humanPb(data.label) : ""}`));
  }
  t.workChev = el("span", { class: "chev" }, icon("chevR", 14));
  t.workWhat = el("span", { class: "what" });
  t.workDetail = el("span", { class: "detail" });
  t.workEnd = el("span", { class: "end" });
  t.workHead = el("button", { type: "button", class: "step work-head open", "aria-expanded": "true", onclick: () => { t.toggled = true; setWorkOpen(t, !t.open); } },
    t.workChev, t.workWhat, t.workDetail, t.workEnd);
  t.workList = el("div", { class: "work-list" });
  t.work = el("div", { class: "work", hidden: true }, t.workHead, t.workList);
  t.answer = el("div", { class: "answer" });
  t.cards = el("div", { class: "cards" });
  t.extras = el("div", { class: "extras" });
  t.lead = el("div", { class: "lead", hidden: true },
    el("div", { class: "avatar" }, logo(18)),
    el("div", { class: "lead-body" },
      el("div", { class: "who" }, el("strong", { text: "Lead" }), el("span", { class: "muted", text: ` · orchestrator · ${fmtClock(ts)}` })),
      t.work, t.answer, t.cards, t.extras));
  t.root.append(t.lead);
  mutate(() => S.ui.feed.append(t.root));
  S.turns.push(t); S.turn = t;
  updateWorkHead(t);
  trimFeed();
  return t;
}
function ensureTurn(ts) { return S.turn || newTurn("system", null, ts); }
function setWorkOpen(t, open) {
  t.open = open; t.workList.hidden = !open;
  t.workHead.classList.toggle("open", open); t.workHead.setAttribute("aria-expanded", String(open));
}
function updateWorkHead(t) {
  const now = Date.now() / 1000;
  const dur = (t.ended || now) - t.started;
  t.workWhat.textContent = t.running ? `Working · ${fmtDur(dur)}` : t.interrupted ? "Interrupted" : `Worked for ${fmtDur(dur)}`;
  const bits = [plural(t.steps, "step")];
  if (t.subs.size) bits.push(plural(t.subs.size, "subagent"));
  if (t.tools) bits.push(plural(t.tools, "tool call"));
  t.workDetail.textContent = bits.join(" · ");
  const waiting = [...t.approvals.values()].some((a) => !a.resolved && S.pending.has(a.id));
  const key = waiting ? "wait" : t.running ? "run" : "done";
  if (key !== t.endKey) {
    t.endKey = key; clear(t.workEnd);
    if (waiting) t.workEnd.append(el("span", { class: "chip warn", text: "Waiting for approval" }));
    else if (t.running) t.workEnd.append(el("span", { class: "spin", title: "Working" }));
  }
  if (t.steps) t.work.hidden = false;
}
function finishTurn(t, ts, d, silent) {
  if (!t || !t.running) return;
  t.running = false; t.ended = ts || Date.now() / 1000;
  if (!t.toggled && t.steps) setWorkOpen(t, false);
  updateWorkHead(t);
  if (d && !d.ok && !silent) {
    t.lead.hidden = false;
    const head = d.ended ? "Ended after the restart" : d.stopped ? "Stopped by you" : d.interrupted ? "Interrupted: the dashboard stopped" : "The operation failed";
    const box = el("div", { class: "error-card" + (d.interrupted ? " warn" : "") },
      el("div", { class: "head" }, icon(d.interrupted ? "clock" : "alert", 16), head),
      el("div", { class: "small", text: d.text || "" }),
      d.stopped || d.interrupted ? null : el("div", { class: "toolbar" },
        t.text || t.playbook ? el("button", { type: "button", class: "btn btn-sm", onclick: () => send(t.text || "", t.playbook || "") }, icon("refresh", 14), "Retry") : null,
        el("button", { type: "button", class: "btn btn-sm", onclick: () => copyText(d.text || "") }, icon("copy", 14), "Copy details")));
    mutate(() => t.extras.append(box));
  }
}
function addStep(t, o) {
  t.lead.hidden = false;
  const expandable = typeof o.body === "function";
  const asButton = expandable && !o.note;
  const row = el(asButton ? "button" : "div", { class: "step" + (o.denied ? " denied" : "") + (o.note ? " note" : "") + (expandable ? " expandable" : ""), type: asButton ? "button" : null, "aria-expanded": asButton ? "false" : null });
  const st = { row, end: el("span", { class: "end" }), wrap: null, bodyEl: null, data: o };
  row.append(...[el("span", { class: "ic" }, icon(o.icon || "box")), o.note ? el("span", { class: "what" }, inline(o.what)) : el("span", { class: "what", text: o.what }),
    o.note ? null : el("span", { class: "detail", text: o.detail || "" }), st.end].filter(Boolean));
  const toggle = expandable && o.note ? el("button", { type: "button", class: "chev-btn", "aria-expanded": "false", "aria-label": "Show the full text" }, icon("chevR", 14)) : null;
  if (asButton) row.append(el("span", { class: "chev" }, icon("chevR", 14)));
  if (toggle) row.append(toggle);
  st.wrap = el("div", {}, row);
  if (expandable) {
    const flip = () => {
      const open = !st.bodyEl;
      if (!open) { st.bodyEl.remove(); st.bodyEl = null; } else { st.bodyEl = el("div", { class: "step-body fade" }, o.body(st)); st.wrap.append(st.bodyEl); }
      row.classList.toggle("open", open); (toggle || row).setAttribute("aria-expanded", String(open));
    };
    row.addEventListener("click", (e) => { if (!toggle || !e.target.closest(".file-ref, .cite")) flip(); });
  }
  if (o.endNodes) st.end.append(...o.endNodes.filter(Boolean));
  mutate(() => t.workList.append(st.wrap));
  t.steps++; updateWorkHead(t);
  return st;
}
function setEnd(st, ...nodes) { clear(st.end).append(...nodes.filter(Boolean)); }
function toolDetail(s) {
  const out = [];
  if (s.decision && !s.decision.allowed) out.push(el("div", {}, el("span", { class: "label", text: "Why it did not run: " }), s.decision.reason));
  out.push(el("div", { class: "label", text: "Arguments" }), el("pre", { class: "code", text: JSON.stringify(s.args || {}, null, 2) }));
  if (s.result) {
    out.push(el("div", { class: "label", text: `Result · ${fmtChars(s.result.chars)} · ${s.result.seconds} s${s.result.error ? " · error" : ""}` }),
      el("pre", { class: "code", text: s.result.preview || "(empty)" }));
  } else if (!s.decision || s.decision.allowed) out.push(el("div", { class: "muted small", text: "Waiting for the result…" }));
  return out;
}
function pendingKey(agent, tool) { return agent + "|" + tool; }
function queuePending(map, agent, tool, st) { const k = pendingKey(agent, tool); if (!map.has(k)) map.set(k, []); map.get(k).push(st); }
function takePending(map, agent, tool) { const q = map.get(pendingKey(agent, tool)); return q && q.length ? q.shift() : null; }
function isLead(d) { return (d.agent_id || d.agent) === "lead"; }

/* ---------------------------------------------------------------- subagents */
function sub(id, patch) {
  let s = S.subs.get(id);
  if (!s) { s = { id, expert: "", title: id, task: "", status: "idle", started: 0, ended: 0, activity: "", events: [], report: null, step: null, seen: false }; S.subs.set(id, s); }
  if (patch) Object.assign(s, patch);
  return s;
}
function isWaiting(s) {
  if (s.status !== "running") return false;
  for (const p of S.pending.values()) if (agentOf(p.why) === s.expert) return true;
  return false;
}
function elapsedText(s) {
  const secs = s.status === "running" && s.started ? Date.now() / 1000 - s.started : s.ended && s.started ? s.ended - s.started : 0;
  return secs >= 1 ? fmtDur(secs) : "";
}
function subLog(id, kind, d, ts) {
  const s = sub(id); s.seen = true;
  s.events.push({ kind, d, ts });
  if (kind === "decision") s.activity = `${toolLabel(d.tool)}${d.allowed ? "" : " (not executed)"}${argSummary(d.args) ? " · " + argSummary(d.args) : ""}`;
  else if (kind === "text") s.activity = firstLine(d.text, 140);
  else if (kind === "skill_used") s.activity = `Loaded skill ${d.skill} v${d.version}`;
  else if (kind === "steer") s.activity = "Received your guidance";
  renderSubframeSoon();
  if (S.insp.thread === id) renderInspSoon();
}
const renderSubframeSoon = debounce(() => renderSubframe(), 60);
function renderSubframe() { keepFocus(S.ui.subframe, drawSubframe); }
function drawSubframe() {
  const f = S.ui.subframe;
  const subs = [...S.subs.values()].filter((s) => s.expert);
  if (!subs.length) { f.hidden = true; return; }
  const running = subs.filter((s) => s.status === "running" || s.status === "queued");
  const waiting = running.filter(isWaiting);
  const interrupted = subs.filter((s) => s.status === "interrupted").length;
  const done = subs.length - running.length - interrupted;
  const open = S.subframeOpen === null ? running.length > 0 : S.subframeOpen;
  const summary = [running.length - waiting.length ? `${running.length - waiting.length} running` : null,
    waiting.length ? `${waiting.length} waiting for approval` : null, interrupted ? `${interrupted} interrupted` : null,
    done ? `${done} finished` : null].filter(Boolean).join(" · ");
  clear(f).append(el("button", { type: "button", class: "step head" + (open ? " open" : ""), "aria-expanded": String(open),
    onclick: () => { S.subframeOpen = !open; renderSubframe(); } },
    el("span", { class: "ic" }, icon("users")), el("span", { class: "what", text: plural(subs.length, "subagent") }),
    el("span", { class: "detail", text: summary }), el("span", { class: "chev" }, icon(open ? "chevD" : "chevU", 14))));
  if (open) {
    const list = el("div", { class: "sub-list" });
    const active = (s) => s.status === "running" || s.status === "queued";
    const order = [...subs].sort((a, b) => active(b) - active(a) || b.id.localeCompare(a.id));
    for (const s of order) list.append(subRow(s));
    f.append(list);
  }
  f.hidden = false;
}
function subRow(s) {
  const run = s.status === "running" || s.status === "queued", wait = isWaiting(s);
  const dot = run ? (wait ? "dot warn live" : "dot red live") : s.status === "completed" ? "dot ok" : s.status === "failed" ? "dot red" : "dot";
  const act = run ? (wait ? "Waiting for your approval" : s.status === "queued" ? "Waiting for a free slot" : s.activity || "Working") : (s.report ? firstLine(s.report.summary, 140) : s.status);
  s.actEl = el("span", { class: "act", text: act });
  return el("div", { class: "sub-row" },
    el("button", { type: "button", class: "open", title: s.task, onclick: () => openThread(s.id) },
      el("span", { class: dot }), el("span", { class: "sid", text: s.id }),
      el("span", { class: "nm", text: shortTitle(s.title) }),
      s.actEl),
    el("span", { class: "muted small", "data-elapsed": s.id, text: elapsedText(s) }),
    run ? el("button", { type: "button", class: "btn btn-sm", "aria-label": `Steer ${s.id}`, onclick: () => openThread(s.id, true) }, "Steer") : null,
    run ? stopButton(s) : null);
}
function stopButton(s) {
  const armed = () => (S.stopArmed.get(s.id) || 0) > Date.now();
  const b = el("button", { type: "button", class: "btn btn-sm btn-danger stop-" + s.id, "aria-label": `${armed() ? "Confirm stop" : "Stop"} ${s.id}` }, armed() ? "Confirm stop" : "Stop");
  b.addEventListener("click", async () => {
    if (!armed()) {
      S.stopArmed.set(s.id, Date.now() + 4000); b.textContent = "Confirm stop"; b.setAttribute("aria-label", `Confirm stop ${s.id}`);
      setTimeout(() => { if (!armed()) document.querySelectorAll(".btn-danger.stop-" + CSS.escape(s.id)).forEach((x) => { x.textContent = "Stop"; }); }, 4100);
      return;
    }
    S.stopArmed.delete(s.id);
    try { await api(`/api/subagents/${encodeURIComponent(s.id)}/stop`, {}); toast(`Stopping ${s.id}`); } catch (e) { toast(e.message, true); }
  });
  return b;
}

/* ---------------------------------------------------------------- approvals */
function approvalCard(t, d, replay) {
  const a = { id: d.id, d, resolved: false };
  const who = agentOf(d.why), tgt = targetsOf(d.arguments);
  a.actions = el("div", { class: "toolbar" },
    el("button", { type: "button", class: "btn btn-primary", onclick: () => openApproval(d.id) }, "Review and approve"),
    el("button", { type: "button", class: "btn btn-danger", onclick: () => decide(d.id, false, "") }, "Deny"));
  a.box = el("div", { class: "approval", role: "group", "aria-label": `Approval needed: ${toolLabel(d.tool)}` },
    el("div", { class: "head" }, icon("shield", 18), el("strong", { text: `Approval needed · ${toolLabel(d.tool)}` }),
      el("span", { class: "tier approve", css: { marginLeft: "auto" }, text: "ROE: approve" })),
    el("div", { class: "kv" },
      el("span", { class: "label", text: "Requested by" }), el("span", { text: who || "agent" }),
      tgt ? el("span", { class: "label", text: "Target" }) : null, tgt ? el("span", { class: "mono", text: tgt }) : null,
      commandOf(d.tool, d.arguments) ? el("span", { class: "label", text: "Command" }) : null,
      commandOf(d.tool, d.arguments) ? el("span", { class: "mono cmd", text: commandOf(d.tool, d.arguments) }) : null,
      el("span", { class: "label", text: "Rule" }), el("span", { text: ruleOf(d.why) })),
    a.actions);
  if (replay) a.actions.hidden = true;
  t.approvals.set(d.id, a); S.approvalCards.set(d.id, a);
  mutate(() => t.extras.append(a.box));
  return a;
}
function resolveCard(id, d, how) {
  const a = S.approvalCards.get(id); if (!a || a.resolved) return;
  a.resolved = true; a.box.classList.add("done");
  let node;
  const later = d && d.later ? " · applies as the operation resumes" : "";
  if (how === "expired") node = el("div", { class: "result gone" }, icon("clock", 15), "No longer pending: the operation ended or was stopped");
  else if (d.approved) node = el("div", { class: "result ok" }, icon("check", 15, 2.2), `Approved${d.by ? " by " + d.by : ""}${d.note ? " · " + d.note : ""}${later}`);
  else node = el("div", { class: "result no" }, icon("x", 15, 2.2), `Denied${d.by ? " by " + d.by : ""}${d.note ? " · " + d.note : ""}${later}`);
  a.actions.replaceWith(node); a.actions = node;
}
async function decide(id, approve, note) {
  try { await api("/api/approvals/" + encodeURIComponent(id), { approve, note }); }
  catch (e) { toast(e.message, true); }
}
function openApproval(id) {
  const p = S.pending.get(id);
  if (!p) { toast("That approval is no longer pending", true); return; }
  const note = el("input", { type: "text", id: "ap-note", placeholder: "Optional, recorded in the audit log" });
  const approve = el("button", { type: "button", class: "btn btn-primary" }, "Approve");
  let armed = false, timer = null, dlg = null;
  approve.addEventListener("click", async () => {
    if (!armed) { armed = true; approve.textContent = "Confirm approval"; timer = setTimeout(() => { armed = false; approve.textContent = "Approve"; }, 5000); return; }
    clearTimeout(timer); await decide(id, true, note.value); dlg.close();
  });
  const deny = el("button", { type: "button", class: "btn btn-danger", onclick: async () => { await decide(id, false, note.value); dlg.close(); } }, "Deny");
  const tgt = targetsOf(p.arguments);
  dlg = openDialog({
    title: S.st && S.st.gated ? "Approve action" : "Approve response action", sub: p.tool, iconName: "shield",
    body: [
      p.restored ? el("div", { class: "card warn-card small", text: "Asked before the dashboard restarted. Deciding it carries the interrupted operation on: your decision is applied when the agent reaches this action again." }) : null,
      el("div", { class: "kv" },
        el("span", { class: "label", text: "Action" }), el("span", { text: toolLabel(p.tool) }),
        tgt ? el("span", { class: "label", text: "Target" }) : null, tgt ? el("span", { class: "mono", text: tgt }) : null,
        commandOf(p.tool, p.arguments) ? el("span", { class: "label", text: "Command" }) : null,
        commandOf(p.tool, p.arguments) ? el("span", { class: "mono cmd", text: commandOf(p.tool, p.arguments) }) : null,
        el("span", { class: "label", text: "Requested by" }), el("span", { text: agentOf(p.why) || "agent" }),
        el("span", { class: "label", text: "ROE" }), el("span", { text: ruleOf(p.why) }),
        el("span", { class: "label", text: "Requested" }), el("span", { text: `${fmtClock(p.requested)} · ${fmtRel(p.requested)}${p.restored || p.asked_before_restart ? " · before the restart" : ""}` })),
      el("div", { class: "label", text: "Action brief from the agent" }),
      p.rationale ? md(p.rationale) : el("div", { class: "muted small", text: "The agent gave no rationale. Consider denying until it explains the target, impact and rollback." }),
      el("details", {}, el("summary", { class: "small", css: { cursor: "pointer" }, text: "Arguments" }), el("pre", { class: "code", css: { marginTop: "8px" }, text: JSON.stringify(p.arguments, null, 2) })),
      el("div", {}, el("label", { for: "ap-note", class: "label", css: { display: "block", marginBottom: "6px" }, text: "Note" }), note)],
    foot: [el("span", { class: "note", text: `Recorded in the hash-chained audit log as ${S.st.operator}.` }), deny, approve],
  });
}
function syncPending(list) {
  S.pending = new Map((list || []).map((p) => [p.id, p]));
  for (const a of S.approvalCards.values()) {
    if (a.resolved) continue;
    if (S.pending.has(a.id)) a.actions.hidden = false;
    else if (!S.replaying) resolveCard(a.id, null, "expired");
  }
}

/* ---------------------------------------------------------------- event handlers */
const H = {
  analyst_message(d, ev) {
    newTurn("analyst", d, ev.ts);
    if (!S.replaying && S.st && !S.st.conversation) scheduleRefresh(); // this message just created the conversation
  },
  retro_start(d, ev) { newTurn("retro", null, ev.ts); },
  operation_resumed(d, ev) { newTurn("resume", d, ev.ts); },
  subagent_resumed(d, ev) {
    const s = sub(d.id, { expert: d.expert, title: d.title, task: d.task || "", status: "running", started: ev.ts, ended: 0, activity: "Carrying on from where it stopped" });
    s.seen = true;
    const t = ensureTurn(ev.ts); t.subs.add(d.id);
    s.step = addStep(t, { icon: "refresh", what: `Resumed ${d.id} · ${shortTitle(d.title)}`, detail: d.task || "", body: () => subStepBody(d.id) });
    setEnd(s.step, statusChip("running"));
    renderSubframeSoon();
  },
  delta(d, ev) { applyDelta(d.agent_id || d.agent, d, ev.seq); },
  text(d, ev) {
    if (!isLead(d)) { S.live.delete(d.agent_id); subLog(d.agent_id, "text", d, ev.ts); return; }
    const t = ensureTurn(ev.ts); t.lead.hidden = false;
    S.live.delete("lead"); dropLeadLive(t);
    if (d.final) mutate(() => { if (t.answer.childNodes.length) t.answer.append(el("hr")); t.answer.append(md(d.text)); });
    else addStep(t, { icon: "chat", what: firstLine(d.text, 220), note: true, body: d.text.length > 220 || d.text.includes("\n") ? () => md(d.text) : null });
  },
  decision(d, ev) {
    if (!isLead(d)) { subLog(d.agent_id || d.agent, "decision", d, ev.ts); return; }
    if (d.tool.startsWith("subagent_") || d.tool === "submit_report") return;
    const t = ensureTurn(ev.ts); t.tools++;
    const st = addStep(t, { icon: toolIcon(d.tool), what: toolLabel(d.tool), detail: argSummary(d.args), denied: !d.allowed, body: (s) => toolDetail(s) });
    st.args = d.args; st.decision = d;
    if (!d.allowed) setEnd(st, el("span", { class: "chip red", text: d.tier === "deny" ? "Denied by ROE" : "Not run" }));
    else { setEnd(st, tierChip(d.tier), el("span", { class: "spin" })); queuePending(t.pending, "lead", d.tool, st); }
  },
  result(d, ev) {
    if (!isLead(d)) { subLog(d.agent_id || d.agent, "result", d, ev.ts); return; }
    if (d.tool.startsWith("subagent_") || d.tool === "submit_report") return;
    const t = S.turn; if (!t) return;
    const st = takePending(t.pending, "lead", d.tool); if (!st) return;
    st.result = d;
    setEnd(st, tierChip(st.decision && st.decision.tier), d.error ? el("span", { class: "chip red", text: "Error" }) : el("span", { text: `${d.seconds} s` }));
    if (st.bodyEl) { clear(st.bodyEl).append(...toolDetail(st)); }
  },
  subagent_spawn(d, ev) {
    const s = sub(d.id, { expert: d.expert, title: d.title, task: d.task, status: "running", started: ev.ts, ended: 0, report: null, activity: "Starting" });
    s.seen = true;
    const t = ensureTurn(ev.ts); t.subs.add(d.id);
    s.step = addStep(t, { icon: "users", what: `Spawned ${d.id} · ${shortTitle(d.title)}`, detail: d.task, body: () => subStepBody(d.id) });
    setEnd(s.step, statusChip("running"));
    renderSubframeSoon(); renderHeader();
  },
  subagent_message(d, ev) {
    const s = sub(d.id, { expert: d.expert, title: d.title, status: "running", started: ev.ts, ended: 0, activity: "Reading your follow-up" });
    s.seen = true;
    const t = ensureTurn(ev.ts); t.subs.add(d.id);
    const reflect = /^#\s*Reflection/.test(d.message || "");
    s.step = addStep(t, { icon: "chat", what: reflect ? `Asked ${d.id} to reflect on its skills` : `Followed up with ${d.id}`, detail: reflect ? shortTitle(d.title) : firstLine(d.message, 200),
      body: () => [el("div", { class: "label", text: "Message to the subagent" }), md(d.message)] });
    setEnd(s.step, statusChip("running"));
    s.events.push({ kind: "message", d, ts: ev.ts });
    renderSubframeSoon();
  },
  subagent_steer(d, ev) {
    subLog(d.id, "steer", d, ev.ts);
    const t = ensureTurn(ev.ts);
    addStep(t, { icon: "steer", what: `You steered ${d.id}`, detail: firstLine(d.message, 200) });
  },
  subagent_report(d, ev) {
    S.live.delete(d.id);
    const s = sub(d.id, { expert: d.expert, title: d.title, status: d.status, report: d, ended: ev.ts });
    s.seen = true; s.events.push({ kind: "report", d, ts: ev.ts });
    if (s.step) setEnd(s.step, statusChip(d.status, d.seconds));
    const t = ensureTurn(ev.ts);
    const card = el("button", { type: "button", class: "sa-card", onclick: () => openThread(d.id) },
      el("div", { class: "head" }, el("span", { class: "sid", text: d.id }), el("span", { class: "name", text: shortTitle(d.title) }),
        el("span", { css: { marginLeft: "auto" } }, statusChip(d.status))),
      el("div", { class: "body", text: d.summary || "(empty report)" }),
      el("div", { class: "foot", text: [d.confidence && d.confidence !== "unstated" ? `Confidence ${d.confidence}` : null, d.seconds ? fmtDur(d.seconds) : null,
        (d.recommended_tasks || []).length ? plural(d.recommended_tasks.length, "recommended task") : null, "Open thread"].filter(Boolean).join(" · ") }));
    mutate(() => { const old = t.cardEls.get(d.id); if (old) old.replaceWith(card); else t.cards.append(card); t.cardEls.set(d.id, card); });
    renderSubframeSoon(); if (S.insp.thread === d.id) renderInspSoon();
  },
  skill_used(d, ev) {
    if (d.agent_id && d.agent_id !== "lead") { subLog(d.agent_id, "skill_used", d, ev.ts); return; }
    addStep(ensureTurn(ev.ts), { icon: "book", what: `Loaded skill ${d.skill}`, detail: `v${d.version}` });
  },
  skill_proposed(d, ev) {
    if (d.agent_id && d.agent_id !== "lead") subLog(d.agent_id, "skill_proposed", d, ev.ts);
    const t = ensureTurn(ev.ts);
    const st = addStep(t, { icon: "book", what: d.status === "candidate" ? `${d.agent_id} proposed skill ${d.skill} v${d.version}` : `${d.agent_id} saved skill ${d.skill} v${d.version}`,
      detail: d.change_note || "" });
    if (d.status === "candidate") setEnd(st, el("a", { href: "#/skills", class: "chip warn", text: "Review" }));
    if (!S.replaying) scheduleRefresh();
  },
  approval_request(d, ev) {
    const old = S.approvalCards.get(d.id); // asked again after a restart: the same card comes back to life
    let t;
    if (old && !old.resolved) { old.actions.hidden = !!ev.replay; t = S.turns.find((x) => x.approvals.has(d.id)); }
    else { t = ensureTurn(ev.ts); approvalCard(t, d, !!ev.replay); }
    if (!ev.replay) { S.pending.set(d.id, d); onPendingChanged(); }
    if (t) updateWorkHead(t);
  },
  approval_resolved(d) {
    S.pending.delete(d.id); resolveCard(d.id, d);
    if (!S.replaying) onPendingChanged();
    for (const t of S.turns) if (t.approvals.has(d.id)) updateWorkHead(t);
  },
  run_start(d) { S.running = true; S.runLabel = d.label; onRunChanged(); },
  run_end(d, ev) {
    if (!ev.replay) { S.running = false; onRunChanged(); }
    const t = S.turn;
    S.live.delete("lead"); if (t) dropLeadLive(t);
    if (t) {
      if (d.ok && d.text && !t.answer.childNodes.length) mutate(() => t.answer.append(md(d.text)));
      finishTurn(t, ev.ts, d);
    }
    if (!S.replaying) { refreshConvs(); scheduleRefresh(); }
  },
  loop_guard(d, ev) {
    const what = d.gave_up ? "Gave up: the model kept repeating itself" : "Cut off a reply that was repeating itself and asked again";
    const detail = `"${d.unit}"${d.where === "reasoning" ? " (in its reasoning)" : ""}`;
    if (!isLead(d)) { subLog(d.agent_id || d.agent, "text", { text: `${what}: ${detail}` }, ev.ts); return; }
    const st = addStep(ensureTurn(ev.ts), { icon: "alert", what, detail });
    if (d.gave_up) setEnd(st, el("span", { class: "chip red", text: "Stopped" }));
  },
  gate_on(d, ev) {
    const st = addStep(ensureTurn(ev.ts), { icon: "shield", what: "Approval mode on: every action in this conversation needs your approval", detail: d.reason });
    setEnd(st, el("span", { class: "chip warn", text: "Approve everything" }));
    if (S.st && !S.replaying) { S.st.gated = d.reason; renderHeader(); }
  },
  plan_saved(d, ev) {
    if (d.agent_id && d.agent_id !== "lead") subLog(d.agent_id, "text", { text: `Saved ${PLAN_KIND[d.kind] || "file"}: ${d.name}` }, ev.ts);
    const t = ensureTurn(ev.ts);
    mutate(() => t.cards.append(planCard(d)));
    if (!S.replaying) refreshPlans();
  },
  compact(d, ev) {
    if (!isLead(d)) { subLog(d.agent_id || d.agent, "text", { text: `Compacted ${d.dropped} old messages` }, ev.ts); return; }
    addStep(ensureTurn(ev.ts), { icon: "refresh", what: "Compacted the lead's context", detail: `${plural(d.dropped, "older message")} summarized` });
  },
  telemetry(d) {
    if (S.live.has(d.agent_id)) { S.live.delete(d.agent_id); liveChanged(d.agent_id); } // the call ended without text
    if (d.agent_id === "lead") { S.telemetry = d; renderStatus(); }
  },
  history_truncated(d) {
    mutate(() => S.ui.feed.append(el("div", { class: "turn-label", text: `${plural(d.omitted, "earlier event")} not shown here; see canarchist history show` })));
  },
  conversation_switched() { if (!S.replaying) loadConversation(); },
  case_updated() { scheduleRefresh(); refreshConvs(); },
  memory_updated() { scheduleRefresh(); if (S.view === "memory") renderPage("memory"); },
  skills_updated() { scheduleRefresh(); if (S.view === "skills") renderPage("skills"); },
  model_switched() { scheduleRefresh(); },
  ui_updated(d) {
    if (!S.st) return;
    S.st.ui.classification = d.classification; S.st.ui.classification_source = d.source;
    applyClassification(d.classification);
    if (S.view === "settings" && !S.clsDraft) renderPage("settings");
  },
  rated() { scheduleRefresh(); },
  settings_changed(d) { if (!d.restarting) { scheduleRefresh(); if (S.view === "settings" && !S.clsDraft) renderPage("settings"); } },
  case_switched() { location.reload(); },
  ready() { scheduleRefresh(); },
};
function onEvent(ev) {
  if (S.loading) { S.buffer.push(ev); return; }
  if (ev.seq <= S.lastSeq) return;
  S.lastSeq = ev.seq;
  const h = H[ev.kind];
  if (h) { try { h(ev.data || {}, ev); } catch (e) { console.error(ev.kind, e); } }
}
function onPendingChanged() { renderBanner(); renderStatus(); renderHeader(); renderSide(); renderSubframeSoon(); }
function onRunChanged() { renderStatus(); renderComposerState(); renderSide(); renderResume(); }
/* ---------------------------------------------------------------- streaming */
// Deltas carry their offset in the reply, so pieces seeded from /api/state and pieces from the event stream
// stitch together without gaps or duplicates. A gap (missed piece) triggers a state refresh to resync.
function applyDelta(id, d, seq) {
  if (!id) return;
  if (d.reset) { if (S.live.delete(id)) liveChanged(id); return; }
  const cur = S.live.get(id) || { text: "", seq: 0 };
  const off = d.offset || 0;
  if (off > cur.text.length) { scheduleRefresh(); return; }
  const next = cur.text.slice(0, off) + (d.text || "");
  if (next.length <= cur.text.length) return; // already have this piece
  S.live.set(id, { text: next, seq });
  liveChanged(id);
}
function seedLive(st) {
  const live = st.live || {};
  for (const [id, v] of Object.entries(live)) {
    const cur = S.live.get(id);
    if (!cur || v.text.length > cur.text.length) { S.live.set(id, { text: v.text, seq: v.seq }); liveChanged(id); }
  }
  for (const [id, cur] of [...S.live]) {
    if (!(id in live) && cur.seq <= (st.last_seq || 0)) { S.live.delete(id); liveChanged(id); } // finished meanwhile
  }
}
function liveChanged(id) {
  if (id === "lead") { renderLeadLiveSoon(); return; }
  const s = S.subs.get(id); if (!s) return;
  const v = S.live.get(id);
  if (v && v.text.trim()) s.activity = tailLine(v.text);
  if (s.actEl && s.actEl.isConnected && s.status === "running" && !isWaiting(s)) s.actEl.textContent = s.activity || "Working";
  if (S.insp.thread === id) renderThreadLiveSoon();
}
function rafOnce(fn) { let q = 0; return () => { if (!q) q = requestAnimationFrame(() => { q = 0; fn(); }); }; }
const renderLeadLiveSoon = rafOnce(() => {
  const v = S.live.get("lead");
  if (!v || !v.text.trim()) { if (S.turn) dropLeadLive(S.turn); return; }
  const t = ensureTurn(Date.now() / 1000);
  mutate(() => {
    t.lead.hidden = false;
    if (!t.live) { t.live = el("div", { class: "answer live", "aria-hidden": "true" }); t.answer.before(t.live); }
    clear(t.live).append(withCaret(md(v.text)));
  });
});
function dropLeadLive(t) { if (t && t.live) { t.live.remove(); t.live = null; } }
const renderThreadLiveSoon = rafOnce(() => {
  const box = S.ui.threadLive; const id = S.insp.thread;
  if (!box || !box.isConnected || !id) return;
  const v = S.live.get(id);
  const has = !!(v && v.text.trim());
  clear(box); box.hidden = !has;
  if (has) box.append(withCaret(md(v.text)));
});

function subStepBody(id) {
  const s = S.subs.get(id); if (!s) return [];
  return [el("div", {}, el("span", { class: "label", text: "Brief " }), s.task || ""),
    s.report ? el("div", {}, el("span", { class: "label", text: "Report " }), s.report.summary || "") : el("div", { class: "muted small", text: s.activity || "Working" }),
    el("div", {}, el("button", { type: "button", class: "btn btn-sm", onclick: () => openThread(id) }, icon("external", 14), `Open ${id} thread`))];
}

/* ---------------------------------------------------------------- loading / replay */
function replay(evs) {
  S.replaying = true;
  try { for (const ev of evs) onEvent(ev); }
  finally { S.replaying = false; }
  for (const t of S.turns) {
    if (t.running && (!S.running || t !== S.turn)) { t.interrupted = !t.ended; finishTurn(t, t.ended || null, null, true); }
  }
  syncPending([...S.pending.values()]);
  settleSubs(S.st);
  if (!S.turns.length) showHero();
  renderSubframe(); renderHeader(); renderBanner(); renderResume();
  scrollBottom();
}
async function loadConversation() {
  S.loading = true; S.buffer = [];
  try {
    const [st, evs, convs] = await Promise.all([api("/api/state"), api("/api/events/poll?after=0"), api("/api/conversations")]);
    resetFeed();
    applyState(st); S.convs = convs.conversations;
    S.lastSeq = 0;
    S.loading = false;
    replay(evs);
    const buffered = S.buffer; S.buffer = [];
    for (const ev of buffered) onEvent(ev);
    const draft = st.conversation ? S.drafts.get(st.conversation.id) : "";
    S.ui.input.value = draft || ""; onComposerInput();
    renderSide(); renderInsp(); renderStatus(); renderComposerState();
  } catch (e) { S.loading = false; toast("Could not load the conversation: " + e.message, true); }
}
// Nothing is running: the server's subagent statuses are final. (A replayed feed shows a subagent that a restart cut
// off as still running.)
function settleSubs(st) {
  if (!st || st.running) return;
  for (const m of st.subagents || []) {
    const s = S.subs.get(m.id);
    if (s && ["running", "queued"].includes(s.status)) Object.assign(s, { status: m.status, report: m.last_report || s.report });
  }
}
function applyState(st) {
  const prevCase = S.st ? JSON.stringify(S.st.case) : "";
  S.st = st;
  S.running = st.running; S.runLabel = st.run_label;
  if (st.telemetry && st.telemetry.agent_id) S.telemetry = st.telemetry;
  applyClassification(st.ui && st.ui.classification);
  seedLive(st);
  // the first message of a new conversation creates it mid-run: list it in the sidebar straight away
  if (st.conversation && !S.loading && !(S.convs || []).some((c) => c.id === st.conversation.id)) refreshConvs();
  syncPending(st.pending);
  for (const m of st.subagents || []) {
    const s = sub(m.id);
    if (!s.seen) Object.assign(s, { expert: m.expert, title: m.title, task: m.task, status: m.status, report: m.last_report || null });
    else if (["running", "queued"].includes(m.status) && ["running", "queued"].includes(s.status)) s.status = m.status;
    // nothing is running: the server's status is final (a replayed feed shows a subagent cut off by a restart as running)
    if (m.status === "running" && m.elapsed !== null && m.elapsed !== undefined) s.started = Date.now() / 1000 - m.elapsed;
  }
  settleSubs(st);
  return prevCase !== JSON.stringify(st.case);
}
async function refreshState() {
  const st = await api("/api/state");
  const caseChanged = applyState(st);
  renderSide(); renderHeader(); renderBanner(); renderResume(); renderStatus(); renderComposerState(); renderSubframe();
  if (caseChanged && !S.insp.thread) renderInsp();
  if (!S.turns.length) showHero();
}
const scheduleRefresh = debounce(() => refreshState().catch(() => {}), 250);
async function refreshConvs() { try { const d = await api("/api/conversations"); S.convs = d.conversations; renderSide(); } catch (e) { /* ignore */ } }
async function refreshAudit() { try { S.audit = await api("/api/audit?limit=1"); renderSide(); renderStatus(); } catch (e) { /* ignore */ } }

function connect() {
  if (S.es) S.es.close();
  const es = new EventSource("/api/events?after=" + S.lastSeq);
  S.es = es;
  es.onopen = () => {
    const again = S.wasConnected; S.wasConnected = true;
    if (!S.connected) { S.connected = true; renderStatus(); }
    if (again) scheduleRefresh(); // streamed text sent while we were away is not in the backlog; state carries it
  };
  es.onerror = () => {
    S.connected = false; renderStatus(); es.close();
    setTimeout(async () => {
      try { const r = await fetch("/api/public", { credentials: "same-origin" }); const d = await r.json(); if (!d.authed) { location.replace("/login"); return; } } catch (e) { /* server down; keep retrying */ }
      connect();
    }, 2000);
  };
  es.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch (e) { console.error(e); } };
}

/* ---------------------------------------------------------------- conversations */
async function newConversation() {
  if (S.running) { toast("Stop the current operation first", true); return; }
  try { await api("/api/conversations/new", {}); go("ops"); S.ui.input.focus(); } catch (e) { toast(e.message, true); }
}
async function openConversation(id) {
  try { await api(`/api/conversations/${encodeURIComponent(id)}/open`, {}); } catch (e) { toast(e.message, true); }
}
function renameDialog(c) {
  const input = el("input", { type: "text", value: c.title || "", "aria-label": "Conversation title" });
  const save = async () => {
    try { await api(`/api/conversations/${encodeURIComponent(c.id)}/rename`, { title: input.value.trim() }); dlg.close(); refreshConvs(); scheduleRefresh(); }
    catch (e) { toast(e.message, true); }
  };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); save(); } });
  const dlg = openDialog({ title: "Rename conversation", body: [input], foot: [el("span", { class: "note" }), el("button", { type: "button", class: "btn", onclick: () => dlg.close() }, "Cancel"),
    el("button", { type: "button", class: "btn btn-primary", onclick: save }, "Save")] });
}
function deleteDialog(c) {
  const input = el("input", { type: "text", placeholder: "Type delete to confirm", "aria-label": "Type delete to confirm" });
  const btn = el("button", { type: "button", class: "btn btn-primary", disabled: true }, "Delete permanently");
  input.addEventListener("input", () => { btn.disabled = input.value.trim().toLowerCase() !== "delete"; });
  btn.addEventListener("click", async () => {
    try { await api(`/api/conversations/${encodeURIComponent(c.id)}/delete`, { confirm: c.id }); dlg.close(); toast("Conversation deleted"); refreshConvs(); }
    catch (e) { toast(e.message, true); }
  });
  const dlg = openDialog({ title: "Delete this conversation?", sub: c.title, iconName: "trash",
    body: [el("p", { css: { margin: "0" }, text: `This removes the conversation's ${plural(c.events, "event")}, the lead's and every subagent's context, and its transcripts. It cannot be undone.` }),
      el("p", { class: "muted small", css: { margin: "0" }, text: "The case record, the audit log, and the memories and skills learned from it are kept. The deletion is audited." }), input],
    foot: [el("span", { class: "note" }), el("button", { type: "button", class: "btn", onclick: () => dlg.close() }, "Cancel"), btn] });
}
function convMenuItems() {
  const c = S.st && S.st.conversation;
  const row = c && S.convs.find((x) => x.id === c.id);
  return [
    { icon: "edit", label: "Rename", disabled: !row, run: () => renameDialog(row) },
    { icon: "refresh", label: "After-action review", disabled: S.running || !c, run: runRetro },
    { icon: "star", label: "Rate this session", disabled: !c, run: rateDialog },
    "-",
    { icon: "trash", label: "Delete conversation", danger: true, disabled: !row || S.running, run: () => deleteDialog(row) },
  ];
}
async function runRetro() { try { await api("/api/retro", {}); } catch (e) { toast(e.message, true); } }
function rateDialog() {
  let rating = 0;
  const seg = el("div", { class: "seg", role: "group", "aria-label": "Rating" });
  const btns = [1, 2, 3, 4, 5].map((n) => el("button", { type: "button", "aria-pressed": "false", "aria-label": `${n} of 5`, onclick: () => { rating = n; btns.forEach((b, i) => { b.classList.toggle("on", i + 1 === n); b.setAttribute("aria-pressed", String(i + 1 === n)); }); } }, String(n)));
  seg.append(...btns);
  const note = el("input", { type: "text", placeholder: "What worked, what didn't (optional)", "aria-label": "Rating note" });
  const dlg = openDialog({ title: "Rate this session", iconName: "star",
    body: [el("p", { class: "muted small", css: { margin: "0" }, text: "4-5 marks the skills used here as having worked, 1-2 as having failed. Highly rated sessions become fine-tuning data." }), seg, note],
    foot: [el("span", { class: "note" }), el("button", { type: "button", class: "btn", onclick: () => dlg.close() }, "Cancel"),
      el("button", { type: "button", class: "btn btn-primary", onclick: async () => {
        if (!rating) { toast("Pick a rating", true); return; }
        try { await api("/api/rate", { rating, note: note.value }); dlg.close(); toast(`Session rated ${rating}`); } catch (e) { toast(e.message, true); }
      } }, "Save rating")] });
}
function playbookMenu() {
  const items = (S.st.playbooks || []).map((p) => ({ icon: "list", label: humanPb(p), run: () => setPlaybook(p) }));
  if (S.playbook) items.push("-", { icon: "x", label: "No playbook", run: () => setPlaybook("") });
  return items;
}
function modelLabel(name) { const m = S.st && S.st.models.find((x) => x.name === name); return m ? m.label : name; }
function modelGroups(models) {
  const groups = new Map();
  for (const m of models) { if (!groups.has(m.group)) groups.set(m.group, []); groups.get(m.group).push(m); }
  return groups;
}
async function switchModel(m) {
  try { await api("/api/model", { name: m.name }); toast(`Lead now on ${m.label}`); scheduleRefresh(); } catch (e) { toast(e.message, true); }
}
// Profiles come from config/models.yaml (+ models.local.yaml); the state is re-read first so file edits show up.
async function openModelMenu(anchor) {
  try { await refreshState(); } catch (e) { /* show what we have */ }
  const items = [];
  for (const [g, list] of modelGroups(S.st.models)) {
    items.push({ header: g });
    for (const m of list) items.push({ icon: m.name === S.st.model ? "check" : "box", label: m.label, disabled: S.running || !m.ready,
      end: m.ready ? m.model : "needs setup", title: m.ready ? `${m.name} · ${m.provider} · ${m.model}` : `${m.name}: ${m.problem}`, run: () => switchModel(m) });
  }
  items.push("-", { icon: "sliders", label: "Manage models…", end: "models.yaml", run: () => go("settings") });
  openMenu(anchor, items);
}
async function signOut() { try { await api("/api/logout", {}); } catch (e) { /* ignore */ } location.replace("/login"); }

/* ================================================================ inspector (case panel / subagent thread) */
function toggleInsp() { S.insp.open = !S.insp.open; setPref("insp", S.insp.open ? "1" : "0"); renderInsp(); renderHeader(); }
function openThread(id, steer) {
  S.insp.thread = id; S.insp.open = true; renderInsp(); renderHeader();
  if (steer) setTimeout(() => { const t = $("steer-input"); if (t) t.focus(); }, 30);
}
const renderInspSoon = debounce(() => renderInsp(), 80);
function renderInsp() {
  const box = $("insp");
  if (!S.st || S.view !== "ops" || !S.insp.open) { box.hidden = true; return; }
  box.hidden = false;
  const keepScroll = box.querySelector(".insp-body");
  const scrollTop = keepScroll ? keepScroll.scrollTop : 0;
  const focus = captureFocus(box);
  S.ui.threadLive = null;
  clear(box);
  if (S.insp.thread && S.subs.has(S.insp.thread)) renderThread(box, S.subs.get(S.insp.thread));
  else { S.insp.thread = null; renderCase(box); }
  const body = box.querySelector(".insp-body");
  if (body && keepScroll) body.scrollTop = scrollTop;
  restoreFocus(box, focus);
}
function inspClose() { return el("button", { type: "button", class: "btn btn-ghost icon-btn", "aria-label": "Close panel", title: "Close (Ctrl+.)", onclick: toggleInsp }, icon("x")); }
function renderCase(box) {
  const c = S.st.case;
  const tabs = [["findings", "Findings", c.findings.length], ["iocs", "IOCs", c.iocs.length], ["timeline", "Timeline", c.timeline.length],
    ["evidence", "Evidence", c.evidence.length], ["plans", "Plans & reports", S.plans ? S.plans.files.filter((f) => PLAN_COUNTED.has(f.kind)).length : null],
    ["report", "Report", null]];
  box.append(el("div", { class: "insp-head" },
    el("div", { class: "t" }, el("strong", { text: `Case ${c.id}` }), el("span", { class: "muted small", text: c.mission ? firstLine(c.mission, 140) : "No mission recorded yet" })),
    inspClose()));
  box.append(tabList("Case sections", "case", tabs.map(([id, label, n]) => [id, label, n ? el("span", { class: "count", "aria-label": `(${n})`, text: n }) : null]),
    S.insp.tab, (id) => { S.insp.tab = id; renderInsp(); if (id === "plans") refreshPlans(); }));
  const body = el("div", { class: "insp-body fade", role: "tabpanel", id: "case-panel", "aria-labelledby": `case-tab-${S.insp.tab}`, tabindex: "0" });
  box.append(body);
  ({ findings: caseFindings, iocs: caseIocs, timeline: caseTimeline, evidence: caseEvidence, plans: casePlans, report: caseReport })[S.insp.tab](body, c);
}
const SEV_ORDER = ["critical", "high", "medium", "low", "informational"];
function caseFindings(body, c) {
  if (!c.findings.length) { body.append(el("div", { class: "empty", text: "No findings yet. Subagents record them as they confirm activity." })); return; }
  const verdicts = [["tp", "True positive"], ["fp", "False positive"], ["benign", "Benign"], ["inconclusive", "Inconclusive"]];
  for (const f of [...c.findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))) {
    const note = el("input", { type: "text", placeholder: "Verdict note (optional)", "aria-label": "Verdict note" });
    body.append(el("div", { class: "card finding", "data-ref": f.id },
      el("div", { class: "top" }, el("span", { class: "sev " + f.severity, text: f.severity }), el("span", { class: "mono muted", text: f.id }),
        el("span", { class: "muted small", css: { marginLeft: "auto" }, text: f.confidence ? `Confidence ${f.confidence}` : "" })),
      el("h3", { text: f.title }),
      el("div", { class: "desc" }, md(f.description)),
      (f.attack_techniques || []).length || (f.affected_assets || []).length ? el("div", { class: "chips", css: { marginTop: "10px" } },
        (f.attack_techniques || []).map((t) => el("span", { class: "chip mono", text: t })), (f.affected_assets || []).map((a) => el("span", { class: "chip", text: a }))) : null,
      (f.recommended_actions || []).length ? el("div", { css: { marginTop: "12px" } }, el("div", { class: "label", text: "Recommended" }),
        el("ul", { css: { margin: "4px 0 0", paddingLeft: "18px", fontSize: "13px", color: "var(--text-2)" } }, f.recommended_actions.map((a) => el("li", { text: a })))) : null,
      el("div", { class: "label", css: { marginTop: "12px" }, text: f.verdict && f.verdict !== "unreviewed" ? `Your verdict${f.verdict_note ? " · " + f.verdict_note : ""}` : "Your verdict" }),
      el("div", { class: "verdicts", role: "group", "aria-label": "Verdict", css: { marginTop: "6px" } }, verdicts.map(([v, label]) =>
        el("button", { type: "button", class: (f.verdict === v ? "on " : "") + v, "aria-pressed": String(f.verdict === v), onclick: async () => {
          try { await api("/api/verdict", { finding_id: f.id, verdict: v, note: note.value }); toast(`${f.id}: ${label}`); scheduleRefresh(); } catch (e) { toast(e.message, true); }
        } }, label))),
      el("div", { css: { marginTop: "8px" } }, note)));
  }
}
function caseIocs(body, c) {
  if (!c.iocs.length) { body.append(el("div", { class: "empty", text: "No indicators recorded yet." })); return; }
  for (const i of c.iocs) {
    body.append(el("div", { class: "card", "data-ref": i.id, css: { padding: "10px 12px" } },
      el("div", { css: { display: "flex", alignItems: "center", gap: "8px" } }, el("span", { class: "label", text: i.type }),
        el("span", { class: "chip" + (i.confidence === "high" ? " red" : ""), css: { marginLeft: "auto" }, text: i.confidence }),
        el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", "aria-label": "Copy value", title: "Copy", onclick: () => copyText(i.value) }, icon("copy", 14))),
      el("div", { class: "mono", css: { marginTop: "2px", wordBreak: "break-all" }, text: i.value }),
      i.context ? el("div", { class: "muted small", text: i.context }) : null));
  }
}
function caseTimeline(body, c) {
  if (!c.timeline.length) { body.append(el("div", { class: "empty", text: "No timeline events yet." })); return; }
  let day = "";
  for (const e of c.timeline) {
    const t = String(e.event_time || "");
    const d = t.slice(0, 10);
    if (d !== day) { day = d; body.append(el("div", { class: "tl-day", text: d || "Undated" })); }
    body.append(el("div", { class: "tl-item", "data-ref": e.id }, el("span", { class: "when", text: t.slice(11, 16) || "--:--" }), el("span", { class: "pin" }),
      el("span", {}, el("div", { class: "what", text: e.description }),
        el("div", { class: "src", text: [e.host, e.source, e.attack_technique].filter(Boolean).join(" · ") }))));
  }
}
function caseEvidence(body, c) {
  const st = S.st || {};
  if (st.evidence_folder) {
    body.append(el("div", { class: "card drop-card" },
      el("div", { class: "label", text: "Drop artifacts for this case into" }),
      el("div", { class: "path-row" }, el("span", { class: "mono", text: st.evidence_folder }),
        el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", "aria-label": "Copy folder path", title: "Copy path", onclick: () => copyText(st.evidence_folder) }, icon("copy", 14))),
      el("div", { class: "muted small", text: "Subfolders disk/, memory/, logs/, network/, mobile/, triage/, other/ - types are detected by content. Files pulled from endpoints land in the evidence vault. The forensics playbook starts from both." }),
      el("div", { class: "toolbar" }, el("button", { type: "button", class: "btn btn-sm", onclick: () => setPlaybook("forensics") }, icon("list", 14), "Examine this case's evidence"))));
  }
  if (!c.evidence.length) { body.append(el("div", { class: "empty", text: "No evidence registered yet. The team registers and hashes each item before analysis." })); return; }
  for (const e of c.evidence) {
    const sha = (e.hashes && e.hashes.sha256) || "";
    body.append(el("div", { class: "card", "data-ref": e.id, css: { padding: "10px 12px" } },
      el("div", { css: { fontWeight: "500", wordBreak: "break-all" }, text: String(e.path || "").split("/").pop() }),
      el("div", { class: "mono muted", css: { fontSize: "11.5px", wordBreak: "break-all" }, text: e.path }),
      sha ? el("div", { css: { display: "flex", alignItems: "center", gap: "6px", marginTop: "4px" } },
        el("span", { class: "mono", css: { fontSize: "12px" }, text: `SHA-256 ${sha.slice(0, 12)}…${sha.slice(-6)}` }),
        el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", "aria-label": "Copy SHA-256", onclick: () => copyText(sha) }, icon("copy", 14))) : null,
      el("div", { class: "muted small", text: [e.description, e.size ? `${e.size} bytes` : null, e.acquired_by].filter(Boolean).join(" · ") })));
  }
}
function folderRow(label, path, note) {
  return [el("div", { class: "label", css: { marginTop: "6px" }, text: label }),
    el("div", { class: "path-row" }, el("span", { class: "mono", text: path }),
      el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", "aria-label": `Copy ${label.toLowerCase()} path`, title: "Copy path", onclick: () => copyText(path) }, icon("copy", 14))),
    note ? el("div", { class: "muted small", text: note }) : null];
}
function casePlans(body) {
  const P = S.plans, st = S.st || {};
  const f = (k, k2) => (P && P[k]) || st[k2 || k] || "";
  body.append(el("div", { class: "card drop-card" },
    ...folderRow("Hunt plans folder", f("folder", "plans_folder"), "The hunt planner saves plans and ATT&CK Navigator layers here. The threat hunter reads them and saves its results next to them, and hunts only when you ask."),
    ...folderRow("CTE plans folder", f("cte_folder"), "Emulation plans (plans only: nothing is run). Drop a network map in maps/ (CSV, nmap XML, draw.io, Visio .vsdx or text)."),
    ...folderRow("Reports folder", f("reports_folder"), "Report drafts, checked against the mission data, and finals you approve."),
    ...folderRow("Example reports", f("examples_folder", "report_examples_folder"), "Your old reports, one folder per type (.docx, .md, .txt). Format only: never a source of facts."),
    f("vuln_folder") ? folderRow("Vulnerability assessment folder", f("vuln_folder"), "") : [],
    el("div", { class: "toolbar" }, el("button", { type: "button", class: "btn btn-sm", onclick: () => setPlaybook("hunt_plan") }, icon("list", 14), "Plan a hunt"),
      el("button", { type: "button", class: "btn btn-sm", onclick: () => setPlaybook("cte_plan") }, icon("list", 14), "Plan an emulation"),
      el("button", { type: "button", class: "btn btn-sm", onclick: () => setPlaybook("report") }, icon("file", 14), "Write a report"),
      el("button", { type: "button", class: "btn btn-sm", onclick: () => setPlaybook("vulnerability_assessment") }, icon("shield", 14), "Assess vulnerabilities"))));
  if (!P) { body.append(el("div", { class: "empty", text: "Loading…" })); return; }
  if (!P.host.available && P.host.why) body.append(el("div", { class: "muted small plans-why", text: `Opening in an editor on the host: ${P.host.why}.` }));
  if (!P.files.length) { body.append(el("div", { class: "empty", text: "No plans or reports yet. Pick the hunt plan, emulation plan, report or vulnerability assessment playbook." })); return; }
  for (const x of P.files) body.append(planCard(x, true));
}

/* ---------------------------------------------------------------- hunt plans: view, download, open in an editor */
const PLAN_KIND = { plan: "Hunt plan", results: "Hunt results", layer: "ATT&CK Navigator layer", vuln_report: "Vulnerability report",
  cte_plan: "CTE plan", cte_results: "CTE results", report: "Report draft", report_final: "Final report", other: "File" };
const PLAN_COUNTED = new Set(["plan", "vuln_report", "cte_plan", "report", "report_final"]);
const PLAN_FILE_RE = /^(hunt_plan_|hunt_results_|attack_layer_|vuln_report_|cte_plan_|cte_results_|report_)[\w.-]+\.(md|json)$/i;
const LINK_NAMES = { vscode: "VS Code", obsidian: "Obsidian" };
async function refreshPlans() {
  try { S.plans = await api("/api/plans"); } catch (e) { return; }
  labelOpenButtons();
  if (S.insp.open && !S.insp.thread) renderInspSoon();
}
function planUrl(name, download) { return `/api/plans/${encodeURIComponent(name)}${download ? "?download=1" : ""}`; }
function planPath(name) {
  const f = S.plans && S.plans.files.find((x) => x.name.toLowerCase() === name.toLowerCase());
  const key = /^vuln_report_/i.test(name) ? "vuln_folder" : /^(cte_|attack_layer_cte_)/i.test(name) ? "cte_folder"
    : /^report_/i.test(name) ? "reports_folder" : "";
  const folder = key ? (S.plans && S.plans[key]) || (S.st && S.st[key]) || ""
    : (S.plans && S.plans.folder) || (S.st && S.st.plans_folder) || "";
  return f ? f.path : folder ? `${folder}/${name}` : name;
}
function linkUrl(kind, path) {
  const remote = S.plans && S.plans.vscode_remote;
  if (kind === "vscode") return remote ? `vscode://vscode-remote/${remote}${encodeURI(path)}` : `vscode://file${encodeURI(path)}`;
  return `obsidian://open?path=${encodeURIComponent(path)}`;
}
// The ways this browser can open a file: editors on the host (when the browser is on the host), else links that
// hand the file to VS Code / Obsidian on the viewer's own computer.
function openChoices(name) {
  const P = S.plans;
  if (!P) return [];
  if (P.host.available) return P.host.editors.map((e) => ({ key: "host:" + e.id, label: e.name, isDefault: e.default,
    end: e.default ? "default" : "", run: () => openOnHost(name, e) }));
  return (P.links || []).map((k) => ({ key: "link:" + k, label: LINK_NAMES[k] || k, end: "on your computer", run: () => openLink(k, name) }));
}
function preferredChoice(choices) { const k = pref("editor", ""); return choices.find((c) => c.key === k) || choices.find((c) => c.isDefault) || choices[0] || null; }
async function openOnHost(name, e) {
  try { await api(`/api/plans/${encodeURIComponent(name)}/open`, { editor: e.id }); toast(`Opening ${name} in ${e.name}`); }
  catch (err) { toast(err.message, true); }
}
function clickLink(href, download) { const a = el("a", { href, download, hidden: true }); document.body.append(a); a.click(); a.remove(); }
function openLink(kind, name) {
  clickLink(linkUrl(kind, planPath(name)));
  toast(kind === "obsidian" ? "Sent to Obsidian. The file must be inside one of your vaults." : `Sent to ${LINK_NAMES[kind] || kind}`);
}
function downloadPlan(name) { clickLink(planUrl(name, true), name); }
async function viewPlan(name) {
  let text;
  try { text = await api(planUrl(name)); } catch (e) { toast(e.message, true); return; }
  const dlg = openDialog({ title: name, sub: planPath(name), iconName: "file", wide: true, cls: "plan-view",
    body: [name.toLowerCase().endsWith(".json") ? el("pre", { class: "code", text }) : md(text)],
    foot: [el("span", { class: "note" }), ...planActions(name, false), el("button", { type: "button", class: "btn btn-sm", onclick: () => dlg.close() }, "Close")] });
}
function fileMenu(name) {
  const items = openChoices(name).map((c) => ({ icon: "external", label: `Open in ${c.label}`, end: c.end,
    run: () => { setPref("editor", c.key); labelOpenButtons(); c.run(); } }));
  const why = S.plans && !S.plans.host.available ? S.plans.host.why : "";
  if (why && S.plans.links && S.plans.links.length) items.push({ icon: "alert", label: `Not on the host: ${why}`, disabled: true, run: () => {} });
  if (items.length) items.push("-");
  items.push({ icon: "file", label: "View here", run: () => viewPlan(name) },
    { icon: "download", label: "Download", run: () => downloadPlan(name) },
    ...(/\.md$/i.test(name) ? [{ icon: "download", label: "Download as Word (.docx)", run: () => downloadDocx(name) }] : []),
    { icon: "copy", label: "Copy path", end: planPath(name).length > 46 ? "…" + planPath(name).slice(-45) : planPath(name), run: () => copyText(planPath(name)) });
  return items;
}
function openLabel(name) { const c = preferredChoice(openChoices(name)); return c ? `Open in ${c.label}` : "Open"; }
function labelOpenButtons() { for (const b of document.querySelectorAll("button[data-plan]")) b.lastChild.textContent = openLabel(b.dataset.plan); }
function planActions(name, withView = true) {
  const main = el("button", { type: "button", class: "btn btn-sm btn-primary", "data-plan": name, title: "Open it in your editor",
    onclick: () => { const c = preferredChoice(openChoices(name)); if (c) c.run(); else viewPlan(name); } }, icon("external", 14), document.createTextNode(openLabel(name)));
  const caret = el("button", { type: "button", class: "btn btn-sm btn-primary split-caret", "aria-label": "Open with…", title: "Open with…",
    onclick: (e) => openMenu(e.currentTarget, fileMenu(name)) }, icon("chevD", 14));
  return [el("span", { class: "split" }, main, caret),
    withView ? el("button", { type: "button", class: "btn btn-sm", onclick: () => viewPlan(name) }, icon("file", 14), "View") : null,
    el("button", { type: "button", class: "btn btn-sm", onclick: () => downloadPlan(name) }, icon("download", 14), "Download"),
    /\.md$/i.test(name) ? el("button", { type: "button", class: "btn btn-sm", title: "Download as a Word document", onclick: () => downloadDocx(name) }, icon("download", 14), ".docx") : null,
    el("button", { type: "button", class: "btn btn-ghost icon-btn btn-sm", "aria-label": "Copy path", title: "Copy path", onclick: () => copyText(planPath(name)) }, icon("copy", 14))].filter(Boolean);
}
function planCard(f, inPanel) {
  const meta = inPanel ? [f.mtime ? fmtRel(f.mtime) : null, f.kind === "plan" ? (f.hunted ? "hunted" : "not hunted yet") : null,
    f.edited ? "edited by you" : null].filter(Boolean).join(" · ") : "";
  return el("div", { class: "file-card" + (inPanel ? " in-panel" : "") },
    el("div", { class: "head" }, el("span", { class: "ic" }, icon("file", 16)), el("span", { class: "kind", text: PLAN_KIND[f.kind] || "File" }),
      el("span", { class: "mono name", title: f.path || f.name, text: f.name })),
    f.title ? el("div", { class: "title", text: f.title }) : null,
    f.kind === "layer" ? el("div", { class: "muted small", text: "Download it, then in ATT&CK Navigator: Open Existing Layer, Upload from local." }) : null,
    meta ? el("div", { class: "muted small", text: meta }) : null,
    el("div", { class: "toolbar" }, ...planActions(f.name)));
}
// A plan file named in agent text becomes a link that opens the same menu.
function fileRef(text) {
  const base = String(text).split("/").pop();
  if (!PLAN_FILE_RE.test(base)) return null;
  const n = el("span", { class: "file-ref", role: "button", tabindex: "0", title: "Open, view or download this file" }, icon("file", 12), text);
  const go = (e) => { e.preventDefault(); e.stopPropagation(); openMenu(n, fileMenu(base)); };
  n.addEventListener("click", go);
  n.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") go(e); });
  return n;
}

async function caseReport(body) {
  const ask = el("button", { type: "button", class: "btn btn-sm", onclick: () => setPlaybook("report") }, "Ask the reporter to draft it");
  try {
    const r = await api("/api/report?format=json");
    if (!r.text) {
      body.append(el("div", { class: "empty" }, el("div", { css: { fontWeight: "500", color: "var(--text)" }, text: "No report yet" }),
        el("p", { text: "The reporter drafts it from this mission's data only, cites every fact, and asks you for anything missing." }), ask));
      return;
    }
    const v = /_v(\d+)\.md$/.exec(r.name || "");
    body.append(el("div", { class: "muted small", text: r.final ? `Final report · ${r.name}` : r.name ? `Draft v${v ? v[1] : "?"} · ${r.name} · not yet approved as final` : "report.md" }),
      el("div", { class: "toolbar" }, r.final ? null : ask,
        r.name ? el("button", { type: "button", class: "btn btn-sm", onclick: () => downloadDocx(r.name) }, icon("download", 14), "Word (.docx)") : null,
        el("button", { type: "button", class: "btn btn-sm", onclick: () => copyText(r.text) }, icon("copy", 14), "Copy")),
      el("p", { class: "muted small", text: "Each citation, like [FIN-0001], opens the mission data it points at." }),
      md(r.text));
  } catch (e) { body.append(el("div", { class: "empty", text: e.message })); }
}
function downloadDocx(name) { clickLink(`/api/plans/${encodeURIComponent(name)}/docx`, name.replace(/\.md$/i, ".docx")); toast("Exporting to Word"); }
function renderThread(box, s) {
  const run = s.status === "running";
  box.append(el("div", { class: "insp-head" },
    el("button", { type: "button", class: "btn btn-ghost icon-btn", "aria-label": "Back to the case", title: "Back to the case", onclick: () => { S.insp.thread = null; renderInsp(); } }, icon("chevL")),
    el("div", { class: "t" }, el("strong", { text: `${s.id} · ${shortTitle(s.title)}` }),
      el("span", { class: "muted small" }, s.expert, " · ", el("span", { "data-elapsed": s.id, text: elapsedText(s) }))),
    statusChip(s.status), inspClose()));
  const body = el("div", { class: "insp-body" });
  box.append(body);
  body.append(el("div", { class: "thread-sec" }, el("div", { class: "label", text: "Task from the lead" }), el("div", { css: { fontSize: "13px" }, text: s.task || "" })));
  if (run) {
    const ta = el("textarea", { id: "steer-input", class: "field", rows: 2, placeholder: "Guidance for this subagent, delivered before its next step", "aria-label": "Guidance for the subagent",
      value: S.steerDrafts.get(s.id) || "", oninput: () => S.steerDrafts.set(s.id, ta.value) });
    body.append(el("div", { class: "card thread-sec" },
      el("div", { class: "label", text: "Steer" }), ta,
      el("div", { class: "toolbar" },
        el("button", { type: "button", class: "btn btn-primary btn-sm", onclick: async () => {
          const m = ta.value.trim(); if (!m) return;
          try { await api(`/api/subagents/${encodeURIComponent(s.id)}/steer`, { message: m }); ta.value = ""; S.steerDrafts.delete(s.id); toast(`Guidance queued for ${s.id}`); } catch (e) { toast(e.message, true); }
        } }, icon("steer", 14), "Send guidance"), stopButton(s))));
  }
  if (isWaiting(s)) {
    const p = [...S.pending.values()].find((x) => agentOf(x.why) === s.expert);
    body.append(el("div", { class: "approval" }, el("div", { class: "head" }, icon("shield", 18), el("strong", { text: `Waiting for your approval · ${toolLabel(p.tool)}` })),
      el("div", { class: "toolbar" }, el("button", { type: "button", class: "btn btn-primary btn-sm", onclick: () => openApproval(p.id) }, "Review"))));
  }
  const acts = el("div", { class: "thread-sec" }, el("div", { class: "label", text: "Activity" }));
  const list = el("div", { class: "work", css: { padding: "4px" } });
  const pend = new Map();
  let shown = 0;
  for (const e of s.events) {
    const d = e.d;
    if (e.kind === "decision") {
      if (d.tool === "submit_report") continue;
      const st = threadRow(list, toolIcon(d.tool), toolLabel(d.tool), argSummary(d.args), !d.allowed, (x) => toolDetail(x));
      st.args = d.args; st.decision = d; shown++;
      if (!d.allowed) setEnd(st, el("span", { class: "chip red", text: "Not run" }));
      else { setEnd(st, tierChip(d.tier), el("span", { class: "spin" })); queuePending(pend, "x", d.tool, st); }
    } else if (e.kind === "result") {
      const st = takePending(pend, "x", d.tool);
      if (st) { st.result = d; setEnd(st, tierChip(st.decision.tier), d.error ? el("span", { class: "chip red", text: "Error" }) : el("span", { text: `${d.seconds} s` })); }
    } else if (e.kind === "text") { threadRow(list, "chat", firstLine(d.text, 200), "", false, d.text.length > 200 ? () => md(d.text) : null, true); shown++; }
    else if (e.kind === "skill_used") { threadRow(list, "book", `Loaded skill ${d.skill}`, `v${d.version}`); shown++; }
    else if (e.kind === "skill_proposed") { threadRow(list, "book", `Proposed skill ${d.skill} v${d.version}`, d.change_note || ""); shown++; }
    else if (e.kind === "steer") { threadRow(list, "steer", "Your guidance", firstLine(d.message, 200)); shown++; }
    else if (e.kind === "message") { threadRow(list, "chat", "Follow-up from the lead", firstLine(d.message, 200), false, () => md(d.message)); shown++; }
  }
  const lv = S.live.get(s.id);
  if (!shown && lv && lv.text) list.hidden = true; // nothing logged yet: the live text below is all there is
  else if (!shown) list.append(el("div", { class: "muted small", css: { padding: "8px 10px" }, text: run ? "Starting…" : "No activity was recorded in this session for this subagent." }));
  S.ui.threadLive = el("div", { class: "thread-live", "aria-hidden": "true", hidden: true });
  acts.append(list, S.ui.threadLive); body.append(acts);
  renderThreadLiveSoon();
  if (s.report) {
    const r = s.report;
    const parts = [r.summary || ""];
    if (r.details) parts.push("", r.details);
    if ((r.open_questions || []).length) parts.push("", "**Open questions**", ...r.open_questions.map((q) => `- ${q}`));
    if ((r.recommended_tasks || []).length) parts.push("", "**Recommended tasks**", ...r.recommended_tasks.map((t) => `- ${t.expert || "any"}: ${t.task}`));
    if ((r.skills_used || []).length) parts.push("", "**Skills used**", ...r.skills_used.map((u) => `- ${u.name}: ${u.worked ? "worked" : "did not work"} ${u.note || ""}`));
    body.append(el("div", { class: "thread-sec" }, el("div", { class: "label", text: `Report · ${r.status}${r.confidence && r.confidence !== "unstated" ? " · confidence " + r.confidence : ""}` }),
      el("div", { class: "card" }, md(parts.join("\n")))));
  }
  if (!run) {
    body.append(el("div", { class: "thread-sec" }, el("div", { class: "muted small", text: `${s.id} keeps its context. Ask the lead to follow up with it to continue this line of work.` }),
      el("div", {}, el("button", { type: "button", class: "btn btn-sm", onclick: () => { S.ui.input.value = `Follow up with ${s.id}: `; onComposerInput(); S.ui.input.focus(); } }, icon("chat", 14), "Follow up"))));
  }
}
function threadRow(list, ic, what, detail, denied, body, note) {
  const expandable = typeof body === "function";
  const asButton = expandable && !note;
  const row = el(asButton ? "button" : "div", { class: "step" + (denied ? " denied" : "") + (note ? " note" : "") + (expandable ? " expandable" : ""), type: asButton ? "button" : null, "aria-expanded": asButton ? "false" : null });
  const st = { row, end: el("span", { class: "end" }), bodyEl: null };
  row.append(...[el("span", { class: "ic" }, icon(ic)), note ? el("span", { class: "what" }, inline(what)) : el("span", { class: "what", text: what }),
    note ? null : el("span", { class: "detail", text: detail || "" }), st.end].filter(Boolean));
  const toggle = expandable && note ? el("button", { type: "button", class: "chev-btn", "aria-expanded": "false", "aria-label": "Show the full text" }, icon("chevR", 14)) : null;
  if (toggle) row.append(toggle);
  const wrap = el("div", {}, row);
  if (expandable) row.addEventListener("click", (e) => {
    if (toggle && e.target.closest(".file-ref, .cite")) return;
    const open = !st.bodyEl;
    if (!open) { st.bodyEl.remove(); st.bodyEl = null; } else { st.bodyEl = el("div", { class: "step-body" }, body(st)); wrap.append(st.bodyEl); }
    (toggle || row).setAttribute("aria-expanded", String(open)); row.classList.toggle("open", open);
  });
  list.append(wrap);
  return st;
}

/* ================================================================ pages */
const VIEWS = ["ops", "skills", "memory", "audit", "roe", "connectors", "settings"];
function route() { const m = /^#\/(\w+)/.exec(location.hash); go(m && VIEWS.includes(m[1]) ? m[1] : "ops", false); }
function go(view, push = true) {
  if (push) { const h = view === "ops" ? "#/" : "#/" + view; if (location.hash !== h) history.pushState(null, "", h); }
  S.view = view;
  $("view-ops").hidden = view !== "ops";
  $("view-page").hidden = view === "ops";
  $("side").classList.remove("open");
  renderSide(); renderInsp();
  if (view !== "ops") renderPage(view);
}
async function renderPage(view) {
  const box = $("view-page");
  const focus = captureFocus(box);
  const root = clear(box);
  const inner = el("div", { class: "page-inner" });
  root.append(el("div", { class: "page" }, inner));
  try { await PAGES[view](inner); } catch (e) { inner.append(el("div", { class: "empty", text: "Could not load this page: " + e.message })); }
  restoreFocus(box, focus);
}
function pageHead(title, sub, ...actions) {
  return el("div", { class: "page-head" }, el("div", { class: "t" }, el("h1", { text: title }), sub ? el("p", { text: sub }) : null), actions);
}
function parseDiff(text) {
  const out = [];
  for (const ln of String(text || "").split("\n")) {
    if (ln.startsWith("+++") || ln.startsWith("---")) continue;
    if (ln.startsWith("@@")) out.push(["hunk", "", ln]);
    else if (ln.startsWith("+")) out.push(["add", "+", ln.slice(1)]);
    else if (ln.startsWith("-")) out.push(["del", "−", ln.slice(1)]);
    else if (ln.length) out.push(["", "", ln.slice(1)]);
  }
  return out;
}
function recordBar(s) {
  const total = s.successes + s.failures;
  return el("span", { class: "bar" + (total ? "" : " none") }, el("span", { css: { width: (total ? Math.round(100 * s.successes / total) : 0) + "%" } }));
}
const PAGES = {
  async skills(root) {
    const data = await api("/api/skills");
    const weak = data.skills.filter((s) => s.needs_revision);
    root.append(pageHead("Skills", "Procedures the team wrote and refined during earlier operations. " +
      (data.require_approval ? "Skills written by agents are used only after you approve them." : "Auto-approve is on: agent-written skills are used immediately."),
      el("span", { class: "muted small", text: "Import or export SKILL.md files with: canarchist skills import|export" })));
    const tabs = [["review", "Needs review", data.pending.length], ["all", "All skills", data.skills.length], ["weak", "Needs revision", weak.length]];
    root.append(tabList("Skills", "skills", tabs.map(([id, label, n]) => [id, label, el("span", { class: "count" + (id === "review" && n ? " warn" : ""), "aria-label": `(${n})`, text: n })]),
      S.skillsTab, (id) => { S.skillsTab = id; renderPage("skills"); }));
    const panel = el("div", { role: "tabpanel", id: "skills-panel", "aria-labelledby": `skills-tab-${S.skillsTab}`, class: "tab-panel" });
    root.append(panel);
    if (S.skillsTab === "review") skillsReview(panel, data);
    else if (S.skillsTab === "all") skillsAll(panel, data.skills);
    else skillsWeak(panel, weak);
  },
  async memory(root) {
    root.append(pageHead("Memory", "What the team has learned about your environment: facts, proven queries, false-positive patterns, observed tradecraft and lessons. Agent-written memories are used only after you promote them."));
    const statuses = [["candidate", "Candidates"], ["approved", "Approved"], ["rejected", "Rejected"], ["retired", "Retired"], ["", "All"]];
    root.append(el("div", {}, el("div", { class: "seg", role: "group", "aria-label": "Status" }, statuses.map(([v, label]) =>
      el("button", { type: "button", class: S.memStatus === v ? "on" : "", "aria-pressed": String(S.memStatus === v), onclick: () => { S.memStatus = v; renderPage("memory"); } }, label)))));
    const kind = el("select", { class: "field", "aria-label": "Kind" }, (S.st.memory_kinds || []).map((k) => el("option", { value: k, text: k })));
    const title = el("input", { type: "text", placeholder: "Title, specific and searchable", "aria-label": "Title" });
    const content = el("textarea", { class: "field", rows: 3, placeholder: "The knowledge, self-contained", "aria-label": "Content" });
    root.append(el("details", { class: "card" }, el("summary", { css: { cursor: "pointer", fontWeight: "500" }, text: "Add knowledge (approved immediately)" }),
      el("div", { css: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px" } }, el("div", { class: "toolbar" }, kind, el("div", { css: { flex: "1" } }, title)), content,
        el("div", {}, el("button", { type: "button", class: "btn btn-primary btn-sm", onclick: async () => {
          try { await api("/api/remember", { kind: kind.value, title: title.value, content: content.value }); toast("Saved"); renderPage("memory"); } catch (e) { toast(e.message, true); }
        } }, "Save")))));
    const rows = await api("/api/memory?status=" + encodeURIComponent(S.memStatus));
    if (!rows.length) { root.append(el("div", { class: "empty", text: "Nothing here." })); return; }
    const list = el("div", { css: { display: "flex", flexDirection: "column", gap: "10px" } });
    for (const m of rows) {
      const act = (a, label, cls) => el("button", { type: "button", class: "btn btn-sm " + (cls || ""), onclick: async () => {
        try { await api("/api/memory/" + m.id, { action: a }); renderPage("memory"); scheduleRefresh(); } catch (e) { toast(e.message, true); } } }, label);
      list.append(el("div", { class: "card" },
        el("div", { css: { display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" } }, el("span", { class: "mono muted", text: `M${m.id}` }), el("strong", { text: m.title }),
          el("span", { class: "chip", css: { marginLeft: "auto" }, text: m.kind })),
        el("div", { class: "muted small", text: `${m.status} · from ${m.source}${m.case_id ? " in " + m.case_id : ""} · helpful ${m.helpful}, misleading ${m.unhelpful} · used ${m.uses}` }),
        el("div", { css: { whiteSpace: "pre-wrap", fontSize: "13px", margin: "8px 0" }, text: m.content }),
        el("div", { class: "toolbar" }, m.status !== "approved" ? act("promote", "Promote", "btn-primary") : null,
          m.status !== "rejected" ? act("reject", "Reject", "btn-danger") : null, m.status === "approved" ? act("retire", "Retire") : null)));
    }
    root.append(list);
  },
  async audit(root) {
    const a = await api("/api/audit?limit=500");
    S.audit = a; renderSide();
    root.append(pageHead("Audit log", "Every tool decision, approval, verdict, skill and memory review, sign-in and deletion, hash-chained so any edit or removal is detected."),
      el("div", { class: "card", css: { display: "flex", alignItems: "center", gap: "10px", borderColor: a.verified ? "var(--line)" : "var(--red-line)", color: a.verified ? "var(--ok)" : "var(--red-hi)" } },
        icon(a.verified ? "check" : "alert", 18), el("span", { css: { fontWeight: "500" }, text: a.message })));
    const tb = el("tbody");
    for (const r of a.records) {
      const d = r.data || {};
      const detail = d.tool ? `${d.agent_id || d.agent || ""} ${d.tool}${d.tier ? " [" + d.tier + "]" : ""}${d.allowed === false ? " DENIED " + (d.reason || "") : ""}` : JSON.stringify(d).slice(0, 240);
      tb.append(el("tr", {}, el("td", { class: "mono", css: { whiteSpace: "nowrap" }, text: String(r.ts).replace("T", " ").slice(0, 19) }),
        el("td", { text: r.event }), el("td", { text: r.operator }), el("td", { css: { wordBreak: "break-word" }, text: detail })));
    }
    root.append(el("div", { class: "table-box" }, el("table", { class: "list" }, el("thead", {}, el("tr", {}, ["Time (UTC)", "Event", "Operator", "Detail"].map((h) => el("th", { text: h })))), tb)));
  },
  async roe(root) {
    const rows = await api("/api/tools");
    const respond = S.st.posture === "respond";
    root.append(pageHead("Rules of engagement", `Posture ${respond ? "RESPOND" : "OBSERVE"}. Every tool call is classified before it runs: auto runs, notify runs and is flagged, approve waits for an analyst, deny never runs. Rules live in config/roe.yaml.`));
    const filter = el("input", { type: "search", placeholder: "Filter tools", value: S.roeFilter, "aria-label": "Filter tools" });
    const tb = el("tbody");
    const draw = () => {
      clear(tb); const f = S.roeFilter.toLowerCase();
      for (const r of rows.filter((r) => !f || r.name.toLowerCase().includes(f) || r.tier.includes(f))) {
        tb.append(el("tr", {}, el("td", {}, el("span", { class: "tier " + r.tier, text: r.tier })), el("td", { class: "mono", title: r.description, text: r.name }), el("td", { class: "muted", text: r.why })));
      }
    };
    filter.addEventListener("input", () => { S.roeFilter = filter.value; draw(); });
    draw();
    root.append(el("div", { css: { maxWidth: "360px" } }, filter),
      el("div", { class: "table-box" }, el("table", { class: "list" }, el("thead", {}, el("tr", {}, ["Tier", "Tool", "Rule"].map((h) => el("th", { text: h })))), tb)));
  },
  async connectors(root) {
    const tools = await api("/api/tools");
    root.append(pageHead("Connectors", "MCP servers the harness launched for this session, and the tools each one gave the team. Configure them in config/harness.yaml."));
    const grid = el("div", { class: "grid-cards" });
    const names = Object.keys(S.st.connectors || {});
    if (!names.length) root.append(el("div", { class: "empty", text: "No connectors are enabled in harness.yaml." }));
    for (const n of names) {
      const status = String(S.st.connectors[n]);
      const ok = status.startsWith("connected");
      const mine = tools.filter((t) => t.server === n);
      grid.append(el("div", { class: "card", css: { display: "flex", flexDirection: "column", gap: "8px" } },
        el("div", { css: { display: "flex", alignItems: "center", gap: "8px" } }, el("span", { class: "dot " + (ok ? "ok" : "red") }), el("strong", { text: SERVER_NAMES[n] || n }),
          el("span", { class: "mono muted", css: { marginLeft: "auto", fontSize: "11.5px" }, text: n })),
        el("div", { class: "small", css: { color: ok ? "var(--text-3)" : "var(--red-hi)" }, text: status }),
        mine.length ? el("details", {}, el("summary", { class: "small", css: { cursor: "pointer" }, text: plural(mine.length, "tool") }),
          el("div", { css: { display: "flex", flexDirection: "column", gap: "4px", marginTop: "8px" } }, mine.map((t) =>
            el("div", { css: { display: "flex", alignItems: "center", gap: "8px", fontSize: "12.5px" } }, el("span", { class: "tier " + t.tier, text: t.tier }), el("span", { class: "mono ellipsis", title: t.description, text: t.name.split("__")[1] || t.name }))))) : null));
    }
    root.append(grid);
  },
  async settings(root) {
    try { applyState(await api("/api/state")); } catch (e) { /* render what we have */ } // picks up edits to models.yaml
    const st = S.st;
    root.append(pageHead("Settings", "The theme is stored in this browser. The classification banner applies to everyone using this dashboard. Models live in config/models.yaml; other server settings in config/harness.yaml and config/roe.yaml."));
    const mode = pref("theme", "dark");
    const seg = el("div", { class: "seg", role: "group", "aria-label": "Theme" }, [["dark", "Dark"], ["light", "Light"], ["system", "Match system"]].map(([v, label]) =>
      el("button", { type: "button", class: mode === v ? "on" : "", "aria-pressed": String(mode === v), onclick: () => { applyTheme(v); renderPage("settings"); } }, label)));
    root.append(el("div", { class: "card form-grid" },
      el("span", { class: "label", text: "Theme" }), el("div", {}, seg),
      el("span", { class: "label", text: "Operator" }), el("span", { text: st.operator }),
      el("span", { class: "label", text: "Case" }), el("span", { text: st.case.id }),
      el("span", { class: "label", text: "Posture" }), el("span", { text: st.posture.toUpperCase() + " (set at start with --posture)" }),
      el("span", { class: "label", text: "Session" }), el("span", { class: "mono", text: st.session }),
      el("span", { class: "label", text: "Version" }), el("span", { text: `${st.ui.name} ${st.ui.version}` })));
    try { root.append(runSettings(await api("/api/settings/startup"))); } catch (e) { root.append(el("div", { class: "empty", text: "Could not load the posture, address and case settings: " + e.message })); }
    root.append(classificationSettings());
    root.append(modelSettings(st));
    root.append(el("h2", { css: { fontSize: "15px" }, text: "Keyboard shortcuts" }), shortcutsTable());
  },
};
/* ---------------------------------------------------------------- model profiles (config/models.yaml) */
function modelSettings(st) {
  const box = el("section", { class: "settings-sec" });
  const files = st.models_files || [];
  box.append(el("h2", { css: { fontSize: "15px" }, text: "Models" }),
    el("p", { class: "muted small", css: { margin: "0 0 8px" } },
      "The model picker lists the profiles in ", el("code", { text: files[0] || "config/models.yaml" }),
      files[1] ? [" and your site file ", el("code", { text: files[1] })] : null,
      ". Edit them to add, change or remove models; changes show up here without a restart. API keys go in ", el("code", { text: "config/.env" }), ", referenced as ${VAR}."));
  if (st.models_error) box.append(el("div", { class: "card warn-card" }, el("strong", { text: "Your last edit was not applied: " }), el("span", { class: "mono", text: st.models_error }),
    el("div", { class: "muted small", text: "The dashboard keeps using the profiles from before that edit. Fix the file and reopen this page." })));
  const tb = el("tbody");
  for (const [g, list] of modelGroups(st.models)) {
    tb.append(el("tr", { class: "group-row" }, el("td", { colspan: "5", text: g })));
    for (const m of list) tb.append(el("tr", {},
      el("td", {}, m.name === st.model ? el("span", { class: "chip red", text: "lead" }) : null),
      el("td", {}, el("div", { text: m.label }), el("div", { class: "mono muted", css: { fontSize: "11.5px" }, text: m.name })),
      el("td", { text: m.provider }), el("td", { class: "mono", text: m.model }),
      el("td", {}, m.ready ? el("span", { class: "chip ok", text: "ready" }) : el("span", { class: "chip warn", title: m.problem, text: "needs setup" }),
        m.ready ? null : el("div", { class: "muted small", text: m.problem }))));
  }
  box.append(el("div", { class: "table-box" }, el("table", { class: "list" }, el("thead", {}, el("tr", {}, ["", "Profile", "Provider", "Model", "Status"].map((h) => el("th", { text: h })))), tb)));
  return box;
}

/* ---------------------------------------------------------------- posture, address and case (live) */
// Changed here while it runs; each change is audited and becomes the default scripts/start.sh offers next time.
function runSettings(info) {
  const now = info.now, busy = info.running;
  const seg = (items, current, onPick, disabled) => el("div", { class: "seg", role: "group" }, items.map(([v, label]) =>
    el("button", { type: "button", class: current === v ? "on" : "", disabled: disabled || current === v, "aria-pressed": String(current === v), onclick: () => onPick(v) }, label)));

  const posture = seg([["observe", "Observe"], ["respond", "Respond"]], now.posture, (v) => {
    const go = async () => {
      try { await api("/api/settings/posture", { posture: v }); toast(v === "respond" ? "Posture is now RESPOND" : "Posture is now OBSERVE"); await refreshState(); renderPage("settings"); }
      catch (e) { toast(e.message, true); }
    };
    if (v !== "respond") { go(); return; }
    const dlg = openDialog({ title: "Switch to RESPOND?", iconName: "shield",
      body: [el("p", { css: { margin: "0" }, text: "Response actions (containment, collection, quarantine and the like) become possible. Each one still needs your approval and passes the rules of engagement." })],
      foot: [el("span", { class: "note", text: "Recorded in the audit log." }), el("button", { type: "button", class: "btn", onclick: () => dlg.close() }, "Cancel"),
        el("button", { type: "button", class: "btn btn-primary", onclick: () => { dlg.close(); go(); } }, "Switch to RESPOND")] });
  });

  const local = now.address === "127.0.0.1";
  const address = seg([["auto", `Main address ${info.main_address}`], ["127.0.0.1", "This host only"]], now.address, (v) => {
    const url = v === "127.0.0.1" ? `http://127.0.0.1:${info.port}` : `https://${info.main_address}:${info.port}`;
    const remote = !["127.0.0.1", "localhost", "[::1]"].includes(location.hostname);
    const dlg = openDialog({ title: "Move the dashboard?", sub: url, iconName: "globe",
      body: [el("p", { css: { margin: "0" }, text: `It restarts in place on ${url}. That takes 10-20 seconds while the connectors reconnect; a running operation must be stopped first.` }),
        el("p", { css: { margin: "0" }, text: "The access token from this start stays valid. Sign in again at the new address with it and your username and password." }),
        v === "127.0.0.1" && remote ? el("p", { class: "form-error", css: { margin: "0" }, text: `You are browsing from another computer (${location.hostname}). After the move only a browser on the host itself can reach the dashboard.` }) : null],
      foot: [el("span", { class: "note", text: "Recorded in the audit log." }), el("button", { type: "button", class: "btn", onclick: () => dlg.close() }, "Cancel"),
        el("button", { type: "button", class: "btn btn-primary", onclick: async () => {
          try { const r = await api("/api/settings/address", { address: v }); dlg.close(); movingTo(r.url); }
          catch (e) { toast(e.message, true); }
        } }, "Move it")] });
  }, busy || !info.can_move);

  const pick = el("select", { class: "field", id: "run-case", "aria-label": "Case", disabled: busy },
    info.cases.map((c) => el("option", { value: c, text: c === now.case ? `${c} (open now)` : c })));
  pick.value = now.case;
  const fresh = el("input", { type: "text", id: "run-case-new", placeholder: "or a new case id", maxlength: "64", autocomplete: "off", disabled: busy });
  const switchBtn = el("button", { type: "button", class: "btn", disabled: true }, "Switch case");
  const target = () => (fresh.value.trim() || pick.value);
  const sync = () => { switchBtn.disabled = busy || target() === now.case; };
  pick.addEventListener("change", sync); fresh.addEventListener("input", sync);
  switchBtn.addEventListener("click", async () => {
    switchBtn.disabled = true; switchBtn.textContent = "Switching…";
    try { await api("/api/settings/case", { case: target() }); location.reload(); }
    catch (e) { toast(e.message, true); switchBtn.textContent = "Switch case"; sync(); }
  });

  return el("section", { class: "card settings-sec", "aria-labelledby": "run-h" },
    el("div", { class: "sec-head" },
      el("h2", { id: "run-h", text: "Posture, address and case" }),
      el("p", { text: "Change them while it runs. Every change is recorded in the audit log and becomes the default scripts/start.sh offers next time." })),
    el("div", { class: "form-grid" },
      el("span", { class: "label", text: "Posture" }),
      el("div", {}, posture, el("div", { class: "muted small", css: { marginTop: "6px" }, text: "Observe: watch and investigate; response actions are refused. Respond: response actions are allowed, each with your approval. Applies at once." })),
      el("span", { class: "label", text: "Address" }),
      el("div", {}, address, el("div", { class: "muted small", css: { marginTop: "6px" },
        text: !info.can_move ? "Started without scripts/start.sh: restart it with the address you want." : `Now ${now.url || (local ? "this host only" : "the main address")}. Moving restarts the dashboard in place; the access token stays the same.` })),
      el("label", { class: "label", for: "run-case", text: "Case" }),
      el("div", {}, el("div", { class: "path-row" }, pick, fresh, switchBtn),
        el("div", { class: "muted small", css: { marginTop: "6px" }, text: busy ? "Stop the running operation to switch case." : "The other case's files stay as they are. Connectors reconnect for a few seconds; you stay signed in." }))),
    el("div", { class: "sec-foot" }, el("span", { class: "note", text: `Next start offers: ${info.defaults.posture.toUpperCase()} · ${info.defaults.address === "127.0.0.1" ? "this host only" : "main address"} · case ${info.defaults.case}` })));
}
function movingTo(url) {
  openDialog({ title: "Moving the dashboard", sub: url, iconName: "globe",
    body: [el("p", { css: { margin: "0" }, text: "Restarting on the new address. This page will open the sign-in page there in about 20 seconds." }),
      el("p", { css: { margin: "0" } }, "If it does not, open ", el("a", { href: url + "/login", text: url + "/login" }), " yourself. Use this start's access token with your username and password.")] });
  setTimeout(() => location.replace(url + "/login"), 20000);
}

/* ---------------------------------------------------------------- classification banner setting */
// Common US banner colors. Picking one fills the text and colors; the text stays editable (e.g. SECRET//NOFORN).
const MARKINGS = [
  { id: "off", label: "Off", text: "", background: "#007a33", color: "#ffffff" },
  { id: "u", label: "Unclassified", text: "UNCLASSIFIED", background: "#007a33", color: "#ffffff" },
  { id: "cui", label: "CUI", text: "CUI", background: "#502b85", color: "#ffffff" },
  { id: "c", label: "Confidential", text: "CONFIDENTIAL", background: "#0033a0", color: "#ffffff" },
  { id: "s", label: "Secret", text: "SECRET", background: "#c8102e", color: "#ffffff" },
  { id: "ts", label: "Top Secret", text: "TOP SECRET", background: "#ff8c00", color: "#000000" },
  { id: "sci", label: "Top Secret//SCI", text: "TOP SECRET//SCI", background: "#fce83a", color: "#000000" },
];
function markingOf(v) {
  if (!v.text) return "off";
  const m = MARKINGS.find((x) => x.text && x.background === v.background.toLowerCase() && x.color === v.color.toLowerCase()
    && (v.text === x.text || v.text.startsWith(x.text + "//")));
  return m ? m.id : "custom";
}
function contrastRatio(a, b) {
  const lum = (hex) => {
    const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
  };
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
function classificationSettings() {
  const ui = S.st.ui;
  const saved = ui.classification || { text: "", background: "#007a33", color: "#ffffff" };
  const locked = ui.classification_source === "locked";
  const v = { ...(S.clsDraft || saved) };
  const same = (a, b) => a.text === b.text && a.background.toLowerCase() === b.background.toLowerCase() && a.color.toLowerCase() === b.color.toLowerCase();

  const select = el("select", { class: "field", id: "cls-marking", "aria-label": "Marking", disabled: locked },
    MARKINGS.map((m) => el("option", { value: m.id, text: m.label })), el("option", { value: "custom", text: "Custom" }));
  const text = el("input", { type: "text", id: "cls-text", maxlength: "120", placeholder: "e.g. SECRET//NOFORN", autocomplete: "off", disabled: locked, value: v.text });
  const bg = el("input", { type: "color", id: "cls-bg", "aria-label": "Banner color", disabled: locked, value: v.background });
  const fg = el("input", { type: "color", id: "cls-fg", "aria-label": "Text color", disabled: locked, value: v.color });
  const bgHex = el("span", { class: "mono small" }), fgHex = el("span", { class: "mono small" });
  const contrast = el("span");
  const top = el("div", { class: "cls-banner" }), bottom = el("div", { class: "cls-banner" });
  const mock = el("div", { class: "cls-mock", "aria-hidden": "true" }, top, el("div", { class: "body", text: "Every page of the dashboard, sign-in included" }), bottom);
  const save = el("button", { type: "button", class: "btn btn-primary", disabled: true }, "Save banner");
  const revert = el("button", { type: "button", class: "btn", hidden: true }, "Discard changes");
  const reset = el("button", { type: "button", class: "btn btn-ghost", hidden: locked || ui.classification_source !== "settings",
    title: "Remove the setting saved here and use dashboard.classification from config/harness.yaml" }, "Use the config file default");

  function sync() {
    select.value = markingOf(v);
    bgHex.textContent = v.background; fgHex.textContent = v.color;
    for (const b of [top, bottom]) {
      b.textContent = v.text || "No banner"; b.style.background = v.text ? v.background : "transparent"; b.style.color = v.text ? v.color : "var(--text-3)";
      b.classList.toggle("off", !v.text);
    }
    const r = contrastRatio(v.background, v.color);
    clear(contrast);
    if (v.text) contrast.append(el("span", { class: "chip " + (r >= 4.5 ? "ok" : "warn"), title: "WCAG AA needs at least 4.5:1 for this text size",
      text: `${r >= 4.5 ? "Contrast" : "Low contrast"} ${r.toFixed(1)}:1` }));
    const dirty = !same(v, saved);
    S.clsDraft = dirty ? { ...v } : null;
    save.disabled = locked || !dirty; revert.hidden = !dirty;
  }
  select.addEventListener("change", () => {
    const m = MARKINGS.find((x) => x.id === select.value);
    if (m) { v.text = m.text; v.background = m.background; v.color = m.color; text.value = v.text; bg.value = v.background; fg.value = v.color; }
    else text.focus();
    sync();
  });
  text.addEventListener("input", () => { v.text = text.value.replace(/\s+/g, " ").trimStart(); sync(); });
  bg.addEventListener("input", () => { v.background = bg.value; sync(); });
  fg.addEventListener("input", () => { v.color = fg.value; sync(); });
  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      const r = await api("/api/settings/classification", { text: v.text.trim(), background: v.background, color: v.color });
      S.clsDraft = null; ui.classification = r.classification; ui.classification_source = r.source;
      applyClassification(r.classification);
      toast(r.classification.text ? "Banner updated for everyone using this dashboard" : "Banner turned off for everyone using this dashboard");
      renderPage("settings");
    } catch (e) { toast(e.message, true); sync(); }
  });
  revert.addEventListener("click", () => { S.clsDraft = null; renderPage("settings"); });
  reset.addEventListener("click", async () => {
    try {
      const r = await api("/api/settings/classification", { reset: true });
      S.clsDraft = null; ui.classification = r.classification; ui.classification_source = r.source;
      applyClassification(r.classification); toast("Using the banner from config/harness.yaml"); renderPage("settings");
    } catch (e) { toast(e.message, true); }
  });
  sync();

  const source = locked ? "Locked by config/harness.yaml (dashboard.classification.locked). Change it there."
    : ui.classification_source === "settings" ? "Set on this page. It overrides dashboard.classification in config/harness.yaml."
      : "Using dashboard.classification from config/harness.yaml.";
  return el("section", { class: "card settings-sec", "aria-labelledby": "cls-h" },
    el("div", { class: "sec-head" },
      el("h2", { id: "cls-h", text: "Classification banner" }),
      el("p", { text: "Shown at the top and bottom of every page, sign-in included, for everyone who uses this dashboard. Changes are recorded in the audit log." })),
    el("div", { class: "form-grid" },
      el("label", { class: "label", for: "cls-marking", text: "Marking" }), el("div", {}, select),
      el("label", { class: "label", for: "cls-text", text: "Banner text" }), text,
      el("span", { class: "label", text: "Colors" }),
      el("div", { class: "swatches" },
        el("label", {}, bg, "Banner", bgHex), el("label", {}, fg, "Text", fgHex), contrast),
      el("span", { class: "label", text: "Preview" }), mock),
    el("div", { class: "sec-foot" }, el("span", { class: "note", text: source }), reset, revert, save));
}

function skillsReview(root, data) {
  if (!data.pending.length) { root.append(el("div", { class: "empty", text: "Nothing waiting for review. Proposals appear here as subagents write and revise skills." })); return; }
  if (!data.pending.some((v) => v.id === S.skillsSel)) S.skillsSel = data.pending[0].id;
  const v = data.pending.find((x) => x.id === S.skillsSel);
  const list = el("div", { class: "list-col" }, data.pending.map((p) =>
    el("button", { type: "button", class: "prop" + (p.id === v.id ? " on" : ""), "aria-pressed": String(p.id === v.id), onclick: () => { S.skillsSel = p.id; renderPage("skills"); } },
      el("span", { css: { display: "flex", alignItems: "center", gap: "8px", width: "100%" } }, el("span", { class: "mono", css: { fontWeight: "500" }, text: p.name }),
        el("span", { class: "chip", css: { marginLeft: "auto" }, text: p.active_version ? `v${p.active_version} → v${p.version}` : "new" })),
      el("span", { class: "small", css: { color: "var(--text-2)" }, text: firstLine(p.change_note, 120) }),
      el("span", { class: "muted small", text: `${p.expert} · by ${p.author || p.source} · ${fmtRel(p.created)}` }))));
  const cur = data.skills.find((s) => s.name === v.name);
  const note = el("input", { type: "text", placeholder: "Review note (optional, audited)", "aria-label": "Review note" });
  const approve = el("button", { type: "button", class: "btn btn-primary" }, "Approve");
  let armed = false, timer = null;
  approve.addEventListener("click", async () => {
    if (!armed) { armed = true; approve.textContent = "Confirm approval"; timer = setTimeout(() => { armed = false; approve.textContent = "Approve"; }, 5000); return; }
    clearTimeout(timer);
    try { await api(`/api/skills/versions/${v.id}`, { action: "approve", note: note.value }); toast(`${v.name} v${v.version} approved`); S.skillsSel = null; renderPage("skills"); scheduleRefresh(); } catch (e) { toast(e.message, true); }
  });
  const reject = el("button", { type: "button", class: "btn btn-danger", onclick: async () => {
    try { await api(`/api/skills/versions/${v.id}`, { action: "reject", note: note.value }); toast("Rejected"); S.skillsSel = null; renderPage("skills"); scheduleRefresh(); } catch (e) { toast(e.message, true); }
  } }, "Reject");
  const diff = el("div", { class: "diff", role: "region", "aria-label": "Changes to the procedure" },
    parseDiff(v.diff).map(([cls, sign, text]) => el("div", { class: "dl" + (cls ? " " + cls : "") }, el("span", { class: "sg", text: sign }), el("span", { class: "tx", text: text || " " }))));
  const detail = el("div", { class: "detail-col card fade", css: { padding: "0" } },
    el("div", { css: { padding: "16px 18px", borderBottom: "1px solid var(--line)", display: "flex", flexDirection: "column", gap: "6px" } },
      el("div", { css: { display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" } }, el("h2", { class: "mono", css: { fontSize: "15px", fontWeight: "500" }, text: v.name }),
        el("span", { class: "chip", text: v.active_version ? `v${v.active_version} → v${v.version}` : "New skill · v1" }), el("span", { class: "chip", text: v.expert })),
      el("div", { class: "muted small", text: `Proposed by ${v.author || v.source}${v.case_id ? " in " + v.case_id : ""} · ${fmtRel(v.created)}` })),
    el("div", { css: { padding: "16px 18px", display: "flex", flexDirection: "column", gap: "14px" } },
      el("div", { css: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px" } },
        el("div", {}, el("div", { class: "label", text: "What changed and why" }), el("div", { css: { fontSize: "13.5px", marginTop: "2px" }, text: v.change_note || "(no note)" })),
        el("div", {}, el("div", { class: "label", text: "Current version's track record" }),
          cur && cur.active_version ? el("div", { css: { fontSize: "13.5px", marginTop: "4px", display: "flex", alignItems: "center", gap: "10px" } }, recordBar(cur), cur.track_record)
            : el("div", { class: "muted small", text: "No approved version yet" }))),
      el("div", {}, el("div", { class: "label", css: { marginBottom: "4px" }, text: "When to use" }), el("div", { css: { fontSize: "13.5px", color: "var(--text-2)" }, text: v.description })),
      el("div", {}, el("div", { class: "label", css: { marginBottom: "6px" }, text: "Procedure" }), diff),
      note,
      el("div", { class: "toolbar" }, el("span", { class: "muted small", css: { flex: "1 1 220px" }, text: `Approving makes this the version every ${v.expert} subagent is briefed with. Earlier versions stay available for rollback.` }), reject, approve)));
  root.append(el("div", { class: "split" }, list, detail));
}
function skillsAll(root, skills) {
  if (!skills.length) { root.append(el("div", { class: "empty", text: "No skills yet. Subagents propose them as they work, and every after-action review asks them to." })); return; }
  const tb = el("tbody");
  for (const s of skills) {
    const versions = el("tr", { hidden: true }, el("td", { colspan: "6" }));
    const toggle = async () => {
      if (!versions.hidden) { versions.hidden = true; return; }
      const d = await api("/api/skills/" + encodeURIComponent(s.name));
      const cell = clear(versions.firstChild);
      cell.append(el("pre", { class: "code", text: d.skill.body || "(no approved version)" }),
        el("div", { css: { display: "flex", flexDirection: "column", gap: "4px", marginTop: "8px" } }, d.versions.map((x) =>
          el("div", { class: "toolbar small" }, el("span", { class: "mono", text: `v${x.version}` }), el("span", { class: "chip", text: x.status }),
            el("span", { class: "muted", text: `${x.source}:${x.author} · ${fmtRel(x.created)} · ${x.change_note || ""}` }),
            x.status === "superseded" ? el("button", { type: "button", class: "btn btn-sm", onclick: () => skillAction(s.name, "rollback", x.version) }, "Roll back to this") : null))));
      versions.hidden = false;
    };
    tb.append(el("tr", {},
      el("td", { css: { minWidth: "260px" } }, el("button", { type: "button", class: "btn btn-ghost btn-sm mono", css: { padding: "0", height: "auto", fontWeight: "500", color: "var(--text)" }, onclick: toggle }, s.name),
        el("div", { class: "muted small", text: s.description || "" })),
      el("td", { text: s.expert }), el("td", { class: "mono", text: s.active_version ? `v${s.active_version}` : "-" }),
      el("td", { css: { whiteSpace: "nowrap" } }, recordBar(s), el("span", { class: "small", css: { marginLeft: "8px", color: s.needs_revision ? "var(--red-hi)" : "var(--text-2)" }, text: s.track_record })),
      el("td", {}, el("span", { class: "chip" + (s.status === "retired" ? "" : s.pending ? " warn" : " ok"), text: s.status === "retired" ? "Retired" : s.pending ? `${s.pending} pending` : "Active" })),
      el("td", {}, el("button", { type: "button", class: "btn btn-sm", onclick: () => skillAction(s.name, s.status === "retired" ? "restore" : "retire") }, s.status === "retired" ? "Restore" : "Retire"))));
    tb.append(versions);
  }
  root.append(el("div", { class: "table-box" }, el("table", { class: "list" }, el("thead", {}, el("tr", {}, ["Skill", "Owner", "Version", "Track record", "Status", ""].map((h) => el("th", { text: h })))), tb)));
}
function skillsWeak(root, weak) {
  if (!weak.length) { root.append(el("div", { class: "empty", text: "No skill is failing more often than it works." })); return; }
  for (const s of weak) {
    root.append(el("div", { class: "card", css: { borderColor: "var(--red-line)", display: "flex", flexDirection: "column", gap: "8px" } },
      el("div", { class: "toolbar" }, el("span", { class: "mono", css: { fontWeight: "500" }, text: s.name }), el("span", { class: "chip", text: `v${s.active_version} · ${s.expert}` }),
        el("span", { class: "chip red", css: { marginLeft: "auto" }, text: s.track_record })),
      el("div", { class: "small", css: { color: "var(--text-2)" }, text: s.description || "" }),
      el("div", { class: "toolbar" },
        el("button", { type: "button", class: "btn btn-sm", onclick: () => { go("ops"); send(`Have a ${s.expert} subagent review and revise the skill ${s.name}: it fails more often than it works (${s.track_record}). Propose the fix with skill_update.`, ""); } }, "Ask for a revision"),
        el("button", { type: "button", class: "btn btn-sm btn-danger", onclick: () => skillAction(s.name, "retire") }, "Retire"))));
  }
}
async function skillAction(name, action, version) {
  try { await api(`/api/skills/${encodeURIComponent(name)}/action`, { action, version }); toast(`${name}: ${action}`); renderPage("skills"); scheduleRefresh(); }
  catch (e) { toast(e.message, true); }
}

// Focus an element a re-render is about to create (pages render asynchronously).
function focusWhenReady(id, tries = 40) {
  const n = document.getElementById(id);
  if (n) { n.focus(); return; }
  if (tries > 0) setTimeout(() => focusWhenReady(id, tries - 1), 30);
}
// A WAI-ARIA tab list: one tab in the Tab order, arrow keys / Home / End move between tabs and select them.
function tabList(label, prefix, tabs, current, pick) {
  const list = el("div", { class: "tabs", role: "tablist", "aria-label": label });
  for (const [id, text, extra] of tabs) {
    const on = id === current;
    list.append(el("button", { type: "button", role: "tab", id: `${prefix}-tab-${id}`, class: "tab" + (on ? " on" : ""), "aria-selected": String(on),
      "aria-controls": `${prefix}-panel`, tabindex: on ? "0" : "-1", onclick: () => pick(id) }, text, extra || null));
  }
  list.addEventListener("keydown", (e) => {
    const ids = tabs.map((x) => x[0]), i = ids.indexOf(current);
    const j = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: ids.length - 1 }[e.key];
    if (j === undefined) return;
    e.preventDefault();
    const next = ids[(j + ids.length) % ids.length];
    pick(next);
    focusWhenReady(`${prefix}-tab-${next}`);
  });
  return list;
}

/* ================================================================ overlays: dialogs, menus, palette */
function openDialog(o) {
  const ov = el("div", { class: "overlay" + (o.top ? " top" : "") });
  const prev = document.activeElement;
  const handle = { el: null, close: null };
  const prevKey = prev && prev !== document.body ? focusKey(prev) : null;
  const close = () => {
    ov.remove(); S.dialogs = S.dialogs.filter((x) => x !== handle);
    if (prev && prev.isConnected && prev.focus) { prev.focus(); return; }
    const twin = prevKey && [...document.querySelectorAll(FOCUSABLE)].find((x) => focusKey(x) === prevKey);
    if (twin) twin.focus(); else if (S.view === "ops" && S.ui.input) S.ui.input.focus();
  };
  const dlg = el("div", { class: "dialog" + (o.wide ? " wide" : "") + (o.cls ? " " + o.cls : ""), role: "dialog", "aria-modal": "true", "aria-label": o.title || o.label || "Dialog" });
  if (o.title) {
    dlg.append(el("div", { class: "dialog-head" }, o.iconName ? el("span", { class: "badge-icon" }, icon(o.iconName, 18)) : null,
      el("div", { class: "t" }, el("h2", { text: o.title }), o.sub ? el("div", { class: "mono muted small ellipsis", text: o.sub }) : null),
      el("button", { type: "button", class: "btn btn-ghost icon-btn", "aria-label": "Close", onclick: close }, icon("x"))));
  }
  if (o.raw) dlg.append(...o.raw);
  if (o.body) dlg.append(el("div", { class: "dialog-body" }, o.body));
  if (o.foot) dlg.append(el("div", { class: "dialog-foot" }, o.foot));
  ov.append(el("button", { type: "button", class: "scrim", "aria-label": "Close", tabindex: "-1", onclick: close }), dlg);
  $("overlays").append(ov);
  handle.el = dlg; handle.close = close;
  S.dialogs.push(handle);
  setTimeout(() => { const f = dlg.querySelector("input, textarea, .btn-primary, button:not(.icon-btn)"); if (f) f.focus(); }, 0);
  return handle;
}
function trapFocus(e) {
  if (e.key !== "Tab" || !S.dialogs.length) return;
  const dlg = S.dialogs[S.dialogs.length - 1].el;
  const f = [...dlg.querySelectorAll("button, input, textarea, select, summary, a[href], [tabindex]:not([tabindex='-1'])")].filter((x) => !x.disabled && x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  else if (!dlg.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
}
function closeMenu(refocus) {
  if (!S.menu) return;
  S.menu.remove(); S.menu = null; document.removeEventListener("mousedown", menuOutside, true);
  const a = S.menuAnchor; S.menuAnchor = null;
  if (a) { a.setAttribute("aria-expanded", "false"); if (refocus && a.isConnected) a.focus(); }
}
function menuOutside(e) { if (S.menu && !S.menu.contains(e.target)) closeMenu(); }
function openMenu(anchor, items) {
  closeMenu();
  const m = el("div", { class: "menu", role: "menu", "aria-label": anchor.getAttribute("aria-label") || anchor.textContent.trim() || "Menu" });
  for (const it of items) {
    if (it === "-") { m.append(el("div", { class: "menu-sep", role: "separator" })); continue; }
    if (it.header) { m.append(el("div", { class: "menu-head", role: "presentation", text: it.header })); continue; }
    m.append(el("button", { type: "button", class: "menu-item" + (it.danger ? " danger" : ""), role: "menuitem", disabled: !!it.disabled, title: it.title || null,
      onclick: () => { closeMenu(true); it.run(); } }, it.icon ? icon(it.icon, 15) : null, it.label, it.end ? el("span", { class: "end", text: it.end }) : null));
  }
  document.body.append(m);
  const r = anchor.getBoundingClientRect(), mr = m.getBoundingClientRect();
  let top = r.bottom + 6; if (top + mr.height > innerHeight - 8) top = Math.max(8, r.top - mr.height - 6);
  let left = r.left; if (left + mr.width > innerWidth - 8) left = Math.max(8, innerWidth - mr.width - 8);
  m.style.top = top + "px"; m.style.left = left + "px";
  S.menu = m; S.menuAnchor = anchor;
  anchor.setAttribute("aria-haspopup", "menu"); anchor.setAttribute("aria-expanded", "true");
  setTimeout(() => document.addEventListener("mousedown", menuOutside, true), 0);
  const first = m.querySelector(".menu-item:not([disabled])"); if (first) first.focus();
}
function menuKey(e) {
  if (!S.menu) return false;
  const items = [...S.menu.querySelectorAll(".menu-item:not([disabled])")];
  if (!items.length) return false;
  const i = items.indexOf(document.activeElement);
  if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); return true; }
  if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); return true; }
  if (e.key === "Home" || e.key === "End") { e.preventDefault(); items[e.key === "Home" ? 0 : items.length - 1].focus(); return true; }
  if (e.key === "Tab") { closeMenu(); return false; }
  return false;
}
function paletteItems() {
  const st = S.st, items = [];
  const add = (group, ic, label, run, end, keys) => items.push({ group, icon: ic, label, run, end: end || "", keys: keys || "" });
  add("Actions", "plus", "New conversation", newConversation, "Ctrl Shift O");
  add("Actions", "panel", "Toggle case panel", () => { go("ops"); toggleInsp(); }, "Ctrl .");
  add("Actions", "refresh", "After-action review", runRetro, "", "retro reflect skills");
  add("Actions", "star", "Rate this session", rateDialog, "", "rating feedback");
  add("Actions", "sun", pref("theme", "dark") === "light" ? "Switch to dark theme" : "Switch to light theme", () => applyTheme(pref("theme", "dark") === "light" ? "dark" : "light"), "", "theme appearance");
  add("Actions", "keyboard", "Keyboard shortcuts", showShortcuts, "Ctrl /");
  add("Actions", "logout", "Sign out", signOut);
  for (const [v, ic, label] of [["ops", "chat", "Operations"], ["skills", "book", "Skills"], ["memory", "db", "Memory"], ["audit", "file", "Audit log"],
    ["roe", "shield", "Rules of engagement"], ["connectors", "plug", "Connectors"], ["settings", "sliders", "Settings"]]) add("Go to", ic, label, () => go(v));
  for (const p of st.playbooks || []) add("Playbooks", "list", `Start playbook: ${humanPb(p)}`, () => { go("ops"); setPlaybook(p); }, "", PB_DESC[p] || "");
  for (const s of S.subs.values()) if (s.expert) add("Subagents", "users", `${s.id} · ${shortTitle(s.title)}`, () => { go("ops"); openThread(s.id); }, s.status, s.task);
  for (const c of S.convs) add("Conversations", "chat", c.title || "Untitled", () => { go("ops"); openConversation(c.id); }, fmtRel(c.updated));
  for (const m of st.models) if (m.name !== st.model && m.ready) add("Models", "box", `Switch the lead to ${m.label}`, () => switchModel(m), m.model, m.name);
  return items;
}
function openPalette() {
  if (S.dialogs.some((d) => d.palette)) return;
  const all = paletteItems();
  let sel = 0, shown = all;
  const input = el("input", { type: "search", placeholder: "Search conversations, subagents, playbooks and commands", "aria-label": "Command search", autocomplete: "off",
    role: "combobox", "aria-expanded": "true", "aria-controls": "pal-list", "aria-autocomplete": "list" });
  const list = el("div", { class: "pal-list", role: "listbox", id: "pal-list", "aria-label": "Commands" });
  const run = (it) => { dlg.close(); it.run(); };
  const draw = () => {
    clear(list);
    if (!shown.length) { list.append(el("div", { class: "empty", text: "No matches" })); input.removeAttribute("aria-activedescendant"); return; }
    input.setAttribute("aria-activedescendant", `pal-opt-${sel}`);
    let group = "";
    shown.forEach((it, i) => {
      if (it.group !== group) { group = it.group; list.append(el("div", { class: "pal-group", role: "presentation", text: group })); }
      const b = el("button", { type: "button", id: `pal-opt-${i}`, tabindex: "-1", class: "pal-item" + (i === sel ? " on" : ""), role: "option", "aria-selected": String(i === sel), onclick: () => run(it), onmousemove: () => { if (sel !== i) { sel = i; draw(); } } },
        icon(it.icon, 16), el("span", { class: "ellipsis", text: it.label }), it.end ? el("span", { class: "end", text: it.end }) : null);
      list.append(b);
      if (i === sel) setTimeout(() => b.scrollIntoView({ block: "nearest" }), 0);
    });
  };
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    shown = !q ? all : all.filter((it) => (it.label + " " + it.group + " " + it.keys).toLowerCase().includes(q));
    sel = 0; draw();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); draw(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); draw(); }
    else if (e.key === "Enter") { e.preventDefault(); if (shown[sel]) run(shown[sel]); }
  });
  const dlg = openDialog({ cls: "palette", top: true, label: "Command palette",
    raw: [el("div", { class: "pal-input" }, icon("search", 17), input, el("span", { class: "kbd", text: "Esc" })), list] });
  dlg.palette = true;
  draw();
}
const SHORTCUTS = [["Ctrl K", "Search and commands"], ["Ctrl Shift O", "New conversation"], ["Ctrl .", "Toggle the case panel"], ["Ctrl /", "Keyboard shortcuts"],
  ["/", "Focus the message box"], ["Enter", "Send"], ["Shift Enter", "New line"], ["Esc", "Close a dialog, menu or thread"]];
function shortcutsTable() {
  return el("div", { class: "table-box" }, el("table", { class: "list" }, el("tbody", {}, SHORTCUTS.map(([k, d]) => el("tr", {}, el("td", { css: { width: "160px" } }, el("span", { class: "kbd", text: k })), el("td", { text: d }))))));
}
function showShortcuts() { const d = openDialog({ title: "Keyboard shortcuts", iconName: "keyboard", body: [shortcutsTable()], foot: [el("span", { class: "note", text: "Cmd works in place of Ctrl on macOS." }), el("button", { type: "button", class: "btn", onclick: () => d.close() }, "Close")] }); }

/* ================================================================ keyboard, ticker, boot */
document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (menuKey(e)) return;
  if (e.key === "Escape") {
    if (S.menu) { closeMenu(true); return; }
    if (S.dialogs.length) { e.preventDefault(); S.dialogs[S.dialogs.length - 1].close(); return; }
    if ($("side").classList.contains("open")) { $("side").classList.remove("open"); return; }
    if (S.insp.thread) { S.insp.thread = null; renderInsp(); return; }
    return;
  }
  if (S.dialogs.length) { trapFocus(e); return; }
  const k = e.key.toLowerCase();
  if (mod && k === "k") { e.preventDefault(); openPalette(); }
  else if (mod && e.shiftKey && k === "o") { e.preventDefault(); newConversation(); }
  else if (mod && e.key === ".") { e.preventDefault(); if (S.view !== "ops") go("ops"); toggleInsp(); }
  else if (mod && e.key === "/") { e.preventDefault(); showShortcuts(); }
  else if (e.key === "/" && !mod && !isTyping(e.target)) { e.preventDefault(); if (S.view !== "ops") go("ops"); S.ui.input.focus(); }
});
function tick() {
  for (const t of S.turns) if (t.running) updateWorkHead(t);
  for (const n of document.querySelectorAll("[data-elapsed]")) { const s = S.subs.get(n.dataset.elapsed); if (s) n.textContent = elapsedText(s); }
  if (S.pending.size && S.view === "ops") renderBanner();
}
window.addEventListener("hashchange", (e) => { if (location.hash === "#composer") { history.replaceState(null, "", "#/" + (S.view === "ops" ? "" : S.view)); if (S.view !== "ops") go("ops"); S.ui.input.focus(); return; } route(e); });
window.addEventListener("popstate", route);

// Sign-ins end after hours of no analyst activity. Background polling does not count; this ping (at most once a
// minute, only while someone uses the page) does. An expired session gets 401 and the page returns to sign-in.
function watchActivity() {
  let last = 0;
  const ping = () => {
    if (document.hidden || Date.now() - last < 60000) return;
    last = Date.now();
    api("/api/activity", {}).catch(() => {});
  };
  for (const ev of ["pointerdown", "keydown", "wheel", "touchstart"]) addEventListener(ev, ping, { passive: true, capture: true });
}
(async function boot() {
  applyTheme(pref("theme", "dark"));
  if (innerWidth < 1180) S.insp.open = false;
  buildOps();
  try {
    S.loading = true;
    const [st, evs, convs] = await Promise.all([api("/api/state"), api("/api/events/poll?after=0"), api("/api/conversations")]);
    applyState(st); S.convs = convs.conversations;
    S.loading = false;
    replay(evs);
    for (const ev of S.buffer.splice(0)) onEvent(ev);
  } catch (e) { S.loading = false; toast("Cannot load the dashboard: " + e.message, true); return; }
  renderSide(); renderHeader(); renderStatus(); renderComposerState(); renderInsp();
  route();
  connect();
  refreshAudit();
  refreshPlans();
  watchActivity();
  setInterval(tick, 1000);
  if (S.view === "ops") S.ui.input.focus();
})();
