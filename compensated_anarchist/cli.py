"""Compensated Anarchist command line."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from . import NAME, __version__
from .audit import verify
from .config import load_config

C = {"dim": "\033[2m", "b": "\033[1m", "r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "c": "\033[36m", "m": "\033[35m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}

BANNER = f"""{C['b']}{NAME}{C['x']} v{__version__} - Defensive Cyber Operations harness
{C['dim']}type /help for commands. Every tool call is ROE-gated and audited.{C['x']}"""

HELP = """
  <text>                       talk to the DCO lead (the orchestrator; it tasks expert subagents)
  /playbook <name> <details>   run a playbook: triage | hunt | hunt_plan | incident_response | compromise_assessment
                               | forensics | vulnerability_assessment (every action needs your approval)
                               | cte_plan | report | code
  /experts                     list expert agents and their models
  /subagents                   subagents in this conversation (id, expert, status, last bottom line)
  /conversations               this case's saved conversations
  /new                         start a new conversation (the current one stays saved)
  /open <conversation-id>      resume a saved conversation
  /delete <conversation-id>    delete a conversation permanently (asks you to confirm)
  /skills                      skills and how they are doing; /skills pending  shows proposals awaiting review
  /tools                       list tools with their ROE tier
  /models  |  /model <name>    list / switch the lead's model profile
  /case                        show case summary
  /verdict <FIN-id> <tp|fp|benign|inconclusive> [note]   adjudicate a finding (feeds learning)
  /remember <kind> <title> :: <content>                  add analyst knowledge (approved immediately)
  /retro                       after-action review -> lessons into memory
  /rate <1-5> [note]           rate this session (rated sessions become fine-tuning data)
  /quit
"""


def _event_line(kind: str, d: dict[str, Any]) -> str | None:
    who = d.get("agent_id") or d.get("agent", "")
    if kind == "decision":
        col = {"auto": "dim", "notify": "y", "approve": "m", "deny": "r"}.get(d["tier"], "dim")
        mark = "+" if d["allowed"] else "x"
        args = json.dumps(d["args"], default=str)
        args = args if len(args) < 160 else args[:157] + "..."
        return f"{C[col]}  [{who}] {mark} {d['tool']} {args}  <{d['tier']}>{'' if d['allowed'] else ' ' + d['reason']}{C['x']}"
    elif kind == "result" and d["error"]:
        return f"{C['r']}  [{who}] ! {d['tool']} returned an error{C['x']}"
    elif kind == "subagent_spawn":
        return f"{C['c']}  >> {d['id']} {d['expert']}: {d['task'][:140]}{C['x']}"
    elif kind == "subagent_message":
        return f"{C['c']}  >> follow-up to {d['id']} {d['expert']}: {d['message'][:140]}{C['x']}"
    elif kind == "subagent_report":
        col = "g" if d["status"] == "completed" else "y" if d["status"] in ("blocked", "needs_input") else "r"
        return f"{C[col]}  << {d['id']} {d['expert']} [{d['status']}] {str(d.get('summary', ''))[:200]}{C['x']}"
    elif kind == "skill_used":
        return f"{C['dim']}  [{who}] using skill {d['skill']} v{d['version']}{C['x']}"
    elif kind == "skill_proposed":
        return f"{C['m']}  [{who}] skill {d['skill']} v{d['version']} {d['status']}{' (review: canarchist skills review)' if d['status'] == 'candidate' else ''}{C['x']}"
    elif kind == "text" and d["agent"] != "lead" and not d["final"]:
        return f"{C['dim']}  [{who}] {d['text'][:300]}{C['x']}"
    elif kind == "loop_guard":
        what = "gave up: kept repeating" if d["gave_up"] else "cut off a repeating reply, asking again"
        return f"{C['y']}  [{who}] loop guard: {what} ({d['unit'][:60]!r}{', in reasoning' if d['where'] == 'reasoning' else ''}){C['x']}"
    elif kind == "compact":
        return f"{C['dim']}  [{who}] compacted {d['dropped']} old messages{C['x']}"
    elif kind == "gate_on":
        return f"{C['m']}  APPROVAL MODE: {d['reason']}{C['x']}"
    elif kind == "plan_saved":
        label = {"plan": "hunt plan", "results": "hunt results", "layer": "ATT&CK Navigator layer",
                 "vuln_report": "vulnerability report", "cte_plan": "CTE plan", "cte_results": "CTE results",
                 "report": "report draft", "report_final": "final report"}.get(d["kind"], "file")
        return f"{C['c']}  saved {label}: {_file_link(d['path'])}{C['x']}"
    return None


def _print_models(cfg, current: str) -> None:
    """Model profiles by group (config/models.yaml + models.local.yaml), with what each still needs."""
    print(f"  models from {', '.join(str(f) for f in cfg.model_files if f.exists()) or 'harness.yaml'}")
    if cfg.models_error:
        print(f"{C['r']}  last edit not applied: {cfg.models_error}{C['x']}")
    groups: dict[str, list] = {}
    for p in cfg.models.values():
        groups.setdefault(p.group or "Other", []).append(p)
    for g, profs in groups.items():
        print(f"  {C['dim']}{g}{C['x']}")
        for p in profs:
            why = p.problem()
            state = f"{C['y']}needs setup: {why}{C['x']}" if why else f"{C['dim']}{p.provider} {p.model} tool_mode={p.tool_mode}{C['x']}"
            print(f"  {'*' if p.name == current else ' '} {p.name:18s} {(p.label or p.name)[:28]:28s} {state}")


def _file_link(path: str) -> str:
    """The path as a terminal hyperlink (OSC 8): Ctrl+click opens it in most terminals, VS Code's included."""
    if not sys.stdout.isatty():
        return path
    return f"\033]8;;{Path(path).as_uri()}\033\\{path}\033]8;;\033\\"


# The lead's reply streams to the terminal as it is generated (TTY only; piped output gets whole lines).
STREAM = sys.stdout.isatty() and not os.environ.get("CA_NO_STREAM")
_live = {"open": False, "final": None}


def _end_live() -> None:
    if _live["open"]:
        sys.stdout.write(C["x"] + "\n")
        _live["open"] = False


def event_printer(kind: str, d: dict[str, Any]) -> None:
    lead = (d.get("agent_id") or d.get("agent")) == "lead"
    if kind == "delta":
        if not (STREAM and lead):
            return
        if d.get("reset"):
            if _live["open"]:
                _end_live()
                print(f"{C['dim']}  (response restarted){C['x']}")
            return
        if not _live["open"]:
            if not d.get("text", "").strip():
                return  # don't open a line for leading whitespace
            sys.stdout.write("\n")
            _live["open"] = True
        sys.stdout.write(d.get("text", ""))
        sys.stdout.flush()
        return
    if kind == "text" and lead and _live["open"]:
        _end_live()
        if d.get("final"):
            _live["final"] = d["text"]  # already on screen; say() won't print it again
        return
    line = _event_line(kind, d)
    if line is not None:
        _end_live()
        print(line, flush=True)  # progress shows up live even when output goes to a file


def say(answer: str) -> None:
    """Print an agent's final answer unless it was just streamed to the terminal."""
    streamed, _live["final"] = _live["final"], None
    if answer != streamed:
        print(f"\n{answer}", flush=True)


def _cfg(args):
    path = args.config or os.environ.get("CA_CONFIG") or "config/harness.yaml"
    return load_config(path)


def _playbook(name: str) -> str:
    try:
        return resources.files("compensated_anarchist").joinpath(f"playbooks/{name}.md").read_text()
    except FileNotFoundError:
        raise SystemExit(f"unknown playbook {name}")


async def _with_harness(args, interactive: bool, fn):
    from .agent import Harness

    h = Harness(_cfg(args), args.case, args.model, args.posture, interactive, event_printer)
    await h.start(getattr(args, "conversation", None), getattr(args, "new", False))
    try:
        return await fn(h)
    finally:
        await h.close()


def _print_status(h) -> None:
    print(f"case {C['b']}{h.case.id}{C['x']}  model {C['b']}{h.model_name}{C['x']}  posture {C['b']}{h.roe.posture.upper()}{C['x']}")
    for k, v in h.mcp.status.items():
        print(f"  mcp {k:16s} {C['g'] if v.startswith('connected') else C['r']}{v}{C['x']}")
    from . import vault
    v = vault.status(h.vault_dir)
    mount = (f"{C['g']}noexec mount{C['x']}" if v.get("noexec")
             else f"{C['y']}not on a noexec mount (files are still read-only and non-executable; see SETUP.md){C['x']}")
    print(f"  vault: {v['path']} ({v.get('files', 0)} files, mode {v.get('mode')}) - {mount}")
    drop = h.case_evidence_dir
    n = sum(1 for p in drop.rglob("*") if p.is_file() and p.name != "README.txt")
    print(f"  case evidence folder: {drop} ({n} files) - drop artifacts for this case here")
    print(f"  experts: {', '.join(h.experts)}")
    print(f"  memory: {h.memory.stats() or 'empty'}")
    sk = h.skills.stats()
    print(f"  skills: {sk['active']} active" + (f", {C['m']}{sk['pending_review']} awaiting review (canarchist skills review){C['x']}"
                                                 if sk["pending_review"] else ""))


def _print_conversation(h, tail: int = 12) -> None:
    c = h.conversation
    if not c:
        print(f"  conversation: new (saved on first message; kept until you delete it)")
        return
    print(f"  conversation: {C['b']}{c['id']}{C['x']} {c['title']!r} - resumed, {len(h.subagents)} subagent(s)")
    shown = [e for e in h.history.events(c["id"]) if e["kind"] == "analyst_message"
             or (e["kind"] == "text" and e["data"].get("agent") == "lead" and e["data"].get("final"))
             or e["kind"] == "subagent_report"][-tail:]
    for e in shown:
        d = e["data"]
        if e["kind"] == "analyst_message":
            print(f"{C['dim']}  analyst> {(d.get('text') or d.get('playbook') or '')[:200]}{C['x']}")
        elif e["kind"] == "subagent_report":
            print(f"{C['dim']}    << {d['id']} {d['expert']} [{d['status']}] {str(d.get('summary', ''))[:160]}{C['x']}")
        else:
            print(f"{C['dim']}  lead: {d['text'][:300]}{C['x']}")


def _print_skills(store, pending: bool = False) -> None:
    from .skills import track_record

    if pending:
        rows = store.pending()
        print(f"{len(rows)} skill version(s) awaiting review" + (" - canarchist skills review" if rows else ""))
        for v in rows:
            print(f"  #{v['id']:<4} {v['name']} v{v['version']} ({v['expert']}) by {v['author']}: {v['change_note']}")
        return
    rows = store.list()
    if not rows:
        print("no skills yet")
    for r in rows:
        if r["active_version"]:
            print(f"  {r['expert']:20s} {r['name']:36s} v{r['active_version']:<3} {track_record(r)}"
                  + (f"  ({r['pending']} pending)" if r["pending"] else ""))


async def chat(h) -> None:
    print(BANNER)
    _print_status(h)
    _print_conversation(h)
    while True:
        try:
            line = (await asyncio.to_thread(input, f"\n{C['b']}analyst>{C['x']} ")).strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        try:
            if line in ("/quit", "/exit"):
                break
            if line == "/help":
                print(HELP)
            elif line == "/case":
                print(h.case.summary())
            elif line == "/subagents":
                print(h._list_subagents())
            elif line == "/conversations":
                for c in h.history.list(h.case.id):
                    cur = "*" if h.conversation and c["id"] == h.conversation["id"] else " "
                    print(f"  {cur} {c['id']}  {c['updated'][:16]}  {c['events']:5d} events  {c['title']}")
            elif line == "/new":
                h.new_conversation()
                print("new conversation started (the previous one is saved)")
            elif line.startswith("/open "):
                h.open_conversation(line.split(maxsplit=1)[1].strip())
                _print_conversation(h)
            elif line.startswith("/delete "):
                cid = line.split(maxsplit=1)[1].strip()
                c = h.history.get(cid)
                if not c or c["case_id"] != h.case.id:
                    print("no such conversation in this case")
                    continue
                print(f"Delete {cid} {c['title']!r} ({c['events']} events) and its transcripts? The case record, audit "
                      f"log, memories and skills are kept. This cannot be undone.")
                ans = (await asyncio.to_thread(input, "  type the conversation id to confirm: ")).strip()
                print("deleted" if ans == cid and h.delete_conversation(cid) else "not deleted")
            elif line.startswith("/skills"):
                _print_skills(h.skills, pending=line.strip().endswith("pending"))
            elif line == "/experts":
                for n, e in h.experts.items():
                    print(f"  {n:20s} model={e.model or h.model_name:16s} {e.description}")
            elif line == "/tools":
                for t in h.registry.tools.values():
                    tier, why = h.roe.classify(t.name, {}, t.annotations, t.server)
                    print(f"  {tier:8s} {t.name:45s} {C['dim']}{why}{C['x']}")
            elif line == "/models":
                h.cfg.reload_models()
                _print_models(h.cfg, h.model_name)
            elif line.startswith("/model "):
                h.switch_model(line.split(maxsplit=1)[1])
                print(f"lead now on {h.model_name}")
            elif line.startswith("/verdict "):
                parts = line.split(maxsplit=3)
                ok = h.set_verdict(parts[1], parts[2], parts[3] if len(parts) > 3 else "")
                print(f"{parts[1]} -> {parts[2]}" if ok else "no such finding")
            elif line.startswith("/remember "):
                body = line[len("/remember "):]
                head, _, content = body.partition("::")
                kind, _, title = head.strip().partition(" ")
                mid = h.remember(kind, title, content)
                print(f"saved M{mid}")
            elif line == "/retro":
                say(await h.retro())
            elif line.startswith("/rate "):
                parts = line.split(maxsplit=2)
                h.rate(int(parts[1]), parts[2] if len(parts) > 2 else "")
                print("rated")
            elif line.startswith("/playbook "):
                parts = line.split(maxsplit=2)
                text = _playbook(parts[1]) + "\n\n# Details from analyst\n" + (parts[2] if len(parts) > 2 else "(none)")
                say(await h.mission(text, parts[2] if len(parts) > 2 else '', parts[1]))
            elif line.startswith("/"):
                print("unknown command; /help")
            else:
                say(await h.mission(line))
        except KeyboardInterrupt:
            print("\n(interrupted)")
        except Exception as e:
            print(f"{C['r']}error: {type(e).__name__}: {e}{C['x']}")


def cmd_memory(args) -> None:
    from .audit import AuditLog
    from .memory import Memory

    cfg = _cfg(args)
    audit = AuditLog(cfg.cases_dir / "_memory_audit.jsonl", cfg.operator)
    mem = Memory(cfg.memory_db, cfg.memory, audit)
    if args.action == "stats":
        print(json.dumps(mem.stats(), indent=1))
    elif args.action == "list":
        for m in mem.list(args.status, args.kind):
            print(f"M{m['id']:<5} {m['status']:9s} {m['kind']:14s} +{m['helpful']}/-{m['unhelpful']} {m['title']}")
    elif args.action == "search":
        for m in mem.search(" ".join(args.rest), include_candidates=True):
            print(f"M{m['id']} [{m['status']}] ({m['kind']}) {m['title']}\n   {m['content'][:300]}")
    elif args.action in ("promote", "reject", "retire"):
        status = {"promote": "approved", "reject": "rejected", "retire": "retired"}[args.action]
        for i in args.rest:
            print(f"M{i}: {'ok' if mem.set_status(int(i.lstrip('Mm')), status, cfg.operator) else 'not found'}")
    elif args.action == "review":
        cands = mem.list("candidate")
        print(f"{len(cands)} candidate memories. [p]romote / [r]eject / [s]kip / [q]uit")
        for m in cands:
            print(f"\nM{m['id']} ({m['kind']}) from case {m['case_id']} by {m['source']}\n  {C['b']}{m['title']}{C['x']}\n  {m['content']}")
            a = input("  > ").strip().lower()
            if a == "q":
                break
            if a in ("p", "r"):
                mem.set_status(m["id"], "approved" if a == "p" else "rejected", cfg.operator)


def cmd_history(args) -> None:
    from .agent import delete_conversation
    from .history import ChatStore

    cfg = _cfg(args)
    store = ChatStore(cfg.history_db)
    if args.action == "list":
        rows = store.list(args.case)
        if not rows:
            print("no saved conversations")
        for c in rows:
            print(f"  {c['id']}  case {c['case_id']:18s} {c['updated'][:16]}  {c['events']:5d} events  {c['title']}")
    elif args.action == "show":
        c = store.get(args.id or "")
        if not c:
            raise SystemExit("no such conversation")
        print(f"{c['id']}  case {c['case_id']}  {c['title']!r}  created {c['created'][:16]}")
        for e in store.events(c["id"]):
            d = e["data"]
            if e["kind"] == "analyst_message":
                print(f"\n{C['b']}analyst>{C['x']} {d.get('text') or ('playbook ' + d.get('playbook', ''))}")
            elif e["kind"] == "text" and d.get("agent") == "lead" and d.get("final"):
                print(f"\n{C['b']}lead:{C['x']} {d['text']}")
            elif e["kind"] in ("subagent_spawn", "subagent_message"):
                print(f"{C['c']}  >> {d['id']} {d['expert']}: {(d.get('task') or d.get('message', ''))[:200]}{C['x']}")
            elif e["kind"] == "subagent_report":
                print(f"{C['dim']}  << {d['id']} [{d['status']}] {str(d.get('summary', ''))[:300]}{C['x']}")
            elif e["kind"] == "approval_resolved":
                print(f"{C['m']}  approval {'granted' if d.get('approved') else 'denied'} {d.get('note', '')}{C['x']}")
    elif args.action == "delete":
        c = store.get(args.id or "")
        if not c:
            raise SystemExit("no such conversation")
        if not args.yes:
            print(f"Delete {c['id']} {c['title']!r} (case {c['case_id']}, {c['events']} events) and its transcripts?\n"
                  "The case record, audit log, memories and skills are kept. This cannot be undone.")
            if input("type the conversation id to confirm: ").strip() != c["id"]:
                raise SystemExit("not deleted")
        delete_conversation(cfg, c["id"], cfg.operator)
        print(f"deleted {c['id']}")


def cmd_skills(args) -> None:
    from .audit import AuditLog
    from .skills import SkillStore

    cfg = _cfg(args)
    store = SkillStore(cfg.memory_db, cfg.skills, AuditLog(cfg.cases_dir / "_memory_audit.jsonl", cfg.operator))
    a, rest, by = args.action, args.rest, cfg.operator
    if a == "list":
        _print_skills(store)
    elif a == "pending":
        _print_skills(store, pending=True)
    elif a == "show":
        s = store.get(rest[0]) if rest else None
        if not s:
            raise SystemExit("no such skill")
        print(f"{s['name']} ({s['expert']}) active v{s['active_version']} status {s['status']}\nwhen: {s['description']}\n\n{s['body']}\n")
        for v in store.versions(s["name"]):
            print(f"  v{v['version']} #{v['id']} {v['status']:10s} {v['source']}:{v['author']} {v['created'][:16]} {v['change_note']}")
    elif a == "review":
        rows = store.pending()
        print(f"{len(rows)} proposal(s). [a]pprove / [r]eject / [s]kip / [q]uit")
        for v in rows:
            print(f"\n{C['b']}#{v['id']} {v['name']} v{v['version']}{C['x']} ({v['expert']}) by {v['author']} from case {v['case_id']}")
            print(f"change: {v['change_note']}\n{store.diff(v['id'])}")
            ans = input("  > ").strip().lower()
            if ans == "q":
                break
            if ans == "a":
                store.approve(v["id"], by)
            elif ans == "r":
                store.reject(v["id"], by, input("  reason: ").strip())
    elif a in ("approve", "reject"):
        for vid in rest:
            (store.approve if a == "approve" else store.reject)(int(vid.lstrip("#")), by)  # type: ignore[operator]
            print(f"#{vid}: {a}d")
    elif a == "rollback":
        v = store.rollback(rest[0], int(rest[1].lstrip("v")), by)
        print(f"{v['name']} now at v{v['version']}")
    elif a in ("retire", "restore"):
        print("ok" if store.set_status(rest[0], "retired" if a == "retire" else "active", by) else "no such skill")
    elif a == "export":
        print(f"exported {store.export_dir(Path(rest[0]))} skills to {rest[0]}")
    elif a == "import":
        done = store.import_dir(Path(rest[0]), by)
        print(f"imported {len(done)}: {', '.join(done)}" if done else "nothing new")


ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{d}-attack/{d}-attack.json"


def _attack_cmd(args) -> None:
    import hashlib
    import shutil
    import tempfile

    from .attack import AttackKB, tools

    cfg = _cfg(args)
    if args.action == "status":
        kb = AttackKB(cfg.attack_paths)
        ok = kb.load()
        for p in cfg.attack_paths:
            print(f"  {'found  ' if p.is_file() else 'missing'} {p}")
        if ok:
            n = kb.counts()
            print(f"  {kb.version}: {n['groups']} groups, {n['techniques']} techniques, {n['software']} software, "
                  f"{n['campaigns']} campaigns")
        else:
            print(f"  {kb.error}")
        return
    if args.action == "group":
        if not args.name:
            raise SystemExit("usage: canarchist attack group <name | alias | G-id>")
        kb = AttackKB(cfg.attack_paths)
        fn = {t.name: t.handler for t in tools(kb, lambda: cfg.cases_dir, lambda: [])}["attack_group"]
        print(fn(name=args.name))
        return
    # fetch: download (or import) one ATT&CK domain bundle into the configured location
    dest = next((p for p in cfg.attack_paths if p.name.startswith(args.domain)), None)
    dest = dest or cfg.attack_paths[0].with_name(f"{args.domain}-attack.json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, suffix=".part")
    os.close(fd)
    try:
        if args.from_file:
            shutil.copyfile(args.from_file, tmp)
            src = args.from_file
        else:
            import httpx

            src = ATTACK_URL.format(d=args.domain)
            print(f"downloading {src}")
            with httpx.stream("GET", src, timeout=120, follow_redirects=True) as r:
                r.raise_for_status()
                with open(tmp, "wb") as fh:
                    for chunk in r.iter_bytes():
                        fh.write(chunk)
        data = json.loads(Path(tmp).read_text(encoding="utf-8"))
        coll = [o for o in data.get("objects") or [] if o.get("type") == "x-mitre-collection"]
        if data.get("type") != "bundle" or not coll:
            raise SystemExit(f"{src} is not an ATT&CK STIX bundle (no x-mitre-collection object)")
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    sha = hashlib.sha256(dest.read_bytes()).hexdigest()
    print(f"saved {dest}: {coll[0].get('name')} v{coll[0].get('x_mitre_version')} ({dest.stat().st_size // 1024} KB, sha256 {sha})")
    if dest not in cfg.attack_paths:
        print(f"note: add {dest} to attack.stix in harness.yaml (or ATTACK_STIX) to use it")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="canarchist", description=f"{NAME} - DCO agentic harness")
    p.add_argument("--config", help="harness.yaml (default $CA_CONFIG or ./config/harness.yaml)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--case", required=True, help="case id, e.g. IR-2026-0042")
        sp.add_argument("--model", help="model profile name from harness.yaml")
        sp.add_argument("--posture", choices=["observe", "respond"], help="override ROE posture")
        g = sp.add_mutually_exclusive_group()
        g.add_argument("--conversation", help="resume this saved conversation (default: the case's most recent)")
        g.add_argument("--new", action="store_true", help="start a new conversation instead of resuming")

    common(sub.add_parser("chat", help="interactive operations console"))
    r = sub.add_parser("run", help="run one mission end-to-end")
    common(r)
    r.add_argument("mission")
    r.add_argument("--playbook")
    r.add_argument("--non-interactive", action="store_true", help="auto-deny all approval-tier actions")
    r.add_argument("--retro", action="store_true", help="run an after-action review at the end")
    common(sub.add_parser("doctor", help="check model profiles, connectors and the tool/ROE table"))
    d = sub.add_parser("dashboard", aliases=["gui"], help="web GUI (live feed, approvals, case, memory, audit)")
    common(d)
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8765)
    d.add_argument("--tls-cert", default="")
    d.add_argument("--tls-key", default="")
    d.add_argument("--allow-plaintext", action="store_true", help="permit non-loopback binding without TLS")
    d.add_argument("--run-dir", default="", help="write pid, URL and the access token here once ready (scripts/start.sh)")
    m = sub.add_parser("memory", help="manage institutional memory")
    m.add_argument("action", choices=["stats", "list", "search", "review", "promote", "reject", "retire"])
    m.add_argument("rest", nargs="*")
    m.add_argument("--status")
    m.add_argument("--kind")
    hp = sub.add_parser("history", help="saved conversations (kept until you delete them)")
    hp.add_argument("action", choices=["list", "show", "delete"])
    hp.add_argument("id", nargs="?")
    hp.add_argument("--case")
    hp.add_argument("--yes", action="store_true", help="delete without the confirmation prompt")
    sk = sub.add_parser("skills", help="expert skills: list, review proposals, approve, roll back, export/import SKILL.md")
    sk.add_argument("action", choices=["list", "pending", "show", "review", "approve", "reject", "rollback", "retire",
                                       "restore", "export", "import"])
    sk.add_argument("rest", nargs="*")
    st = sub.add_parser("start", help="start the dashboard in the background and print this start's access token "
                                      "(scripts/start.sh)")
    st.add_argument("--case", help="case id (default: dashboard.serve.case, else the most recently used case)")
    st.add_argument("--model", help="model profile (default: default_model in models.yaml / CA_MODEL)")
    st.add_argument("--posture", choices=["observe", "respond"], help="default: dashboard.serve.posture (observe)")
    st.add_argument("--host", help="address to serve on (default: dashboard.serve.host; auto = this host's address)")
    st.add_argument("--port", type=int)
    st.add_argument("--localhost", action="store_true", help="only this host's browser, plain http on 127.0.0.1")
    st.add_argument("--foreground", action="store_true", help="stay attached to this terminal (Ctrl+C stops it)")
    st.add_argument("-y", "--yes", action="store_true", help="do not ask; use the saved posture, address and case")
    sub.add_parser("stop", help="stop the dashboard (scripts/stop.sh); your data is untouched")
    sub.add_parser("setup", help="create any missing folders and site config files (never overwrites anything)")
    ac = sub.add_parser("account", help="the dashboard sign-in account: status | create | passwd | reset")
    ac.add_argument("action", choices=["status", "create", "passwd", "reset"])
    at = sub.add_parser("attack", help="MITRE ATT&CK data for hunt planning: status, fetch, group <name>")
    at.add_argument("action", choices=["status", "fetch", "group"])
    at.add_argument("name", nargs="?", help="group name, alias or G-id (for `group`)")
    at.add_argument("--domain", choices=["enterprise", "ics", "mobile"], default="enterprise")
    at.add_argument("--from", dest="from_file", help="import a copied STIX bundle instead of downloading (air-gapped)")
    a = sub.add_parser("audit-verify", help="verify a case audit chain")
    a.add_argument("--case", required=True)
    e = sub.add_parser("export-training", help="export rated transcripts as fine-tuning JSONL")
    e.add_argument("--out", default="training.jsonl")
    e.add_argument("--min-rating", type=int, default=4)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if args.cmd == "chat":
        asyncio.run(_with_harness(args, True, chat))
    elif args.cmd == "run":
        async def go(h):
            text = (_playbook(args.playbook) + "\n\n# Details from analyst\n" + args.mission) if args.playbook else args.mission
            try:
                say(await h.mission(text, args.mission, args.playbook or ""))
                if args.retro:
                    say(await h.retro())
            except Exception as e:  # model server or connector failure: one clear line, not a traceback
                _end_live()
                print(f"{C['r']}error: {e}{C['x']}", file=sys.stderr, flush=True)
                raise SystemExit(1)
        asyncio.run(_with_harness(args, not args.non_interactive, go))
    elif args.cmd == "doctor":
        async def doc(h):
            _print_status(h)
            _print_models(h.cfg, h.model_name)
            print()
            for t in h.registry.tools.values():
                tier, why = h.roe.classify(t.name, {}, t.annotations, t.server)
                print(f"  {tier:8s} {t.name:45s} {C['dim']}{why}{C['x']}")
        asyncio.run(_with_harness(args, False, doc))
    elif args.cmd in ("dashboard", "gui"):
        from .web.app import serve

        serve(_cfg(args), args.case, args.model, args.posture, args.host, args.port, args.tls_cert, args.tls_key,
              args.allow_plaintext, args.conversation, args.new, args.run_dir)
    elif args.cmd == "memory":
        cmd_memory(args)
    elif args.cmd == "history":
        cmd_history(args)
    elif args.cmd == "skills":
        cmd_skills(args)
    elif args.cmd == "attack":
        _attack_cmd(args)
    elif args.cmd == "setup":
        from . import service

        made = service.ensure_layout(_cfg(args))
        print("Created:\n  " + "\n  ".join(made) if made else "Everything is in place; nothing to create.")
    elif args.cmd in ("start", "stop"):
        from . import service

        cfg_path = args.config or os.environ.get("CA_CONFIG") or "config/harness.yaml"
        cfg = _cfg(args)
        try:
            if args.cmd == "stop":
                sys.exit(service.stop(cfg))
            sys.exit(service.start(cfg, cfg_path, {k: getattr(args, k) for k in (
                "case", "model", "posture", "host", "port", "localhost", "foreground", "yes")}))
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            sys.exit(1)
    elif args.cmd == "account":
        from .web import account

        try:
            sys.exit(account.interactive(account.default_path(_cfg(args)), args.action))
        except (KeyboardInterrupt, EOFError):
            print("\nNothing changed.")
            sys.exit(1)
    elif args.cmd == "audit-verify":
        ok, msg = verify(_cfg(args).cases_dir / args.case / "audit.jsonl")
        print(msg)
        sys.exit(0 if ok else 1)
    elif args.cmd == "export-training":
        from .memory import export_training

        n = export_training(_cfg(args).cases_dir, Path(args.out), args.min_rating)
        print(f"exported {n} transcripts to {args.out}")


if __name__ == "__main__":
    main()
