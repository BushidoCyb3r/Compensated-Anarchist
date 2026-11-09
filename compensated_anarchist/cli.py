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
  <text>                       talk to the DCO lead (it plans and delegates to experts)
  /playbook <name> <details>   run a playbook: triage | hunt | incident_response | compromise_assessment | forensics
  /experts                     list expert agents and their models
  /tools                       list tools with their ROE tier
  /models  |  /model <name>    list / switch the lead's model profile
  /case                        show case summary
  /verdict <FIN-id> <tp|fp|benign|inconclusive> [note]   adjudicate a finding (feeds learning)
  /remember <kind> <title> :: <content>                  add analyst knowledge (approved immediately)
  /retro                       after-action review -> lessons into memory
  /rate <1-5> [note]           rate this session (rated sessions become fine-tuning data)
  /quit
"""


def event_printer(kind: str, d: dict[str, Any]) -> None:
    if kind == "decision":
        col = {"auto": "dim", "notify": "y", "approve": "m", "deny": "r"}.get(d["tier"], "dim")
        mark = "+" if d["allowed"] else "x"
        args = json.dumps(d["args"], default=str)
        args = args if len(args) < 160 else args[:157] + "..."
        print(f"{C[col]}  [{d['agent']}] {mark} {d['tool']} {args}  <{d['tier']}>{'' if d['allowed'] else ' ' + d['reason']}{C['x']}")
    elif kind == "result" and d["error"]:
        print(f"{C['r']}  [{d['agent']}] ! {d['tool']} returned an error{C['x']}")
    elif kind == "delegate":
        print(f"{C['c']}  >> delegating to {d['expert']}: {d['task'][:140]}{C['x']}")
    elif kind == "text" and d["agent"] != "lead" and not d["final"]:
        print(f"{C['dim']}  [{d['agent']}] {d['text'][:300]}{C['x']}")
    elif kind == "compact":
        print(f"{C['dim']}  [{d['agent']}] compacted {d['dropped']} old messages{C['x']}")


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
    await h.start()
    try:
        return await fn(h)
    finally:
        await h.close()


def _print_status(h) -> None:
    print(f"case {C['b']}{h.case.id}{C['x']}  model {C['b']}{h.model_name}{C['x']}  posture {C['b']}{h.roe.posture.upper()}{C['x']}")
    for k, v in h.mcp.status.items():
        print(f"  mcp {k:16s} {C['g'] if v.startswith('connected') else C['r']}{v}{C['x']}")
    print(f"  experts: {', '.join(h.experts)}")
    print(f"  memory: {h.memory.stats() or 'empty'}")


async def chat(h) -> None:
    print(BANNER)
    _print_status(h)
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
            elif line == "/experts":
                for n, e in h.experts.items():
                    print(f"  {n:20s} model={e.model or h.model_name:16s} {e.description}")
            elif line == "/tools":
                for t in h.registry.tools.values():
                    tier, why = h.roe.classify(t.name, {}, t.annotations, t.server)
                    print(f"  {tier:8s} {t.name:45s} {C['dim']}{why}{C['x']}")
            elif line == "/models":
                for n, p in h.cfg.models.items():
                    print(f"  {'*' if n == h.model_name else ' '} {n:20s} {p.provider:14s} {p.model} {p.base_url}")
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
                print(await h.retro())
            elif line.startswith("/rate "):
                parts = line.split(maxsplit=2)
                h.rate(int(parts[1]), parts[2] if len(parts) > 2 else "")
                print("rated")
            elif line.startswith("/playbook "):
                parts = line.split(maxsplit=2)
                text = _playbook(parts[1]) + "\n\n# Details from analyst\n" + (parts[2] if len(parts) > 2 else "(none)")
                print(f"\n{await h.mission(text)}")
            elif line.startswith("/"):
                print("unknown command; /help")
            else:
                print(f"\n{await h.mission(line)}")
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


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="canarchist", description=f"{NAME} - DCO agentic harness")
    p.add_argument("--config", help="harness.yaml (default $CA_CONFIG or ./config/harness.yaml)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--case", required=True, help="case id, e.g. IR-2026-0042")
        sp.add_argument("--model", help="model profile name from harness.yaml")
        sp.add_argument("--posture", choices=["observe", "respond"], help="override ROE posture")

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
    m = sub.add_parser("memory", help="manage institutional memory")
    m.add_argument("action", choices=["stats", "list", "search", "review", "promote", "reject", "retire"])
    m.add_argument("rest", nargs="*")
    m.add_argument("--status")
    m.add_argument("--kind")
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
            print(await h.mission(text))
            if args.retro:
                print(await h.retro())
        asyncio.run(_with_harness(args, not args.non_interactive, go))
    elif args.cmd == "doctor":
        async def doc(h):
            _print_status(h)
            for n, prof in h.cfg.models.items():
                print(f"  model {n:16s} {prof.provider:14s} {prof.model} tool_mode={prof.tool_mode}")
            print()
            for t in h.registry.tools.values():
                tier, why = h.roe.classify(t.name, {}, t.annotations, t.server)
                print(f"  {tier:8s} {t.name:45s} {C['dim']}{why}{C['x']}")
        asyncio.run(_with_harness(args, False, doc))
    elif args.cmd in ("dashboard", "gui"):
        from .web.app import serve

        serve(_cfg(args), args.case, args.model, args.posture, args.host, args.port, args.tls_cert, args.tls_key,
              args.allow_plaintext)
    elif args.cmd == "memory":
        cmd_memory(args)
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
