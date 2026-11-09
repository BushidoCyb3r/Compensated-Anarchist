# Compensated Anarchist

An agentic harness for **Defensive Cyber Operations**: hunt, triage, network and host analysis,
disk/memory forensics, malware triage, containment, detection engineering and reporting. It runs a
team of expert agents on **any model you choose** (local or gateway), connects to **Security Onion,
Splunk, Elastic, Velociraptor, MISP and OpenCTI** over MCP, drives **local forensic tools**, enforces
**rules of engagement in code**, **learns from every operation**, and has a **web dashboard** for
running operations and approving response actions.

```
                       analyst (approves response actions, adjudicates findings, rates sessions)
                                           |
                     canarchist dashboard (web GUI)  |  chat  |  run
                                           |
     +----------------------------- DCO Mission Lead ------------------------------+
     |  delegate (parallel)                                                        |
     |  alert_triage  threat_hunter  network_analyst  endpoint_analyst  forensicator|
     |  malware_analyst  cti_analyst  incident_responder  detection_engineer reporter
     +-----------------------------------------------------------------------------+
                  |  every tool call: expert allowlist -> ROE gate -> run -> audit
     +------------+-------------+-------------------------+---------------------------+
     | MCP connectors (stdio)   | local forensics          | case file + memory         |
     | security_onion  splunk   | volatility memprocfs     | IOCs timeline findings     |
     | elastic  velociraptor    | zimmerman tools  sigma   | evidence chain of custody  |
     | misp  opencti            | capa floss yara tshark   | SQLite FTS memory          |
     | + any 3rd-party MCP      | zeek plaso aleapp ileapp |                            |
     +--------------------------+--------------------------+---------------------------+
                  model profiles: vLLM / Ollama / llama.cpp / gateway / Anthropic ...
```

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[all]'     # or just -e . for the core
cp config/env.example config/.env && $EDITOR config/.env         # models + connector credentials
set -a; source config/.env; set +a
mkdir -p evidence                                                # put evidence here (read-only jail)

.venv/bin/canarchist doctor    --case TEST                       # models, connectors, ROE tier per tool
.venv/bin/canarchist dashboard --case IR-2026-0042               # web GUI -> open the printed login URL
.venv/bin/canarchist chat      --case IR-2026-0042               # terminal console
.venv/bin/canarchist run    --case HUNT-0007 --playbook hunt "Kerberoasting against service accounts, last 14 days"
```

In `chat` you type to the **lead**, which plans and delegates. Useful commands: `/playbook`, `/experts`,
`/tools`, `/model <profile>`, `/case`, `/verdict FIN-0001 fp <why>`, `/remember`, `/retro`, `/rate`.

## Dashboard (web GUI)

`canarchist dashboard --case <id>` serves a local web console, like Hermes Agent's `hermes dashboard`.
It prints a login URL containing a one-time token. Everything is self-contained, with no CDNs, so it
works air-gapped.

- **Live operation feed.** Your tasking, the lead's plans and situation reports, expert delegations
  (several run in parallel), every tool call with its ROE tier, denials with reasons, and expandable
  result previews.
- **Approval queue.** A response action that needs approval shows its target and arguments, the
  agent's action brief, and a note field. Approving takes two clicks; Deny is one. Decisions and
  notes go into the hash-chained audit log, and denials feed learning.
- **Case panels.** Findings with TP/FP/benign/inconclusive verdict buttons, IOCs, timeline, the
  evidence register, memory review (promote or reject agent-written candidates, add knowledge), audit
  log with chain verification, the ROE table for every tool, and the report.
- **Controls.** Model switcher, playbook launcher, Stop (cancels cleanly and repairs the conversation),
  after-action review and session rating.
- **Security.** Stricter than a typical local dashboard, because this one approves response actions:
  - A token is always required, even on localhost. It becomes an HttpOnly, SameSite=Strict session
    cookie, and you can fix it with `CA_DASHBOARD_TOKEN`.
  - Every state change needs a CSRF header.
  - A strict CSP: no inline script, no framing, nothing loaded from outside.
  - Binding beyond localhost requires `--tls-cert/--tls-key`.
  - Agent, log and tool text is rendered as text, never HTML, because adversaries control that data.

## Any model

Model profiles live in `config/harness.yaml` and you switch with `--model`, `CA_MODEL` or `/model`:

| provider | covers | notes |
|---|---|---|
| `openai_compat` | vLLM, Ollama, llama.cpp, LM Studio, TGI, LiteLLM, enterprise / government AI gateways, OpenAI-compatible cloud APIs | `ca_bundle` + `client_cert`/`client_key` for DoD PKI / mTLS; `api_key_header` for non-Bearer keys |
| `anthropic` | Claude via the official SDK | adaptive thinking, refusal fallbacks enabled |

- `tool_mode: native` uses function calling. For vLLM, start the server with
  `--enable-auto-tool-choice --tool-call-parser hermes` (or the parser for your model).
- `tool_mode: text` serves models without function calling. Tools go into the prompt and the model replies with
  Hermes-style `<tool_call>{...}</tool_call>`. Native mode also falls back to parsing these tags when a model
  leaks them into its text.
- Each expert can run on a different model (`experts.overrides`), e.g. a large model for the lead and
  hunter, and a small fast one for triage.
- `context_tokens` drives automatic history compaction. Tool output above `max_tool_result_chars` is
  written to the case directory and paged on demand, which keeps small-context local models usable.

## Expert agents

Each expert is a markdown file in `compensated_anarchist/experts/` containing a prompt and frontmatter
(tool allowlist globs, optional model, step budget). To add your own or override one, put a `.md` file in
`config/experts/`. The lead runs experts in parallel by issuing several `delegate` calls in one turn.
Experts cannot delegate further, and each one only sees its own allowlisted tools.

## Connectors (MCP)

The harness starts the bundled servers as stdio subprocesses (`mcp_servers:` in harness.yaml). Their tools
appear as `<server>__<tool>`. Any third-party MCP server can be added with `command:` or `url:`. Connector
stderr goes to `cases/<id>/logs/`.

| server | backend | highlights |
|---|---|---|
| `security_onion` | Security Onion 3, via its Elasticsearch data streams (`logs-*-so`, SOC credentials, a firewall host group for :9200) | alert summary, Zeek/Suricata search, ES\|QL, community_id pivot, beacon candidates, IOC sweep, field stacking, data stream inventory. SO Pro's official MCP server can be added alongside it |
| `splunk` | REST :8089, token auth | SPL oneshot search, data inventory (tstats), field summary, IOC sweep, ES notables. Write/exec SPL commands are refused |
| `elastic` | Elasticsearch / Elastic Security | query_string, DSL, ES\|QL, EQL sequences, alerts + summary, stacking, IOC sweep |
| `velociraptor` + `velociraptor_admin` | gRPC API (`config api_client`). **Tested against a live 0.77.3 server** | 19 tools split by privilege. Investigator key: clients, client flow history, artifact search and detail, collect (wait + results), flow status/logs/results/uploads, labels, cancel, hunts, memory acquisition (Windows). Admin key: **evidence download with SHA-256 and size verification**, quarantine/unquarantine (Windows/Linux/macOS), server VQL |
| `misp` | MISP REST API, auth key | IOC lookup (events, threat level, galaxy/ATT&CK tags), **warninglist check** (known-benign), event search and detail, sightings. Events it creates are always unpublished and org-only |
| `opencti` | OpenCTI GraphQL, read-only token | IOC lookup (observables, indicators, score, kill chain, related intrusion sets/malware), entity search (actors, malware, campaigns, ATT&CK patterns, reports), relationships, read-only GraphQL escape hatch (mutations refused) |

Use least-privilege accounts. For example, a read-only ES role, a Splunk role without `delete_by_keyword`,
and a Velociraptor `investigator,api` client.

**Velociraptor notes (all verified live):**
- **Least privilege.** Two connector entries use two API keys. `velociraptor` uses an
  `investigator,api` key and exposes 15 tools. `velociraptor_admin` uses an `administrator,api` key and
  exposes only download, quarantine, unquarantine and server VQL. Only the incident responder gets all
  admin tools; the forensicator and endpoint analyst get download only. With a single admin key, point
  both entries at it.
- **New API users.** A running server only sees API users created with `config api_client` after a
  restart. Without one, the connector reports `User not found`.
- **Downloads.** Collected files land in `<first evidence root>/velociraptor/<client>/<flow>/`, inside the
  forensic jail, so Volatility, YARA and the other local tools can open them directly.
- **No injection.** Tool arguments reach VQL only as parameters. They are prefixed `Ca…` because plain
  names collide with VQL builtins (`Artifact`) and keywords (`DESC`).
- **Artifact names.** `Windows.KapeFiles.Targets` is no longer built in as of 0.77; import it with
  `Server.Import.Extras`. Full-memory acquisition is built in for Windows only. On Linux, use
  `Linux.Triage.ProcessMemory`.
- **Remote shells.** Shell artifacts (`*.System.PowerShell`, `*.System.CmdShell`, `*.Sys.BashShell`) are
  set to `deny` in roe.yaml. Change them to `approve` only if your ROE permits remote command execution.
- **Re-verify.** To re-check the connector against your own server version, run:
  `CA_VELO_API_CONFIG=api.yaml CA_VELO_ADMIN_API_CONFIG=admin.yaml pytest tests/test_velociraptor_live.py`

## Local forensics

| tool | what | verified |
|---|---|---|
| `local_ez_tool` | Eric Zimmerman parsers to CSV (MFTECmd, PECmd, LECmd, JLECmd, AmcacheParser, AppCompatCacheParser, RECmd + batch, SBECmd, SrumECmd, EvtxECmd, RBCmd, WxTCmd, SQLECmd, bstrings) via `dotnet` or native | stand-in (.NET not on dev box) |
| `local_sigma_convert` / `local_sigma_check` | Sigma to SPL / ES\|QL / EQL / Lucene / KQL (Sentinel, Defender) with the right pipelines | **real sigma-cli** |
| `local_memprocfs` | MemProcFS: process tree, netstat, **FindEvil**, forensic timelines, VFS browse; runs in an isolated subprocess | stand-in (no memory image) |
| `local_capa` | capabilities mapped to ATT&CK and MBC, from parsed JSON | **real capa 10** |
| `local_floss` | decoded, stack and tight strings | stand-in (FLOSS needs a compiler to install here) |
| `local_leapp` | ALEAPP (Android) and iLEAPP (iOS); returns the artifacts found | stand-in |
| `local_volatility`, `local_yara_scan`, `local_strings`, `local_tshark`, `local_zeek`, `local_evtx_hunt`, `local_plaso_timeline`, `local_exiftool`, `local_read_file`... | as named | |
| `local_run` | allowlisted binaries (Sleuth Kit, bulk_extractor, ...) | |

- No shell is ever used: every command is an argv list.
- Reads are jailed to `evidence_roots` and the case directory, and outputs go to `cases/<id>/artifacts/`.
- `local_tools_inventory` shows what is installed. Missing tools fail gracefully.

## Rules of engagement (`config/roe.yaml`)

The ROE gate runs in code, so the model cannot talk its way past it.

- **Tiers:** `auto` / `notify` / `approve` / `deny`, assigned by first-match glob rules. Rules can also
  match on argument values. For example, collecting `Windows.System.Pslist` is `notify` while any other
  artifact is `approve`.
- **Posture:** `observe` denies every approval-tier action. `respond` allows them with analyst approval.
- **Scope:** `allowed_targets` (CIDRs, host globs, client ids). An active action against anything outside
  scope is denied without asking. `protected_assets` always escalate to approval.
  - Velociraptor client ids are resolved live to hostname, FQDN and last IP, so CIDR and hostname rules
    apply to endpoint actions.
  - An id that can't be resolved is denied (fail closed). This was verified against a live server.
- **Defaults:** unknown tools default to `approve`. MCP annotations are trusted only from your own servers.
- **Audit:** every decision, approval (with the analyst's note), result hash, memory write and verdict goes
  into `cases/<id>/audit.jsonl`. The log is hash-chained, so `canarchist audit-verify --case <id>` detects
  any edit or deletion.
- **Untrusted data:** tool output is wrapped as untrusted data, and agents are instructed to treat
  instructions found in logs or files as a sign of adversary activity, never to follow them.

## How it learns

1. **Institutional memory** is stored in SQLite FTS5, so it works air-gapped with no embedding model.
   It holds environment facts, proven queries, false-positive patterns, observed TTPs, lessons, analyst
   feedback and playbook improvements. Relevant memories are injected at mission start and into every
   expert's tasking. Agents also search memory before writing new queries.
2. **Analyst signal becomes knowledge:**
   - A denied action becomes approved `feedback` memory.
   - `/verdict … fp|benign` becomes approved `false_positive` memory.
   - `/remember` adds knowledge directly.
   - `memory_feedback` re-ranks retrieval.
3. **`/retro`** runs an after-action review. The lead distills the operation into one-fact memories.
4. **Poisoning defense.** Agent-written memories are stored as `candidate` and are not used until an
   analyst runs `canarchist memory review` (or `promote`). Adversaries control the data your agents read,
   so don't let them write your agent's beliefs.
5. **Fine-tuning data.** Every agent's full transcript is saved per session. `/rate 1-5` grades the
   session, and `canarchist export-training --min-rating 4` exports those runs as chat-format JSONL
   (messages + tools). You can use that to SFT/LoRA your local models on your own successful DCO work.

## Layout

```
compensated_anarchist/
  agent.py          agent loop, compaction, delegation, Harness
  roe.py audit.py   ROE gate + approvals, hash-chained audit log
  memory.py case.py learning memory, case file / chain of custody / report
  llm/              openai_compat, anthropic, text-mode tool calling
  tools/            registry/executor, local forensics
  servers/          MCP servers: security_onion, splunk, elastic, velociraptor, misp, opencti
  web/              dashboard (Starlette app + self-contained static UI)
  experts/ prompts/ playbooks/
config/             harness.yaml, roe.yaml, env.example
tests/              end-to-end (real MCP subprocess, scripted model) + unit tests
```

Run tests: `.venv/bin/python -m pytest -q`

## Known limits / next steps

- **Live-verified:** Velociraptor (except quarantine, which was deliberately not run on the dev
  workstation), sigma-cli and capa.
- **Tested against mock servers or stand-in tools only:** Security Onion 3, Splunk, Elastic, MISP and
  OpenCTI (mock HTTP servers built from their documented APIs and the official pycti queries), plus the
  Zimmerman tools, FLOSS, MemProcFS and ALEAPP/iLEAPP stand-ins. Validate against your instances.
- SOC-native Security Onion features (cases, PCAP jobs, OQL) need SO Pro's Connect API / official MCP server.
- The dashboard serves one case per process. Run several on different ports for parallel cases.
