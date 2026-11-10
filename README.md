# Compensated Anarchist

An agentic harness for **Defensive Cyber Operations**: hunt, triage, network and host analysis,
disk/memory forensics, malware triage, containment, detection engineering and reporting. It runs a
team of expert agents on **any model you choose** (local or gateway), connects to **Security Onion,
Splunk, Elastic, Velociraptor, MISP and OpenCTI** over MCP, drives **local forensic tools**, enforces
**rules of engagement in code**, **learns from every operation**, and has a **web dashboard** for
running operations and approving response actions. Conversations are **kept until you delete them**,
and the expert team **writes, scores and revises its own skills** as it works.

```
                       analyst (approves response actions, adjudicates findings, rates sessions)
                                           |
                     canarchist dashboard (web GUI)  |  chat  |  run
                                           |
     +------------------------ DCO Mission Lead (orchestrator) --------------------+
     |  subagent_spawn / subagent_message  ->  SA-001, SA-002 ... (parallel)       |
     |  <- structured reports (status, bottom line, evidence, recommended tasks)   |
     |  experts: alert_triage threat_hunter network_analyst endpoint_analyst       |
     |  forensicator malware_analyst cti_analyst incident_responder                |
     |  detection_engineer reporter          each with its own versioned skills    |
     +-----------------------------------------------------------------------------+
                  |  every tool call: expert allowlist -> ROE gate -> run -> audit
     +------------+-------------+-------------------------+---------------------------+
     | MCP connectors (stdio)   | local forensics          | case file + memory         |
     | security_onion  splunk   | volatility memprocfs     | IOCs timeline findings     |
     | elastic  velociraptor    | zimmerman tools  sigma   | evidence chain of custody  |
     | misp  opencti            | capa floss yara tshark   | memory + skills (SQLite)   |
     | + any 3rd-party MCP      | zeek plaso aleapp ileapp | chat history (kept)        |
     +--------------------------+--------------------------+---------------------------+
                  model profiles: vLLM / Ollama / llama.cpp / gateway / Anthropic ...
```

## Quick start

**Setting up the model and connectors:** follow [SETUP.md](SETUP.md). It covers a step-by-step for each system
(Security Onion, Elastic, Splunk, Velociraptor, MISP, OpenCTI, local tools) and the scope file.

```bash
./scripts/install.sh                                             # venv, install, config/.env, folders, doctor
$EDITOR config/.env                                              # models + connector credentials (SETUP.md)
# evidence for a case goes in forensics/<case-id>/ (created per case; the forensics playbook starts there)
set -a; source config/.env; set +a

.venv/bin/canarchist doctor    --case TEST                       # models, connectors, ROE tier per tool
.venv/bin/canarchist dashboard --case IR-2026-0042               # web GUI -> open the printed login URL
.venv/bin/canarchist chat      --case IR-2026-0042               # terminal console
.venv/bin/canarchist run    --case HUNT-0007 --playbook hunt "Kerberoasting against service accounts, last 14 days"
```

In `chat` you type to the **lead**, which plans and tasks expert subagents. `chat` and `dashboard` resume the
case's most recent conversation; pass `--new` for a fresh one or `--conversation <id>` for a specific one.
Useful commands: `/playbook`, `/subagents`, `/conversations`, `/new`, `/open <id>`, `/delete <id>`, `/skills`,
`/experts`, `/tools`, `/model <profile>`, `/case`, `/verdict FIN-0001 fp <why>`, `/remember`, `/retro`, `/rate`.

## Dashboard (web GUI)

`canarchist dashboard --case <id>` serves the operator console: a chat-first window in the spirit of Hermes
Agent, built around DCO work and branded red on black with the circled-A mark. It is a self-contained
single-page app (no CDNs, system fonts), so it works air-gapped, and nothing reloads the page.

- **Sign-in.** The terminal prints a sign-in link containing a token. The sign-in page shows your notice
  and consent text (`dashboard.consent_text`), which must be acknowledged, and the acknowledgement is
  audited. The token is posted once and stripped from the address bar; a GET never signs anyone in.
  Repeated failures from one address are throttled.
- **Classification banners.** Off by default. Turn one on in **Settings > Classification banner**: pick a
  standard marking (Unclassified, CUI, Confidential, Secret, Top Secret, TS//SCI) or write your own, adjust
  the colors with a live preview and contrast check, and save. It shows at the top and bottom of every
  page, sign-in included, for everyone using the dashboard, survives restarts, and each change is audited.
  `dashboard.classification` in `harness.yaml` sets the default; `locked: true` there pins it so the
  Settings page cannot change it.
- **Sidebar.** The case's conversations (switch in place, rename, delete with a typed confirmation), and
  pages for Skills, Memory, Audit log, Rules of engagement, Connectors and Settings, with badges for
  anything waiting on you.
- **Transcript.** Grouped by turn. The lead's work folds into a "Worked for 2 m 14 s" section of one-line
  steps (each expandable to its arguments and result); its answer is rendered markdown. Subagent reports
  appear as cards that open the subagent's own thread.
- **Streaming.** Replies appear word by word as the model writes them: the lead's in the transcript, each
  subagent's in its row of the subagents panel and in its open thread. When a reply is complete it is
  replaced by the rendered text in the same place. A browser that reloads or reconnects mid-reply picks up
  the text written so far. Streamed text is display-only; the saved conversation keeps the finished reply.
- **Subagents panel.** Above the message box: every subagent with live status, elapsed time and latest
  activity. **Steer** queues guidance that the subagent receives before its next step; **Stop** cancels
  that one subagent (the lead gets a "stopped" report and carries on).
- **Approvals.** A banner, an inline card and a review dialog with the action, target, ROE rule, the
  agent's action brief and the arguments. Approve takes a confirming second click; every decision and
  note goes into the hash-chained audit log.
- **Case panel.** Findings with verdicts, IOCs, timeline, evidence and the report, beside the transcript.
- **Status bar.** Posture, the lead's context use, tokens per second (generation speed, excluding the wait
  for the first token, which is shown on hover), connector health, approvals waiting, audit-chain state.
- **Keyboard.** Ctrl+K command palette (conversations, subagents, playbooks, pages, models), Ctrl+Shift+O
  new conversation, Ctrl+. case panel, Ctrl+/ shortcuts, `/` to focus the message box, Esc to close.
- **Themes.** Dark (default), light, or match the system, from Settings or the palette.
- **Security.** Stricter than a typical local dashboard, because this one approves response actions:
  - A token is always required, even on localhost. Sign-in turns it into an HttpOnly, SameSite=Strict
    session cookie; you can fix the token with `CA_DASHBOARD_TOKEN`.
  - Every state change needs a CSRF header.
  - A strict CSP: no inline script or style attributes, no framing, nothing loaded from outside.
  - Binding beyond localhost requires `--tls-cert/--tls-key`.
  - Agent, log and tool text is built into the page with DOM text nodes, never HTML, because adversaries
    control that data.

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
- Both providers stream (`stream: true`, the default). The CLI prints the lead's reply as it is written
  when attached to a terminal (`CA_NO_STREAM=1` turns that off). If an OpenAI-compatible gateway rejects a
  streaming request while the same request works without streaming, the backend stops asking for the rest
  of the session. Set `stream: false` to never ask. In `tool_mode: text`, `<tool_call>` blocks are held
  back from the stream and only the surrounding prose is shown.
- `context_tokens` drives automatic history compaction. Tool output above `max_tool_result_chars` is
  written to the case directory and paged on demand, which keeps small-context local models usable.

## Expert agents: orchestrator and subagents

Each expert is a markdown file in `compensated_anarchist/experts/` containing a prompt and frontmatter
(tool allowlist globs, optional model, step budget). To add your own or override one, put a `.md` file in
`config/experts/`.

The lead is the **orchestrator**, and experts run as its **subagents**:

- **Spawning.** `subagent_spawn(expert, task, context, expected_output)` creates a subagent with an id
  (`SA-001`…), a scoped brief, and its own context window. The brief includes the relevant memories and
  skills. Several spawns in one turn run in parallel, up to `orchestration.max_parallel`.
- **Follow-ups.** `subagent_message(id, message)` goes back to the same subagent with a follow-up, a
  correction or a related task. It still has its earlier work, even after a restart. `subagent_list`
  shows the roster.
- **Reporting.** Subagents report only to the orchestrator and finish every task with `submit_report`:
  status (completed / blocked / needs_input / failed), bottom line, evidence, confidence, open questions,
  recommended tasks and skills used. A model that skips the tool still has its free-text answer passed
  on, marked as unstructured.
- **Limits.** Subagents cannot spawn agents. When they need another expert they recommend the task, and
  the orchestrator decides. Each subagent only sees its expert's allowlisted tools.

## Chat history

Every conversation is saved: the feed you saw, plus the orchestrator's and every subagent's model
context. Nothing expires; a conversation stays until you delete it.

- **Resuming.** `chat` and `dashboard` resume the latest conversation for the case, with the lead and all
  subagents restored.
- **Browsing.** `canarchist history list [--case X]` and `history show <id>`, or the dashboard's
  conversation list.
- **Deleting.** `canarchist history delete <id>` (type the id to confirm), `/delete <id>` in chat, or the
  ✕ in the dashboard. This removes the conversation's feed, the agent contexts and its transcripts. The
  database uses `secure_delete`, so deleted chat is overwritten.
- **What deletion keeps.** The case record (findings, IOCs, timeline, evidence), the hash-chained audit
  log, and the memories and skills learned from the conversation. Those are the case file and the
  accountability record. The deletion itself is audited.

The store is `history.db_path` (default `cases/_history.db`).

## Connectors (MCP)

The harness starts the bundled servers as stdio subprocesses (`mcp_servers:` in harness.yaml). Their tools
appear as `<server>__<tool>`. Any third-party MCP server can be added with `command:` or `url:`. Connector
stderr goes to `cases/<id>/logs/`.

| server | backend | highlights |
|---|---|---|
| `security_onion` | Security Onion 3, via its Elasticsearch data streams (`logs-*-so`, a read-only API key or SOC account, a firewall host group for :9200). **Tested against a live 3.4.0 grid** | alert summary (Suricata + SO Detections), Zeek/Suricata search, ES\|QL, community_id pivot, beacon candidates, IOC sweep, field stacking, data stream inventory. SO Pro's official MCP server can be added alongside it |
| `splunk` | REST :8089, token auth | SPL oneshot search, data inventory (tstats), field summary, IOC sweep, ES notables. Write/exec SPL commands are refused |
| `elastic` | Elasticsearch / Elastic Security, API key. **Tested against a live 9.x cluster** (Kibana detection alerts verified on mocks only) | query_string, DSL, ES\|QL, EQL sequences, alerts + summary, stacking, IOC sweep, index inventory |
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
- **Downloads.** Collected files land in the vault, `<first evidence root>/vault/velociraptor/<client>/<flow>/`,
  inside the forensic jail, so Volatility, YARA and the other local tools can read (never run) them.
- **No injection.** Tool arguments reach VQL only as parameters. They are prefixed `Ca…` because plain
  names collide with VQL builtins (`Artifact`) and keywords (`DESC`).
- **Artifact names.** `Windows.KapeFiles.Targets` is no longer built in as of 0.77; import it with
  `Server.Import.Extras`. Full-memory acquisition is built in for Windows only. On Linux, use
  `Linux.Triage.ProcessMemory`.
- **Remote shells.** Shell artifacts (`*.System.PowerShell`, `*.System.CmdShell`, `*.Sys.BashShell`) are
  set to `deny` in roe.yaml. Change them to `approve` only if your ROE permits remote command execution.
- **Human in the loop.** Every collection, hunt, memory image, evidence download, label, quarantine and server-VQL
  call needs an analyst's approval, enforced in code so `roe.yaml` cannot lower it. Files pulled from endpoints
  land in the evidence vault (`evidence/vault/`): read-only, never executable, executables renamed
  `.quarantined`, every file in `MANIFEST.jsonl`. See SETUP.md section 5.
- **Re-verify.** To re-check the connector against your own server version, run:
  `CA_VELO_API_CONFIG=api.yaml CA_VELO_ADMIN_API_CONFIG=admin.yaml pytest tests/test_velociraptor_live.py`

**Security Onion / Elastic notes (verified live against Security Onion 3.4.0):**
- **Field layout.** Zeek logs are `event.dataset:zeek.conn`, `zeek.dns` and so on, not `event.dataset:conn`.
  Suricata alerts are in `logs-suricata.alerts-so` and SO Detections (Sigma/YARA) in
  `logs-detections.alerts-so`. Both carry `event.severity_label`.
- **Least privilege.** A read-only API key (index privilege `read` only) is enough. The inventory tools fall back
  to a read-only aggregation when `_cat` and `_data_stream` are forbidden.
- **ES|QL width.** Null columns are dropped (`drop_null_columns`). Without `KEEP`, a single row can still
  carry dozens of fields.
- **Re-verify.** To re-check the connectors against your own grid, run:
  `CA_LIVE_ES_URL=https://so:9200 CA_LIVE_ES_API_KEY=... CA_LIVE_ES_VERIFY=/path/ca.crt CA_LIVE_SO=1 pytest tests/test_siem_live.py`

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
5. **Skills.** These are versioned procedures (`SKILL.md` format: name, when to use, steps) owned by an
   expert, `shared`, or `lead` for orchestration patterns.
   - **Using them.** A subagent's brief lists the approved skills relevant to its task. It loads one with
     `skill_view` and reports whether it worked (`skill_feedback`, or `skills_used` in its report).
   - **Improving them.** When a skill was wrong it proposes a fix (`skill_update`, with a change note).
     When it works out a reusable procedure it saves one (`skill_create`).
   - **Scoring.** Your session rating settles any skill use still open: 4-5 counts as worked, 1-2 as
     failed. Skills that fail more often than they work are flagged in every brief and in the retro.
   - **Retro.** `/retro` first asks every subagent to reflect on its own work and revise its skills. The
     orchestrator then writes lessons, fixes struggling skills, and can write skills for any expert
     (`for_expert`).
   - **Review.** Agent-written skills and revisions wait for your review (`canarchist skills review`, or
     the Skills tab). Skills are instructions to the team, and agents learn from attacker-controlled
     data. `skills.require_approval: false` turns auto-approve on.
   - **Management.** Every version is kept for diff and rollback (`skills rollback <name> <v>`).
     `skills export <dir>` and `skills import <dir>` move them as SKILL.md files, for git or for
     analyst-written skills, which are approved on import.
6. **Fine-tuning data.** Every agent's full transcript is saved per session. `/rate 1-5` grades the
   session, and `canarchist export-training --min-rating 4` exports those runs as chat-format JSONL
   (messages + tools). You can use that to SFT/LoRA your local models on your own successful DCO work.

## Layout

```
compensated_anarchist/
  agent.py          agent loop, compaction, orchestrator + subagents, Harness
  history.py        persistent conversations (feed + agent contexts), kept until deleted
  skills.py         expert skills: versions, review, retrieval, scoring, SKILL.md import/export
  roe.py audit.py   ROE gate + approvals, hash-chained audit log (safe for several writer processes)
  memory.py case.py learning memory, case file / chain of custody / report
  llm/              openai_compat, anthropic, text-mode tool calling
  tools/            registry/executor, local forensics
  servers/          MCP servers: security_onion, splunk, elastic, velociraptor, misp, opencti
  web/              dashboard (Starlette app + self-contained single-page UI, sign-in page, logo)
  experts/ prompts/ playbooks/
config/             harness.yaml, roe.yaml, env.example
tests/              end-to-end (real MCP subprocess, scripted model) + unit tests
```

Run tests: `.venv/bin/python -m pytest -q`

## Known limits / next steps

- **Live-verified:** Velociraptor (except quarantine, which was deliberately not run on the dev
  workstation), Security Onion 3.4.0 and Elastic (read-only API key), sigma-cli and capa.
- **Untested beyond its safety check:** Splunk. Only the SPL write/exec blocklist has a test; search and
  response handling have never run against Splunk or a mock of it.
- **Tested against mock servers or stand-in tools only:** MISP and OpenCTI (mock HTTP servers built from
  their documented APIs and the official pycti queries), Elastic Security detection alerts, plus the
  Zimmerman tools, FLOSS, MemProcFS and ALEAPP/iLEAPP stand-ins. Validate against your instances.
- SOC-native Security Onion features (cases, PCAP jobs, OQL) need SO Pro's Connect API / official MCP server.
- The dashboard serves one case per process. Run several on different ports for parallel cases.
- **Approvals and reviews are attributed to the configured operator, not to whoever clicked.** That covers
  response-action approvals, skill and memory reviews, and conversation deletions. Per-analyst identity
  (CAC / client-certificate login) is the next hardening step for multi-analyst use.
- The orchestration and skill loop is tested with a scripted model. How well a given local model uses
  `submit_report` and writes useful skills has not been measured yet.
