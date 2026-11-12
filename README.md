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
     |  forensicator malware_analyst cti_analyst incident_responder cte_planner    |
     |  detection_engineer reporter hunt_planner vuln_assessor code_writer         |
     |                                       each with its own versioned skills    |
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
scripts/start.sh     # first run: builds everything (install.sh) and asks you to create the dashboard account;
                     # every run: asks posture / address / case (Enter keeps your last choice), then prints
                     # the sign-in link with a NEW access token (your data is kept)
scripts/stop.sh      # stops it; cases, conversations, memory, skills and audit logs stay
```

```bash
./scripts/install.sh                                             # (start.sh runs this on the first run)
$EDITOR config/.env                                              # models + connector credentials (SETUP.md)
# evidence for a case goes in forensics/<case-id>/ (created per case; the forensics playbook starts there)
.venv/bin/canarchist attack fetch                                # MITRE ATT&CK data for actor-based hunt plans (optional)
.venv/bin/canarchist doctor    --case TEST                       # models, connectors, ROE tier per tool
scripts/start.sh --case IR-2026-0042                            # web GUI -> open the printed sign-in link
.venv/bin/canarchist chat      --case IR-2026-0042               # terminal console
.venv/bin/canarchist run    --case HUNT-0007 --playbook hunt "Kerberoasting against service accounts, last 14 days"
```

In `chat` you type to the **lead**, which plans and tasks expert subagents. `chat` and `dashboard` resume the
case's most recent conversation; pass `--new` for a fresh one or `--conversation <id>` for a specific one.
Useful commands: `/playbook`, `/subagents`, `/conversations`, `/new`, `/open <id>`, `/delete <id>`, `/skills`,
`/experts`, `/tools`, `/model <profile>`, `/case`, `/verdict FIN-0001 fp <why>`, `/remember`, `/retro`, `/rate`,
and `/resume` or `/end` for an operation that a crash or Ctrl+C cut off. `canarchist export-docx <file.md>` writes a
report or plan as a Word document.

## Dashboard (web GUI)

`scripts/start.sh` (or `canarchist dashboard --case <id>` in the foreground) serves the operator console: a chat-first window in the spirit of Hermes
Agent, built around DCO work and branded red on black with the circled-A mark. It is a self-contained
single-page app (no CDNs, system fonts), so it works air-gapped, and nothing reloads the page.

- **Sign-in.** `scripts/start.sh` prints a sign-in link containing this start's access token; you also enter the
  dashboard account's username and password. The sign-in page shows your notice
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
  appear as cards that open the subagent's own thread. Long conversations stay fast: the newest 40 turns are in
  the page, and earlier ones come back as you scroll up (or press **Show earlier turns**). Turns off screen are
  not laid out until you reach them.
- **Streaming.** Replies appear word by word as the model writes them: the lead's in the transcript, each
  subagent's in its row of the subagents panel and in its open thread. When a reply is complete it is
  replaced by the rendered text in the same place. A browser that reloads or reconnects mid-reply picks up
  the text written so far. Streamed text is display-only; the saved conversation keeps the finished reply.
- **Subagents panel.** Above the message box: every subagent with live status, elapsed time and latest
  activity. **Steer** queues guidance that the subagent receives before its next step; **Stop** cancels
  that one subagent, also while it waits for a free slot (the lead gets a "stopped" report and carries on). The
  composer's Stop ends the whole operation: the lead, every subagent, and any process their tools started
  (a plaso run or a scan, with its worker processes).
- **Approvals.** A banner, an inline card and a review dialog with the action, target, ROE rule, the
  agent's action brief and the arguments. Approve takes a confirming second click; every decision and
  note goes into the hash-chained audit log, with the signed-in user who made it.
- **Restarts don't lose work.** Every agent saves its place after each step, and every approval request is
  saved. If the dashboard stops (or crashes) mid-operation, the next start shows the operation as **interrupted by
  a restart**, with the approvals it was waiting for. Deciding one of them carries the operation on, and the
  decision is applied when the agent gets back to that action. **Resume** carries it on without one: each agent
  continues from where it stopped, a subagent that had finished hands back its report instead of running again,
  and tool calls that had no result are decided by the ROE again. **End it** closes the operation instead, and so
  does sending a new task. Stop is different: it ends an operation for good.
- **Case panel.** Findings with verdicts, IOCs, timeline, evidence and the report, beside the transcript. In the
  report, every citation (`[FIN-0001]`, `[EV-12]`, `[FILE:hunt_plan_x.md]`) opens the mission data it points at,
  with a link to the item in the case panel. **Word (.docx)** exports the report; every markdown plan and report
  in Plans & reports has the same button.
- **Status bar.** Posture, the lead's context use, tokens per second (generation speed, excluding the wait
  for the first token, which is shown on hover), connector health, approvals waiting, audit-chain state.
- **Keyboard.** Ctrl+K command palette (conversations, subagents, playbooks, pages, models), Ctrl+Shift+O
  new conversation, Ctrl+. case panel, Ctrl+/ shortcuts, `/` to focus the message box, Esc to close. The first
  Tab stop skips to the message box; arrow keys move between tabs and menu items.
- **Accessibility.** Text meets WCAG AA contrast in both themes, and every control can be reached and used from
  the keyboard with a visible focus ring. Redraws keep your focus where it was, dialogs return it when they close,
  and a new approval is announced once to screen readers. `tests/test_accessibility.py` checks the colors, and
  drives headless Chrome through a keyboard-only walk-through and a rendered-page audit (names, ARIA references,
  contrast in both themes) whenever Chrome is installed.
- **Themes.** Dark (default), light, or match the system, from Settings or the palette.
- **Security.** Stricter than a typical local dashboard, because this one approves response actions:
  - Signing in takes both the access token, which is new at every start, and the dashboard account's username
    and password, even on localhost. The account is created once on the host (the first `scripts/start.sh` asks;
    `canarchist account create | passwd | reset`), and its password is stored only as a salted scrypt hash in
    `config/secrets/` (mode 600).
  - A sign-in becomes a random server-side session in an HttpOnly, SameSite=Strict cookie. It ends after
    `dashboard.session_idle_hours` (12) without analyst activity, on sign-out, and whenever the dashboard
    restarts. Failed sign-ins are throttled and audited.
  - Every state change needs a CSRF header.
  - A strict CSP: no inline script or style attributes, no framing, nothing loaded from outside.
  - Binding beyond localhost requires TLS. `scripts/start.sh` makes a self-signed certificate for the host's
    address, renews it before it expires, and prints its fingerprint to check against the browser warning.
  - Agent, log and tool text is built into the page with DOM text nodes, never HTML, because adversaries
    control that data.

## Any model

Model profiles live in `config/models.yaml`, and each one is a choice in the dashboard's model picker. It ships
with GenAI (government / enterprise gateway), Claude, ChatGPT and local-server profiles, plus a `my-local-model`
template to fill in. Site profiles go in `config/models.local.yaml` (git-ignored, merged over it). Edits show up
in a running dashboard without a restart, and profiles still missing a key or a `CHANGE-ME` value show as
"needs setup". Switch with the picker, `--model`, `CA_MODEL` or `/model`:

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
- **Operations and approvals.** Each operation run in a conversation is recorded with how it ended (done,
  stopped, failed, interrupted, ended), and so is every approval request with its outcome and who decided it.
  An operation a restart cut off can be resumed from the agents' last checkpoints (dashboard **Resume**, or
  `/resume` in `chat`).

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

## Vulnerability assessment (every action approved)

The `vulnerability_assessment` playbook and the `vuln_assessor` expert assess in-scope hosts and write a
vulnerability report with the most likely attack chains (mapped to ATT&CK, with the cheapest fix that breaks each
chain). The assessor can use every connector, plus command-line scanners through `vuln_run`. On a Kali VM those
are all installed (nmap, nuclei, nikto, testssl.sh, sslscan, enum4linux-ng, whatweb, gobuster, searchsploit, ...).

- **The analyst approves every action**, reads included (see the built-in floors under the rules of engagement
  below). Approval prompts show the exact command line.
- **`vuln_run` checks each command itself**, beyond the approval:
  - one allowlisted program, argv only (no shell);
  - every host in the arguments must be listed in `targets` and sit inside `scope.allowed_targets`
    (hostnames: every address they resolve to). No scope, no scanning;
  - no target ranges or target-list files;
  - exploit, brute-force, DoS and upload options are refused;
  - paths stay in the case folder (or read-only data such as wordlists);
  - a minimal environment, so no API keys reach the tools; a timeout.
- **Outputs:** the full output of every command is kept in `cases/<id>/vuln_assessment/raw/`. The report is
  saved as `vuln_report_<name>.md`, with an Open button in the dashboard.
- **Limits:** no exploitation, password attacks or denial of service, by design. Configure the allowlist, extra
  refused options and timeouts under `vuln_assessment:` in `harness.yaml`.

## Threat emulation plans (defensive, plans only)

The `cte_plan` playbook and the `cte_planner` expert plan a cyber threat emulation that tests whether your sensors
detect an adversary. You give two things: **the adversary** (a name, alias or ATT&CK G-id) and **the network** (its
type, or a map dropped into `cases/<id>/cte_plans/maps/`: CSV asset list, nmap XML, draw.io, Visio `.vsdx` or text,
all read with the standard library). The planner does the rest and asks only when one of the two is missing or
ambiguous.

- **Plans only, no exploitation.** It never runs anything and writes no exploit code or commands. Steps name the
  emulation tool by reference: an Atomic Red Team test number (from a local checkout, `cte.atomics_dir`) or a Mythic
  command. Exploitation (T1190, T1203, T1068, T1210-T1212, T1189) and destructive or disruptive impact are listed
  as **not emulated**, each with its detection opportunity.
- **Every step traces to ATT&CK** for that adversary, to your intel (`intel: <source>`), or to you
  (`analyst-added`). `cte_plan_save` checks the plan against the ATT&CK data and refuses one that breaks these
  rules. It needs the ATT&CK file (`data/attack/enterprise-attack.json`).
- **Each step** gives the documented procedure, the target systems, prerequisites, expected artifacts, the
  detection opportunity on the connected sensors (telemetry gaps are listed), success criteria and cleanup. The
  plan also has scope, deconfliction and stop conditions, and an ATT&CK Navigator layer.
- **After your operators run it**, the threat_hunter checks what was detected and the planner saves
  `cte_results_<adversary>.md` (detected / partially / missed per step). Missed steps go to the
  detection_engineer, and the planner remembers them for the next plan.

## Reports from mission data only

The `report` playbook and the `reporter` expert write reports in your format from this mission's data, and nothing
else.

- **Your format.** Drop old reports into `reports/examples/<report type>/` (`.docx`, `.md`, `.txt`; git-ignored).
  The reporter derives a template per type (`report-template-<type>`, a skill you approve) from sections, order,
  required fields, tables, tone and length. Old reports are format only: never a fact source.
- **Mission data only, every fact cited.** Sources are the case record, your answers (analyst statements), the
  conversations and tool results, and the case's files. `report_save` checks each draft before saving it: every
  citation exists; every IP, hash, domain, path, CVE, T-code, timestamp, reference number, count and `code` value
  is in a cited source; nothing factual is uncited; no value from the example reports leaks in; classification
  markings appear only if you gave them. A draft that fails is not saved.
- **Ask, don't guess.** What the data can't support goes in the draft's Questions / gaps section and comes back to
  you as questions. Your answers are recorded as statements (`STA-nnnn`, quoted from your own messages) and cited.
- **Versions and final.** Drafts are `cases/<id>/reports/report_<name>_v<N>.md`. You can edit them; the reporter
  reads your edits and proposes lessons. `report_finalize` saves the final copy and needs your approval.
- **Citations you can follow.** In the dashboard every citation opens the cited mission data.
- **Word.** The dashboard's **Word (.docx)** button, or `canarchist export-docx <report.md>`, writes the report as a
  Word document (standard library, no extra package). The Sources section goes with it; the internal Verification
  section does not. A draft says at the top that it is not yet approved. A classification marking on the report's
  first line, which is only there if you gave it, goes into the page header and footer. Exports are audited.

## Code for the mission (written, reviewed, never run)

The `code` playbook and the `code_writer` expert write the scripts, parsers, Velociraptor VQL artifacts and analyst
tools a mission needs.

- **Written against reality:** real field names (`field_values`), a real sample of the input from the case evidence,
  and existing Velociraptor artifacts. Unknown platform facts become a question, not a guess.
- **Secure and simple by design:** two always-on skills, `ponytail` (the smallest complete change) and `dco-code`:
  - a short design before coding;
  - evidence treated as hostile input (no eval, no shell, validated and size-capped);
  - path, secret, output-escaping and privilege rules;
  - read-only by default, with a dry run and an explicit flag for anything that changes a host;
  - a test on a fixture built from the real sample.
- **Reviewed by a second code writer**, never the author, against the requirements and a secure-coding checklist.
  The author fixes what it finds; earlier versions stay in the case's `artifacts/authored/older/`.
- **Never run by the harness.** You get the files, the command for each, what it changes, the review result and the
  remaining risks.

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
- **Built-in floors** that no ROE file can lower:
  - Velociraptor actions that touch an endpoint (collection, hunts, memory, downloads, quarantine) and every
    `vuln_*` tool always need approval.
  - **Gate everything:** every action by the `vuln_assessor`, and by any agent in a conversation that ran the
    `vulnerability_assessment` playbook or used that expert, needs approval: reads, notes, memory, tasking and
    reports included. The dashboard shows APPROVE EVERYTHING in the top bar, and the mode stays on for that
    conversation.
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
   - **Always-on and shipped skills.** An expert's `skills:` frontmatter names skills loaded in full into
     every brief, at their current approved version. Each expert's definition holds its role, hard rules and
     deliverable, which never change; its working method is an always-on skill, so the team can improve it
     with your approval:

     | Expert | Method skill |
     |---|---|
     | alert_triage | `alert-triage` |
     | network_analyst | `nsm-analysis` |
     | endpoint_analyst | `endpoint-investigation` |
     | forensicator | `forensic-examination` |
     | malware_analyst | `malware-static-triage` |
     | cti_analyst | `cti-enrichment` |
     | detection_engineer | `detection-engineering` |
     | incident_responder | `incident-response-actions` |
     | threat_hunter | `threat-hunting` |
     | hunt_planner | `hunt-plan-build` |
     | cte_planner | `cte-plan-build` |
     | reporter | `report-writing` |
     | code_writer | `ponytail`, `dco-code` |

     The vuln_assessor keeps its method in its definition, fixed alongside its approval gate.
     Skills shipped in `compensated_anarchist/builtin_skills/` are added, approved, on start. A shipped
     skill follows the shipped text until anyone else touches it: once it has been revised, rolled back or
     retired, or has a revision waiting, it is never replaced. The **code_writer**'s ponytail skills
     (`ponytail` always on; `ponytail-review`, `ponytail-audit`, `ponytail-debt` on demand) come from
     https://github.com/DietrichGebert/ponytail (MIT, (c) 2026 DietrichGebert; licence in
     `builtin_skills/code_writer/LICENSE-ponytail`).
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
  memory.py case.py learning memory, case file / chain of custody / analyst statements
  cte.py            threat emulation planning: network maps, plan check, CTE plans folder
  reports.py        report writer: example library, mission data sources, citation verifier, drafts
  docx.py           markdown -> Word (.docx) export with the standard library
  llm/              openai_compat, anthropic, text-mode tool calling
  tools/            registry/executor, local forensics
  servers/          MCP servers: security_onion, splunk, elastic, velociraptor, misp, opencti
  web/              dashboard (Starlette app + self-contained single-page UI, sign-in page, logo)
  experts/ prompts/ playbooks/
config/             harness.yaml, models.yaml, roe.yaml, env.example
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
- **Most decisions are attributed to the configured operator, not to whoever clicked.** Approval records, steer and
  stop name the signed-in dashboard user, but the ROE audit entries, skill and memory reviews and conversation
  deletions name the operator. There is one dashboard account; per-analyst identity (CAC / client-certificate
  login) is the next hardening step for multi-analyst use.
- **Resuming re-runs a tool call that was in flight.** Results that came back before the interruption are kept, but
  a call that was still running when the dashboard stopped runs again on Resume (the ROE decides it again, so an
  approval-tier action asks you again).
- The orchestration and skill loop is tested with a scripted model. How well a given local model uses
  `submit_report` and writes useful skills has not been measured yet.
