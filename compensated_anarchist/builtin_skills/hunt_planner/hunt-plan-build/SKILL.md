---
name: hunt-plan-build
description: How the hunt_planner builds an ATT&CK hunt plan - resolving actors, collecting and ranking techniques, designing each hunt (testable hypothesis, aggregation-first queries per tool, look-alikes, what "clear" needs), data status, the plan layout and the query dialects. Always on for hunt_planner; revised from the threat_hunter's results.
expert: hunt_planner
source: Compensated Anarchist built-in
---

# Build a hunt plan

## 1. Actors and techniques
- Resolve the actors with `attack_search` / `attack_group`; list the candidates when a name is ambiguous. Note the
  ATT&CK version.
- `attack_group(<actor>, platforms=[...])` with software and campaigns as the analyst chose.
- `memory_search` for earlier hunts, proven queries and known gaps here.

## 2. Rank
Score each technique, highest first, and keep the number the analyst asked for (default 15):
- used by several of the chosen actors, or both directly and through their software: +2;
- the chosen tools can observe it (`data_confirmed` after a survey): +2; `data_unconfirmed`: +1; no source: 0;
- execution, persistence, privilege escalation, credential access, lateral movement or command and control: +1;
- no existing detection or hunt for it in memory: +1.
Reconnaissance and resource development are context, not hunts. Techniques no source can see are **telemetry gaps**:
list them with the data source that would close each.

## 3. Design each hunt (`attack_technique(<T-id>, group=<actor>)`)
- **Hypothesis**, testable: "<actor> uses <procedure, short quote>, so <observable> appears in <data source> on
  <platform or hosts>".
- **Data needed:** the source and fields, and what must be present for the window before a result can be called
  `clear`.
- **Queries per tool,** aggregation first: a stacking query that returns counts by the attribute the adversary
  controls (process path, parent -> child, service path, task command, destination, user agent), so the hunter reads
  the long tail instead of thousands of raw events; then the drill-down query for an outlier.
- **Baseline:** what normal looks like here (expected benign volume, admin tools), and how to compare with an
  earlier period.
- **Benign look-alikes** and how to tell them apart.
- **On a hit:** what the threat_hunter does next (pivot, which host evidence to ask the endpoint_analyst for).
- For Velociraptor, name the artifact and its parameters, confirmed with `velociraptor__artifact_info`. Planning
  never collects.

## 4. Data status
`data_confirmed` (the survey found the source and fields), `data_unconfirmed` (not surveyed) or `no_data` (no source
can see it). Never report hit counts: you have none.

## 5. Save and report
- `hunt_plan_save(name=<actors>, content=<plan>, kind="plan")` saves `hunt_plan_<actors>.md`; earlier versions are
  kept.
- `attack_navigator_layer` with each technique's data status, same name.

# Plan layout (markdown)
- **How it was built:** input only / surveyed / both, and the analyst's choices.
- **Scope:** actors (G-ids), T-codes, ATT&CK version, platforms, the recommended window, the tools covered,
  assumptions.
- **Priority table:** rank | score | T-code | technique | tactic | actors | data source | tools | data status.
- **One section per hunt:** T-code and name, tactic, the actor procedure (short quote); hypothesis; data needed and
  what `clear` requires; queries per tool in code blocks labelled with the tool and dialect (stacking, then
  drill-down); baseline; benign look-alikes; the next step on a hit.
- **Telemetry gaps** and the **backlog** (lower-ranked techniques, one line each).
- **For the threat_hunter:** execution order, the window, and what to record per hunt (outcome, query, counts).

# Query dialects
- **Security Onion** (Lucene for `security_onion__search`; ES|QL for `security_onion__esql`):
  - Zeek: `event.dataset:zeek.conn | zeek.dns | zeek.http | zeek.ssl | zeek.files | zeek.smb_files | zeek.kerberos`.
    Common fields: source.ip, destination.ip, destination.port, dns.query.name, ssl.server_name, http.user_agent.
  - Suricata: `event.dataset:suricata.alert`, rule.name.
  - ES|QL starts `FROM logs-zeek-so | WHERE ...`. Always KEEP or STATS; stacking is `STATS c = COUNT(*) BY <field> |
    SORT c ASC`.
  - Endpoint data exists on the grid only if agents ship it there.
- **Elastic** (Lucene, ES|QL, or EQL for sequences):
  - ECS fields: process.name, process.command_line, process.parent.name, event.code, event.category, registry.path,
    file.path, dns.question.name, destination.ip, user.name.
- **Splunk** (SPL):
  - Sysmon: `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1`.
  - Security log: `source="WinEventLog:Security" EventCode=4698`.
  - Stacking: `| stats count dc(host) as hosts by <field> | sort count`. `tstats` with CIM data models where they
    are populated.
- **Velociraptor:** an artifact plus parameters, confirmed with `artifact_info`. Common ones: Windows.System.Pslist,
  Windows.EventLogs.EvtxHunter (IocRegex), Windows.System.TaskScheduler, Windows.System.Services,
  Windows.Persistence.PermanentWMIEvents, Windows.Sys.StartupItems, Windows.Search.FileFinder, Linux.Sys.Pslist,
  Linux.Sys.Crontab.
- **Sigma:** a rule tagged `attack.tXXXX`, converted with `local_sigma_convert`.

Never invent a field, index, sourcetype or artifact name. If you could not confirm it, say so next to the query. The
threat_hunter fixes syntax and confirms fields when it runs the queries.
