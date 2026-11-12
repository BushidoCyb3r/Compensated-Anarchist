---
name: threat-hunting
description: How the threat_hunter hunts - testable hypotheses, the data check, stacking and baselines, query patterns by tactic, confirming leads, honest conclusions, and checking each step of an emulation the operators ran. Always on for threat_hunter.
expert: threat_hunter
source: Compensated Anarchist built-in
---

# Hunt

## 1. Hypothesis
- Write it as: "<behavior, ATT&CK id> would leave <observable> in <data source> on <hosts or segment> during
  <window>". Specific enough that a query can support or refute it.
- `memory_search`: earlier hunts for this technique, proven queries, baselines, benign look-alikes.
- A hunt plan in the folder may already have a query for it (`hunt_plan_list`): reuse it for reference.

## 2. Data check (before any hunt logic)
- The source exists for the window and the segment: `list_data_streams`, `list_indices`, `list_indexes` /
  `data_inventory`, and a count over the window.
- The fields you need are populated (`field_values`). A missing source is a finding: report it as a gap, and the hunt
  as inconclusive.

## 3. Hunt techniques
- **Stacking** (least frequent occurrence): count by the attribute the adversary controls - process path, parent ->
  child pair, service binary path, task command, user agent, JA3, destination - across all hosts. Read the long tail:
  values on one or two hosts.
- **Baseline vs. now:** the same count over an earlier period of the same length; what is new in the window.
- **Clustering:** several weak signals on one host close together (a new service, encoded PowerShell, a new outbound
  destination) outweigh any one of them.
- **Pivot** from each outlier: the same host +/- 1 hour; the same value on other hosts.

## 4. Query patterns by tactic (adapt to the fields that exist)
- Execution: parent -> child stacks (Office, browsers, mail -> shells); encoded PowerShell; LOLBins with URLs.
- Persistence: new services (7045), tasks (4698), Run keys (Sysmon 13), WMI consumers - stack the binary paths and
  commands.
- Privilege escalation and credential access: lsass opened (Sysmon 10) by unexpected processes; ntds.dit or SAM hive
  copies; Kerberos service tickets with RC4 in bulk from one account.
- Lateral movement: type 3 or 10 logons workstation -> workstation; remote service or task creation; admin shares.
- Command and control: rare destinations; beacon-like pairs (`beacon_candidates` on Security Onion); rare user agents
  and JA3.
- Collection and exfiltration: archivers on staging paths; outbound volume outliers per host.

## 5. Confirm a lead
- Verify over the full window with `pair_counts` and `field_values`, not from a sample.
- Benign check: IT and admin tools, scanners, software deployment, backups. Say which you ruled out and how.
- Endpoint collection only on the hosts of the lead (the analyst approves each).

## 6. Conclude
- **Supported:** evidence of the behavior (findings, IOCs, timeline in the case).
- **Refuted:** the data that would show it exists for the whole window and scope, and it is not there.
- **Inconclusive:** the data is missing or too noisy to tell. Say what would settle it.
- Record every query that produced signal as a `query` memory, and the baselines you measured as environment
  memories. Recommend detections for hunts that found signal or produced a clean query.

# Check an emulation (CTE)
The brief gives the window, the systems and, ideally, the operators' execution log (step, time, host, account). Read
the plan (`cte_plan_read`). For each step:
- **Alert:** did a rule fire on the step's target around the step's time (`alerts_summary`, `alerts`,
  `notable_events`)? Which rule, when.
- **Findable:** query the expected artifacts the plan names (event ids, Zeek logs, process names) on that host and
  time. Give the query and its counts.
- **Result:** detected (an alert fired); partially detected (findable in the data but no alert, or only some of the
  artifacts); missed (the operators ran it and nothing shows); not run (the operators did not run it). Without an
  execution log, you cannot tell missed from not run: say so, and ask for the log in open_questions.
- Report each step with its evidence. Do not save a results file: the cte_planner does.
