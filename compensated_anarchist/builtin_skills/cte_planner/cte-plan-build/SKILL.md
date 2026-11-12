---
name: cte-plan-build
description: How to build a cyber threat emulation (CTE) plan from an adversary and a network, and the plan layout. Always on for the cte_planner; revised after each plan from the analyst's edits and the emulation results.
expert: cte_planner
source: Compensated Anarchist built-in
---

# Build a CTE plan

## 1. Adversary
- `attack_search` / `attack_group` to resolve the adversary to one ATT&CK group (G-id). If several match, stop with
  `needs_input` and list the candidates with their aliases.
- Note the ATT&CK version, the group's software (S-ids) and attributed campaigns (C-ids).
- If MISP or OpenCTI is connected, look for recent reporting on the group (`misp__search_events`,
  `opencti__search_entities`). Use it only to add or rank techniques, and cite it as `intel: <source and id>`.

## 2. Network
- From the brief (the type of network), or from a map: `cte_network_map` with no name lists the files, then read the
  one the analyst named or the only one there.
- Work out the platforms (Windows, Linux, macOS, network devices, cloud, OT/ICS) and the key systems: domain
  controllers, servers, workstations, jump hosts, firewalls, OT gateways. Use the map's own names for target systems.
- `memory_search` for what the team already knows about this network.
- Coverage: `security_onion__list_data_streams`, `elastic__list_indices`, `splunk__list_indexes` and
  `velociraptor__list_clients` show which sensors and data exist. Use them only to judge whether a step would be
  seen, never to look for activity.

## 3. Techniques
- `attack_group(<adversary>, platforms=[...])`, with software and campaigns included.
- Keep the techniques that fit this network and have a documented procedure. Typical plan: 12-25 steps covering
  initial access (simulated, see below), execution, persistence, privilege escalation, defense evasion, credential
  access, discovery, lateral movement, collection, command and control and exfiltration (simulated with test data).
- Rank higher: techniques the adversary uses directly and through its software, and techniques on the systems that
  matter most on this network.
- Exploitation and destructive or disruptive impact go to **Not emulated** (step 5).
- Initial access by exploitation is not emulated. Start the chain from an assumed foothold instead (state it as an
  assumption, e.g. "assume a user executed the adversary's loader on a workstation") or from a non-exploit access
  technique the adversary documents, emulated with test accounts and test files.

## 4. Each step
- `attack_technique(<T-id>, group=<adversary>)` for the documented procedure (quote it briefly) and the data that
  would show it.
- **Emulation reference:**
  - Atomic Red Team: `cte_atomic_tests(<T-id>)`; name the test number and name it returns. Without a local
    checkout, write "Atomic Red Team: tests for <T-id> (operator selects)".
  - Mythic: name a command only if the analyst gave you the agent's command list. Otherwise write "Mythic: a command
    mapped to <T-id> (operator selects)".
  - Never write commands or code.
- **Target:** which system(s) from the map or network type, by name.
- **Prerequisites:** test accounts, test files, approvals, sensors that must be on.
- **Expected artifacts:** the events and logs the step should create (event IDs, Zeek logs, Sysmon events).
- **Detection opportunity:** which connected sensor and data source should see it, and whether that data exists
  (from step 2). A step no sensor can see is a **telemetry gap**: say which data source would close it.
- **Success criteria:** what counts as detected (an alert fired, or the activity is findable in the named data
  within the agreed time).
- **Cleanup:** how the operator undoes the step (remove the test account or task, delete the test files).
- **Timing:** steps are spaced (10-15 minutes by default) so each alert can be matched to its step, and the operator
  logs each step's exact UTC time, host and account in the execution log. Without the log, a missed step cannot be
  told apart from a step that was not run.

## 5. Not emulated
For each exploitation or destructive technique the adversary uses: T-code, name, why it is not emulated, and its
detection opportunity (what would show it, which sensor). Write "not emulated" on each line.

## 6. Check, save, report
- `cte_plan_check(actors=[...], content=...)`; fix every problem; then
  `cte_plan_save(name=<adversary>, content=..., actors=[...])`.
- `cte_navigator_layer` with each technique's status: emulate, not_emulated or analyst_added.
- `submit_report`: the bottom line, the adversary (G-id), the network assumptions, steps per phase, what is not
  emulated and why, the telemetry gaps, the saved paths, and the open questions.

## After the emulation is run (follow-up from the orchestrator)
The threat_hunter reads the plan and checks each step against the operators' execution log; its report comes in your
follow-up. Save `cte_results_<adversary>.md` with
`cte_plan_save(kind="results")`: per step, detected / partially detected / missed / not run, with the evidence
cited. Update the layer with the same statuses. Record what the sensors missed with `memory_record`, and propose
detections for the missed steps as recommended tasks for the detection_engineer.

# Plan layout (markdown)
1. **Title:** `CTE plan: <adversary> (<G-id>) against <network>`, and the ATT&CK version.
2. **Purpose:** detection test for this adversary's documented behavior. Defensive; no exploitation; nothing
   destructive.
3. **Inputs and assumptions:** the analyst's two inputs, word for word; the network assumptions; the assumed
   foothold.
4. **Scope and rules of engagement:** the target systems; the authorized time window (from the analyst); the test
   mode (purple team by default: the SOC knows and each step is checked as it runs; blind only if the analyst says
   so); deconfliction (who in the SOC is told, and who is not, for a blind test); stop conditions (unexpected impact,
   real adversary activity found, an out-of-scope host touched); rollback; contacts (the analyst fills these in).
5. **Summary table:** step | phase | T-code | technique | target | emulation reference | detection opportunity |
   data status.
6. **Steps,** one section each, in kill-chain order: T-code and name, tactic, the adversary's procedure (short
   quote, with source), emulation reference, target, prerequisites, expected artifacts, detection opportunity,
   success criteria, cleanup.
7. **Not emulated:** the table from step 5.
8. **Telemetry gaps:** steps no sensor would see, and the data source that would close each.
9. **Execution log** for the operators to fill in: step | time (UTC) | host | account | ran as planned? | notes.
10. **Questions and gaps** for the analyst.
11. **Sources:** ATT&CK version, group and technique IDs, intel references.
