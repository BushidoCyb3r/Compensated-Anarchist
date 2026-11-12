---
name: incident-response-actions
description: How the incident_responder contains, eradicates and recovers - scope before acting, preserve first, containment options from most to least reversible, the action brief, verifying each action, and the per-host eradication and recovery checklist with credential resets and monitoring. Always on for incident_responder.
expert: incident_responder
source: Compensated Anarchist built-in
---

# Contain, eradicate, recover

## 1. Is the scope known?
- Read the case (`case_summary`): affected hosts, accounts, C2, persistence, the timeline.
- Containing one host while the adversary is on others warns them; they change tools, accounts or infrastructure.
  Unless the brief says to act now (data leaving, damage happening), propose containing every known affected host and
  account together, at one agreed time, once scoping has stopped finding new hosts.
- Say what is still unknown (hosts not checked, accounts possibly exposed) in the action brief.

## 2. Preserve first
Isolation, a reboot or remediation destroys volatile evidence. Before acting on a key host, when time allows:
`acquire_memory` (Windows) or a targeted triage collection, then `download_flow_uploads` into the evidence vault.
If you skip it, say why (active damage, host offline).

## 3. Containment, most reversible first
1. Watch closer: label the host (`label_client`), targeted collection, a monitoring query.
2. Network quarantine (`quarantine_host`): the host keeps its connection to the Velociraptor server, so the
   investigation continues. Rollback: `unquarantine_host`.
3. Process and file remediation through artifacts (names and parameters from `artifact_info`).
4. Accounts, firewall rules, DNS sinkholes, EDR actions: written requests for their owners.

## 4. Verify every action
- Quarantine: the client still checks in to Velociraptor (`client_info` last seen), and the SIEM shows no new
  connections from it except to the Velociraptor server (`pair_counts` from that host since the action).
- Process or file removed: collect the artifact that showed it again.
- C2: query the case's C2 indicators for the time since containment.
- Timeline each action and its verification (`case_add_timeline_event`).

## 5. Eradication and recovery checklist (per host)
- Each persistence mechanism found: removed, with the artifact or query that proves it is gone.
- The entry point closed (patch, configuration, the exposed service).
- Credentials: reset the accounts the adversary used and the accounts whose credentials were on compromised hosts,
  after the adversary is out (resetting earlier shows them and they use another account). Service accounts and
  domain-level keys (e.g. krbtgt after a domain compromise) are the owners' decision: flag them.
- Rebuild or clean: rebuild when the adversary had administrator rights or kernel-level persistence; say which you
  recommend and why.
- Monitoring: the detections and indicators to watch on the recovered hosts, and for how long (default 30 days).
- Release from quarantine only when the checklist is done, with the analyst's approval.
