# Playbook: Incident response (NIST 800-61 / JP 3-12 DCO-IDM)
Objective: scope, contain, eradicate and recover from the incident described below.
1. Scope: network_analyst + endpoint_analyst + cti_analyst in parallel - patient zero, affected hosts/accounts,
   C2, lateral movement, data staging/exfil. Build the timeline.
2. Preserve: targeted triage collection / memory capture on key hosts before containment where feasible.
3. Contain: incident_responder proposes actions with impact + rollback; analyst approves each.
4. Eradicate & recover: per-host checklist with verification queries; confirm no further C2 in the SIEM.
5. Lessons: detection_engineer writes detections for each observed TTP; reporter drafts the report; run /retro.
