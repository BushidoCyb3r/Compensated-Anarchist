# Playbook: Incident response (NIST SP 800-61 / JP 3-12 DCO-IDM)
Objective: scope the incident fully, then contain, eradicate and recover, with every response action approved by
the analyst, and leave the network better defended.

0. **Frame:** what was reported, the first known-bad host and time, and what is at stake (critical assets, data).
   Record it in the case. If the report is thin, start scoping anyway; ask only what blocks you.
1. **Scope,** in parallel, and repeat until a round finds nothing new (the scoping loop):
   - endpoint_analyst on the known hosts: execution chain, persistence, accounts, connections, timeline;
   - network_analyst: C2 (the known indicators, then beacon-like pairs), lateral movement to and from the known
     hosts, staging and exfiltration;
   - cti_analyst: enrich and sweep the indicators across every sensor, and the actor's known TTPs to look for next.
   Keep the case timeline current. If data is leaving or damage is happening, tell the analyst at once: containment
   may have to come before scoping is complete.
2. **Preserve** before containing: memory and triage collections from the key hosts into the evidence vault (the
   analyst approves each). The forensicator examines them; the malware_analyst gets the binaries (static only).
3. **Contain** (incident_responder): one coordinated plan for every known affected host and account, proposed
   together, each action with its impact and rollback. The analyst approves each one, and each is verified after it
   runs.
4. **Eradicate and recover** (incident_responder): a checklist per host, with the verification for each item;
   credential resets after the adversary is out; monitoring for the recovered hosts. Confirm no further C2 in the
   SIEM since containment.
5. **Lessons:**
   - the detection_engineer writes back-tested detections for each observed TTP;
   - the threat_hunter looks for the same TTPs elsewhere if scoping was limited;
   - the reporter drafts the report when the analyst asks for it (report playbook: from mission data only);
   - run /retro.
