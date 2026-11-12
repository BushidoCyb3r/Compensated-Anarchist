# Playbook: Compromise assessment
Objective: an evidence-based answer to "is there, or has there been, an adversary in this environment?", with the
confidence the coverage supports. The answer is never "clean": it is "no evidence of compromise found in what was
examined", with what was examined.

0. **Scope:** the environment, enclave or host group, and the look-back (default 90 days, or as far as the data
   goes). Use what the analyst gave; ask only if the scope is missing.
1. **Coverage first** (threat_hunter): which data exists for the scope and look-back:
   - network sensors and the segments they see;
   - SIEM endpoint logs and which hosts ship them;
   - Velociraptor clients online;
   - log retention.
   Map it to ATT&CK tactics: what could be seen and what could not. The gaps go in the deliverable.
2. **Parallel sweeps,** same scope and look-back, each given the coverage map from step 1:
   - network_analyst: beaconing and rare destinations, DNS anomalies, internal lateral movement, outbound volume
     outliers;
   - threat_hunter, stacking across hosts:
     - persistence (services, tasks, Run keys, WMI);
     - credential access (lsass access, Kerberoasting);
     - execution from user-writable paths, and LOLBins;
     - new local admins, cleared logs;
   - cti_analyst: sweep the indicators in memory, the case, and MISP and OpenCTI for this sector, over the look-back;
   - endpoint_analyst: only on the outliers the others name (collections need approval). A fleet-wide hunt only if
     the analyst agrees it is needed.
3. **Every outlier is explained or escalated:** benign with the evidence (recorded as a `false_positive` memory), or
   escalated to the endpoint_analyst (the scoping loop). Confirmed malicious activity: tell the analyst at once and
   recommend the incident response playbook.
4. **Deliver:**
   - the answer and its confidence;
   - per tactic: what was checked, how, and the result;
   - the evidence for each conclusion, and each outlier with how it was resolved;
   - the coverage gaps and what they do to the confidence;
   - the logging that would close each gap, and other hardening;
   - detections for the detection_engineer from the queries that proved useful.
