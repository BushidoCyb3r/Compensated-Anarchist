# Playbook: Alert queue triage
Objective: every alert in the window has a defensible verdict; true positives are scoped and escalated; noisy rules
go to tuning.

0. **Window and sensors:** what the analyst gave; otherwise the last 24 hours on every connected sensor. Say which
   you used; don't ask.
1. **Look at the queue yourself:** `alerts_summary` (Security Onion, Elastic) and `notable_events` (Splunk). Note the
   number of rules and alerts, the top rules by severity and by volume, and any critical assets involved.
2. **Task alert_triage** (one subagent; split by sensor or rule group only when there are more than about 40 rules):
   - task: triage every alert cluster in the window on those sensors, worst first;
   - context: the counts from step 1, critical assets from memory, anything the analyst said;
   - expected output: the triage table (cluster | count | verdict | severity | confidence | key evidence | next
     action), each escalation with its evidence, and the rules to tune with their proposed exclusions.
3. **Check its report** (lead prompt, "Checking a report"): each escalation names its hosts, window and evidence;
   each false positive names what makes it benign.
4. **Escalations,** in parallel, for each true positive or needs-escalation cluster:
   - network_analyst: the pairs, the window +/- 1 hour, and what to establish (did it succeed, other destinations,
     lateral movement);
   - endpoint_analyst: the internal hosts, the time, the process or user to find (telemetry and existing results
     first; collections need the analyst's approval);
   - cti_analyst: enrich the indicators and sweep them across every sensor over 30 days.
   New hosts or indicators start another round (the scoping loop). Confirmed malicious activity: tell the analyst
   at once and recommend the incident response playbook.
5. **Tuning:** when there are noisy rules, the detection_engineer tunes and back-tests them from the proposed
   exclusions. Nothing is deployed without the analyst.
6. **Brief the analyst:**
   - totals: alerts, clusters, and how many of each verdict;
   - escalations, worst first, with confidence and what was done;
   - the recommended response;
   - rules sent for tuning;
   - anything not triaged, and why.
