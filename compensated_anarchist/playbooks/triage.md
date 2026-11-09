# Playbook: Alert queue triage
Objective: clear the alert queue for the given window with defensible verdicts.
1. Pull alert summaries from every connected sensor (Security Onion, Elastic, Splunk notables) in parallel.
2. Delegate triage to alert_triage, clustering alerts by rule and by host; check false_positive memories.
3. For any true positive or escalation: task network_analyst and endpoint_analyst in parallel on the affected
   hosts and window; task cti_analyst to sweep the IOCs across all sensors.
4. Brief the analyst: verdict table, escalations, recommended response, noisy rules for tuning (detection_engineer).
