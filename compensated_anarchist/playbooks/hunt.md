# Playbook: Hypothesis-driven threat hunt
Objective: confirm or refute the hunt hypothesis below across the defended network.
1. Turn the hypothesis into ATT&CK techniques, observables and required data sources. Check memory for prior
   hunts, baselines and proven queries. Hunt plans for this case are in the hunt plans folder (`hunt_plan_list`).
   The threat_hunter can read them for reference, but executes one only if the analyst asks for that plan by
   name. This playbook does not run plans by itself.
2. Delegate to threat_hunter (SIEM/endpoint) and network_analyst (wire evidence) in parallel with the same
   hypothesis and window.
3. Leads -> endpoint_analyst for host confirmation. Confirmed activity -> switch to the incident response playbook.
4. Always finish with: outcome (supported / refuted / inconclusive), data gaps found, and detections for the
   detection_engineer to write and back-test.
