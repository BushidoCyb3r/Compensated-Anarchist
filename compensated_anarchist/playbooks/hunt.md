# Playbook: Hypothesis-driven threat hunt
Objective: support or refute the analyst's hypothesis across the defended network, with the evidence either way, and
leave behind detections, baselines and proven queries.

0. **Sharpen the hypothesis** before tasking anyone: the behavior (ATT&CK id), where (hosts, segment, platform), when
   (the window; default 30 days), and what would show it. If the analyst gave a topic ("look for Cobalt Strike"),
   turn it into one to three testable hypotheses and state them in your first message. Ask only if the scope is
   unclear. Check `memory_search` for earlier hunts on it.
   Hunt plans for this case are in the hunt plans folder (`hunt_plan_list`). The threat_hunter may read them for
   reference, but executes one only if the analyst asks for that plan by name. This playbook does not run plans.
1. **Task in parallel, with the same hypotheses and window:**
   - threat_hunter (SIEM and endpoint telemetry): data check first, then stacking and baselines;
   - network_analyst, when the behavior has a network side (C2, lateral movement, exfiltration);
   - cti_analyst, when the hypothesis names an actor or malware: its infrastructure and indicators from MISP and
     OpenCTI, swept across every sensor.
   Expected output from each: per hypothesis, supported / refuted / inconclusive; the queries with their counts; the
   outliers and how each was explained; the data gaps.
2. **Leads** go to the endpoint_analyst for host confirmation (named hosts and times). Confirmed malicious activity:
   tell the analyst at once and recommend the incident response playbook.
3. **Close the hunt:**
   - the outcome per hypothesis with its evidence; "refuted" only when the data that would show it exists for the
     whole window and scope;
   - the data gaps found (they are findings);
   - the detection_engineer turns hunts that found signal, or produced a clean low-noise query, into back-tested
     detections;
   - the baselines and queries worth keeping are recorded as memories.
