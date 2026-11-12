---
name: alert-triage
description: How the alert_triage analyst works an alert queue - whole-window clustering, why each rule fired and whether it succeeded, the benign checks, the verdict, severity and confidence rubric, and tuning. Always on for alert_triage; revised from the analyst's verdicts.
expert: alert_triage
source: Compensated Anarchist built-in
---

# Triage an alert queue

## 1. See the whole queue first
- Security Onion and Elastic: `alerts_summary` over the window: every rule with its count, severity, distinct
  sources and destinations, the top source -> destination pairs and last seen. Splunk: `notable_events` (status new,
  then in progress).
- Cluster by rule, then by source -> destination pair. One verdict per cluster, unless a cluster mixes hosts that
  behave differently: then split it.
- Work order: critical and high severity first; then clusters touching critical assets (domain controllers, servers
  holding sensitive data, security tooling); then rare rules (low count, first seen in this window); then volume.
- `memory_search` for each rule and host: known false positives, earlier verdicts, the network's infrastructure.

## 2. For each cluster: why did it fire, and did it work?
- Read the rule: name, SID or Sigma id, category. On Security Onion, Suricata keeps `rule.name` and `rule.uuid`; SO
  Detections keep the matched log under `event_data.*`. The rule name says what its author feared; the matched content
  says what happened.
- Read 2-5 raw alerts across the cluster (the first, the last, one from the middle) and their flow context:
  `community_id_pivot` on a Security Onion alert pulls the Zeek conn, dns, http, ssl and files records of that flow.
- Establish:
  - **Direction:** inbound, outbound or internal, and which side is ours.
  - **Success:** an established session or a rejected one (Zeek connection state and history), bytes each way, the
    HTTP status code, the DNS answer, the file transferred and its hash. A failed attempt still counts, at lower
    severity.
  - **Timing:** first and last seen, steady or a burst, business hours or not.
  - **Who:** the host's name, OS and role (`velociraptor__list_clients` / `client_info`), and the user if the data
    has one.

## 3. The benign checks (do them, then say which you did)
- The source is one of ours that does this for a living: vulnerability scanner, monitoring, backup, patching, the
  resolver, the proxy, a gateway (often a .1 or .254 address).
- It is a reply to our host's own request: an ICMP echo reply, a DNS answer, a server's response flagged on the way
  back.
- The destination is ours, a well-known update or CDN service, or on a MISP warninglist (`misp__warninglist_check`).
- Policy and informational rules (a protocol on a port, a user agent, a TLS version) describe policy, not attack.
- It matches a known false positive in memory: check the distinguishing detail the memory gives, not just the rule
  name.

## 4. Pivot one step, only as far as the verdict needs
- The same host +/- 15 minutes in other data: the DNS lookup before the connection, downloads, other alerts.
- The same destination, domain, hash or user elsewhere: `ioc_sweep`, or `pair_counts` with that value. Other hosts
  showing the same pattern widen the scope; say so.
- Intel: `misp__search_ioc`, `opencti__lookup_ioc`. A hit is context, not proof; no hit is not proof of benign.

## 5. Verdict, severity, confidence
- **Verdict:**
  - true positive: malicious or unauthorized activity, evidenced;
  - benign true positive: the rule matched what it is meant to, but this instance is authorized (a pentest, an admin
    tool, a scanner). Say who or what authorizes it;
  - false positive: the rule matched something it should not have. Say what;
  - needs escalation: triage tools cannot decide it. Say what would.
- **Severity** is the activity's, not the rule's: high when it shows success, persistence, credential access,
  lateral movement or C2, or touches a critical asset; medium for failed attempts and reconnaissance against us; low
  for policy and informational matches.
- **Confidence:** high when the deciding evidence is direct and checked over the full window; medium when it rests on
  one source or an inference; low when it rests on a sample or reputation alone.

## 6. Record
- True positives and escalations: `case_add_finding` (hosts, rule, window, evidence, the ATT&CK id when the behavior
  is clear), `case_add_ioc` for each indicator with its context, timeline events for first and last seen.
- Confirmed benign patterns: a `false_positive` memory naming the rule, the pattern, and the detail that tells benign
  from malicious.

## 7. Tuning
For each rule that produced only benign or false-positive alerts: the rule, the count, why it is noisy, and the
narrowest exclusion that removes the noise (a specific source and destination, a specific service account), never a
whole subnet or the whole rule. Never recommend disabling a rule that detects attack behavior: tune it. Hand each one
to the detection_engineer as a recommended task.
