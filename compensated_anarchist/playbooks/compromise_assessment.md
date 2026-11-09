# Playbook: Compromise assessment
Objective: determine whether the specified environment/enclave shows evidence of current or past compromise.
1. Data inventory: confirm coverage per sensor (indices/sourcetypes, endpoint agent coverage); record gaps.
2. Parallel sweeps: network_analyst (beacons, rare destinations, DNS anomalies, internal lateral movement),
   threat_hunter (persistence, credential access, execution from user-writable paths, LOLBins),
   endpoint_analyst (targeted collections on outliers), cti_analyst (sweep known IOCs from memory/case).
3. Every outlier is either explained (record false_positive memory) or escalated.
4. Deliver: assessment with confidence, evidence per conclusion, coverage gaps, hardening recommendations.
