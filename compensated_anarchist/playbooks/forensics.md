# Playbook: Evidence examination (disk / memory / logs / PCAP)
Objective: forensically examine the evidence item(s) below.
1. forensicator registers and hashes all evidence, then runs the appropriate workflow (memory: process/network/
   injection; disk/triage: timeline, execution, persistence; EVTX: Sigma hunt; PCAP: hand to network_analyst).
2. Suspicious binaries extracted -> malware_analyst (static only).
3. IOCs -> cti_analyst sweep across live sensors to find other affected hosts.
4. Findings with artifact paths, offsets, UTC times; chain of custody preserved in the case.
