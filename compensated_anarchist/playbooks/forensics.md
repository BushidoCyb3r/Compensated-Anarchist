# Playbook: Evidence examination (disk / memory / logs / PCAP / mobile)
Objective: forensically examine the evidence for this case.

Where the evidence is:
- The case evidence folder, `forensics/<case-id>/` (its full path is in the Session block). The analyst drops
  artifacts there, in any subfolder: disk/, memory/, logs/, network/, mobile/, triage/, other/.
- The evidence vault, for files pulled from endpoints by Velociraptor.
- Any specific items the analyst names below take priority.
Start with `local_case_evidence`: it lists both places with each item's type (detected from content) and whether
it is registered. Decide the workflow from that list, not from file names.

1. forensicator registers and hashes every item it will examine (`case_register_evidence`) before analysis, never
   modifies evidence, then runs the workflow for its type: memory (process/network/injection, Volatility +
   MemProcFS); disk image or triage package (timeline, execution, persistence, Zimmerman tools, Sleuth Kit); EVTX
   (Sigma hunt with Hayabusa/Chainsaw); registry hives (RECmd); mobile (ALEAPP/iLEAPP); PCAP: hand to network_analyst.
2. Executables and scripts found in the evidence go to the malware_analyst (static analysis only - never run them).
3. IOCs -> cti_analyst sweeps across live sensors to find other affected hosts.
4. Findings carry artifact paths, offsets, UTC times and the hash of the evidence item; chain of custody is preserved
   in the case. Report anything listed in the evidence folder that could not be examined, and why.
