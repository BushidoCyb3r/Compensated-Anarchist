# Playbook: Evidence examination (disk / memory / logs / PCAP / mobile)
Objective: forensically examine this case's evidence and answer the analyst's question about it, with every
conclusion traced to an artifact, a time and the hash of the evidence it came from.

Where the evidence is:
- The case evidence folder, `forensics/<case-id>/` (its full path is in the Session block). The analyst drops
  artifacts there, in any subfolder: disk/, memory/, logs/, network/, mobile/, triage/, other/.
- The evidence vault, for files pulled from endpoints by Velociraptor.
- Any specific items the analyst names below take priority.

0. **The question:** what the analyst wants to know (what happened, on which system, in which window). If they gave
   only the evidence, the question is "what happened on this system, and is it malicious?". Run
   `local_case_evidence` yourself: it lists both places with each item's type (detected from content) and whether it
   is registered.
1. **Task the forensicator** with the question, the items to examine (the analyst's first, then the rest by
   relevance), and what is already known from the case. It registers and hashes every item before analysis, never
   modifies evidence, and picks each workflow from the detected type.
   PCAPs go to the network_analyst in parallel, with the same question.
2. **Hand-offs from its report:**
   - executables, scripts, documents with macros and dumped memory regions go to the malware_analyst (static
     analysis only: never run them);
   - indicators go to the cti_analyst, to sweep across the live sensors for other affected hosts;
   - a live host that needs checking goes to the endpoint_analyst.
   Confirmed malicious activity on a live network: tell the analyst at once and recommend the incident response
   playbook.
3. **Deliver:**
   - the answer to the question, with confidence;
   - the timeline of key events (UTC) with the artifact behind each;
   - findings carrying artifact paths, offsets, UTC times and the hash of the evidence item;
   - chain of custody preserved in the case;
   - anything in the evidence folder that could not be examined, and why.
