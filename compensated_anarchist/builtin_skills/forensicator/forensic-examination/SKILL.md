---
name: forensic-examination
description: How the forensicator examines memory, disk images, triage packages, EVTX and mobile extractions - intake, the plugin and parser order for each type, what to look for, anti-forensics, what each artifact proves, and how findings are written. Always on for forensicator.
expert: forensicator
source: Compensated Anarchist built-in
---

# Examine evidence

## 0. Intake
- `local_case_evidence`: every item, its detected type, whether it is registered. Pick the workflow from the detected
  type, not the file name.
- `case_register_evidence` for each item you will examine, before analysis.
- `local_tools_inventory` once: which tools are installed. If a workflow's tool is missing, say so and use the next
  best one.
- Start from the tasking's question (what happened, on which host, in which window) and examine what answers it.

## 1. Memory (Volatility 3 and MemProcFS side by side)
- `local_volatility` windows.info (OS build), then `local_memprocfs` summary.
- Processes: windows.pslist and windows.psscan (in psscan but not pslist = unlinked or exited), windows.pstree,
  windows.cmdline. Look for wrong parents, wrong paths, duplicate system processes, odd start times.
- Network: windows.netscan; tie each connection to its process.
- Injection: windows.malfind (private executable memory; an MZ header in it is strong), windows.ldrmodules (DLLs
  missing from the loader lists), `local_memprocfs` findevil.
- Services and autoruns: windows.svcscan; Run keys with windows.registry.printkey.
- For the processes of interest: windows.dlllist, windows.handles.
- Linux images: linux.pslist, linux.pstree, linux.bash, linux.sockstat (plugin names vary by version: list them if
  one fails).
- Dump a process or region only to hand it to the malware_analyst.

## 2. Disk images and triage packages
- Timeline first: `local_ez_tool` MFTECmd on $MFT and $J for a fast file-system timeline; `local_plaso_timeline`
  for a full super-timeline (slow: scope it to the window).
- Execution: PECmd (Prefetch), AmcacheParser, AppCompatCacheParser (Shimcache), RECmd for BAM and UserAssist,
  SrumECmd (network bytes per process per hour).
- Persistence: RECmd (Run keys, services), scheduled task files, the WMI repository, startup folders.
- What the user opened: LECmd (LNK), JLECmd (jump lists), SBECmd (shellbags), including removable and network drives.
- Anti-forensics: $STANDARD_INFORMATION times earlier than $FILE_NAME times (timestomping); deletions and renames in
  $UsnJrnl; cleared logs (1102, 104); alternate data streams; Prefetch wiped or missing.
- Sleuth Kit through `local_run` (mmls, fls, istat, icat) for partitions, deleted files and specific inodes.

## 3. Event logs (EVTX)
- `local_evtx_hunt` (Hayabusa or Chainsaw with Sigma) for a first pass; then read the events behind each hit.
- Logons 4624 (type 3 and 10 for lateral movement: from which source), 4625 bursts, 4648, 4672; RDP:
  TerminalServices-LocalSessionManager 21/24/25 and RemoteConnectionManager 1149; services 7045; tasks 4698;
  PowerShell 4104; log cleared 1102 / 104.
- Lateral movement shows on the destination (a type 3 logon, then a service or task created seconds later) and on
  the source (4648, RDP client history, Prefetch of the tool used).

## 4. Mobile
`local_leapp` (android = ALEAPP, ios = iLEAPP), then the report sections that bear on the question: messages,
installed apps, accounts, locations, browser history.

## 5. What each artifact proves
- Prefetch: execution, up to 8 last-run times. Amcache: presence and usually execution, with SHA-1. Shimcache:
  presence only on Windows 10 and later; its time is the file's modification time. BAM and UserAssist: execution by a
  user. LNK and jump lists: the file or folder was opened. A $SI modified time can be forged; $FN times are harder to
  change.
- One artifact is a lead; two independent artifacts agreeing is a finding.

## 6. Write the findings
- Each claim: the artifact path, the record or offset, the UTC time and which timestamp it is, the tool and version,
  the evidence item's hash.
- Timeline each event that matters, with its source artifact (`case_add_timeline_event`).
- List what you could not examine and why (tool missing, format unsupported, image corrupt).
