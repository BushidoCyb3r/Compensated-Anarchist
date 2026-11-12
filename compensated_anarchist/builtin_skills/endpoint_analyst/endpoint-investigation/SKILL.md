---
name: endpoint-investigation
description: How the endpoint_analyst investigates a host - telemetry before collection, the Velociraptor artifacts to use, what to look for in process trees, command lines, persistence and logons, what each execution artifact can and cannot prove, and how to build the host's story. Always on for endpoint_analyst.
expert: endpoint_analyst
source: Compensated Anarchist built-in
---

# Investigate a host

## 0. Orient
- `memory_search` for the host, its role, normal admin tools and baselines here.
- `list_clients` / `client_info`: client_id, hostname, OS and version, last seen. An offline client cannot be
  collected from: say so, and work from telemetry.
- `client_flows`: what was already collected from this host. Reuse those results (`flow_results`) first.
- Label the host for the case (`label_client`, e.g. `ir-<case id>`) once it is part of the investigation.

## 1. Telemetry first (no impact on the host)
Check which endpoint sources the SIEMs hold for this host before relying on them.
- Windows Security: 4624 logon (type 2 interactive, 3 network, 10 RDP), 4625 failed, 4648 explicit credentials,
  4672 admin logon, 4688 process creation (if enabled), 4698/4702 scheduled task created or changed, 4720/4732 account
  created or added to a group, 1102 log cleared. System: 7045 service installed.
- Sysmon: 1 process, 3 network, 7 image load, 8 remote thread, 10 process access (to lsass), 11 file create,
  13 registry value set, 22 DNS.
- PowerShell: 4104 script block, 4103 module logging.
- Linux: sshd and sudo in the auth logs, auditd execve, cron.

## 2. Live artifacts (the narrowest that answers the question)
Common in recent Velociraptor releases; confirm each with `artifact_info`, or find the right one with
`list_artifacts`:
- Processes and connections: Windows.System.Pslist, Windows.Network.NetstatEnriched, Linux.Sys.Pslist.
- Persistence: Windows.Sys.StartupItems, Windows.System.Services, Windows.System.TaskScheduler,
  Windows.Persistence.PermanentWMIEvents, Linux.Sys.Crontab, Linux.Ssh.AuthorizedKeys.
- Execution history: Windows.Forensics.Prefetch, Windows.Detection.Amcache, Windows.Registry.AppCompatCache,
  Windows.Forensics.Bam, Windows.Registry.UserAssist, Linux.Sys.BashHistory.
- Logs on the host: Windows.EventLogs.EvtxHunter (IocRegex), Windows.EventLogs.RDPAuth.
- Files: Windows.Search.FileFinder (glob and hashes; upload only when the file itself is needed).
- Memory: `acquire_memory` (Windows) when injection, credential theft or fileless malware is suspected and the host
  is up. Poll `flow_status`, then `download_flow_uploads`, and hand the path to the forensicator.

## 3. What to look for
- **Process tree:** Office, browsers, PDF readers or mail clients spawning cmd, powershell, wscript, cscript, mshta,
  rundll32 or regsvr32; services.exe or wmiprvse.exe spawning shells (remote execution); system binaries in the wrong
  path or under the wrong parent (svchost not under services.exe, more than one lsass).
- **Command lines:** encoded PowerShell (-enc), download cradles, LOLBins used to fetch or run (certutil -urlcache,
  bitsadmin, mshta with a URL, rundll32 with an odd export), credential tools, archivers writing to staging paths.
- **Paths:** execution from user-writable places (AppData, Temp, ProgramData, Users\Public, Downloads, the Recycle
  Bin), random or misspelled names, system names in the wrong folder.
- **Persistence:** Run keys, services and tasks pointing at user-writable paths or scripts, WMI consumers, new local
  admins. Compare each creation time with the incident window.
- **Credential access:** anything opening lsass (Sysmon 10) other than the expected security tools; copies of
  ntds.dit or the SAM and SECURITY hives; new shadow copies.
- **Network:** tie each connection under investigation to its PID, process, parent and user.

## 4. What each execution artifact proves (say which you rely on)
- Prefetch: execution, with up to 8 last-run times. Often disabled on servers.
- Amcache: the file was present and usually executed; it carries the SHA-1.
- Shimcache (AppCompatCache): the file existed. On Windows 10 and later it does not prove execution, and its time is
  the file's modification time, not a run time.
- BAM and UserAssist: execution by a user, with a last-run time.
- A gap in the logs or a cleared log (1102, 104) is itself a finding.

## 5. Build the story
- Anchor on the first known-bad time. Work backwards (how it got there, who logged on, from where) and forwards (what
  it did next, where it went). Timeline each step in UTC with the artifact it came from.
- Benign check: IT and admin activity (software deployment, Intune or SCCM, backup, AV, scripts from known admin
  accounts at expected times). Say which you ruled out and how.
- Verdict wording: compromised (malicious activity evidenced on this host); suspicious (unexplained, not proven
  malicious); no evidence found in what was checked (list what was checked).
