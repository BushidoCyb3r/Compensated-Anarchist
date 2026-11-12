---
name: nsm-analysis
description: How the network_analyst finds and proves C2, lateral movement and exfiltration in Zeek, Suricata, flow and PCAP data - beacon analysis, TLS, HTTP and DNS anomalies, internal movement, volume outliers, alert-to-flow joins, and the benign look-alikes to rule out. Always on for network_analyst.
expert: network_analyst
source: Compensated Anarchist built-in
---

# Analyze network evidence

## 0. Orient
- `memory_search`: the network's infrastructure (resolvers, proxies, scanners, update servers), known beacon-like
  services, sensor coverage, field names.
- Confirm the data covers the window: `list_data_streams` (Security Onion), `list_indices`, `data_inventory`, and a
  count of zeek.conn records for the window. Note segments no sensor sees.
- Aggregate first; read raw records only for the pairs that matter.

## 1. Command and control
- **Beaconing:** `beacon_candidates` (Security Onion) gives source -> destination:port pairs with many connections,
  the hours active and average bytes. For each candidate:
  - timing: count its connections per 10-minute bucket over the window. ES|QL:
    `FROM logs-zeek-so | WHERE event.dataset == "zeek.conn" AND source.ip == "<src>" AND destination.ip == "<dst>"
    | EVAL b = DATE_TRUNC(10 minutes, @timestamp) | STATS c = COUNT(*) BY b | SORT b`.
    A steady count across many hours, overnight included, is the signal; jitter of 10-30% still shows as steady;
  - size: requests of near-constant size, with occasional larger responses (tasking);
  - rarity: how many internal hosts talk to that destination over the window (`pair_counts` or `field_values` on
    destination.ip). One or two is rare; fifty is a service;
  - the destination's SNI or Host header, certificate and intel.
  - Rule out NTP, DNS to our resolver, AV and EDR cloud, OS and browser updates, telemetry, monitoring polls, mail
    clients and VPN keepalives. Say which you checked.
- **Long connections:** zeek.conn with a long duration to external hosts (interactive sessions, tunnels).
- **TLS** (zeek.ssl, zeek.x509): JA3/JA4 or JA3S values rare across the network; self-signed or very short-lived
  certificates; a certificate subject that does not match the SNI; no SNI, or an IP as SNI; TLS on a non-TLS port and
  clear text on 443.
- **HTTP** (zeek.http): small, regular POSTs to one host; rare or empty user agents, or a browser user agent from a
  host with no browser; URIs that repeat with only an id changing; requests straight to an IP.
- **DNS** (zeek.dns): long or high-entropy labels under one parent domain (tunneling); TXT or NULL queries at volume;
  bursts of NXDOMAIN from one host (DGA); a domain queried by only one or two hosts; DNS sent to a resolver that is not
  ours.

## 2. Lateral movement (internal -> internal)
- Workstation-to-workstation SMB (445), RDP (3389), WinRM (5985/5986), SSH (22) or RPC (135 and high ports):
  workstations rarely talk to each other. `pair_counts` with destination.port on internal ranges.
- When the sensor logs them (check the datasets first): DCE-RPC remote service creation (svcctl) or scheduled tasks
  (atsvc, ITaskSchedulerService); DRSUAPI replication requests from a host that is not a domain controller (DCSync);
  admin shares (ADMIN$, C$) mapped from workstations; Kerberos service tickets with RC4 (etype 23) requested in bulk by
  one account (Kerberoasting).
- A first-seen pair (never seen before the window) matters more than a busy one: compare with an earlier window.

## 3. Exfiltration and staging
- Outbound bytes far larger than inbound to a rare external destination; uploads over HTTP POST, cloud storage, FTP
  or DNS.
- Volume outliers per source host against its own history (the same hours on earlier days).
- Internal staging: one host pulling large volumes from file servers before an outbound spike.

## 4. Alerts
- Join each alert to its flow with `community_id_pivot`: did the session complete, how many bytes, which file and
  hash.
- An alert on a server's response and an alert on the request mean different things: say which it is.

## 5. PCAP
Register it, then `local_pcap_stats` (conversations, protocols), `local_zeek` (the same logs as the grid), and
`local_tshark` with display filters for what matters: HTTP requests and objects, DNS, TLS handshakes.

## 6. Verify and record
- Every pair, count and byte total in the report comes from a full-window aggregation.
- Tie internal IPs to hosts and users where the data allows (DHCP, Kerberos or NTLM logs); otherwise say the mapping
  is unknown.
- Record IOCs (IPs, domains, JA3/JA4, certificate hashes, URIs, user agents) with context; findings with ATT&CK ids
  (e.g. T1071.001 web C2, T1071.004 DNS C2, T1572 tunneling, T1021.002 SMB admin shares, T1558.003 Kerberoasting,
  T1048 exfiltration over another protocol); timeline events for first and last seen.
