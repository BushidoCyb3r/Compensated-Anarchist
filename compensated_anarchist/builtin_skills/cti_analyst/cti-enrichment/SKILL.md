---
name: cti-enrichment
description: How the cti_analyst enriches indicators, judges their quality, sweeps them across every sensor, pivots from actors and malware to TTPs and infrastructure, finds kill-chain gaps, and writes caveated assessments. Always on for cti_analyst.
expert: cti_analyst
source: Compensated Anarchist built-in
---

# Intelligence support

## 1. Enrich each indicator
- Normalize: refang (hxxp, [.]), lowercase domains, keep a URL and its domain as separate indicators.
- `misp__warninglist_check` first. A hit (CDN, cloud ranges, top domains, public resolvers, sinkholes) means the
  indicator says little on its own.
- `misp__search_ioc` (events, tags, TLP, first seen), `opencti__lookup_ioc` (score, labels, related intrusion sets
  and malware, kill-chain phase), `memory_search` for earlier sightings in this network.
- Judge the indicator (pyramid of pain): a hash changes with one byte; shared hosting, CDN, cloud and dynamic DNS
  addresses change hands; a domain registered for an operation is better; tooling and behavior are best. Say how long
  it is likely to stay useful.

## 2. Sweep
- Confirm each sensor holds data for the window first (`list_data_streams`, `list_indices`, `list_indexes`).
- `ioc_sweep` on every connected sensor over the lookback in the brief (default 30 days, or from the indicator's
  first-seen date if that is later).
- Per indicator: hits per sensor, first and last seen, and the hosts or source -> destination pairs, verified with
  `pair_counts` / `field_values`, not read off a sample.
- No hits: say what was swept, over which window, and whether that source would have seen it (a domain needs DNS or
  proxy logs; a hash needs file or endpoint logs).

## 3. Actors, malware and campaigns
- From an attributed actor or malware: OpenCTI `search_entities` and `entity_relationships`, MISP `search_events` and
  `get_event`. List its TTPs (ATT&CK ids) and infrastructure.
- Sweep for that infrastructure, and recommend hunts for the TTPs (threat_hunter).
- Map what has been observed in this case to ATT&CK and look for the gaps: C2 seen but no initial access means look
  for initial access; credential access seen means look for lateral movement next; staging seen means look for
  exfiltration.

## 4. Assess
- Sources: how reliable the source has been, and whether other sources confirm the information.
- Estimative language with confidence: "almost certainly", "likely", "roughly even chance", "unlikely" - and what the
  confidence rests on.
- Attribution: the links for it, the links against it, and the alternatives (another actor using the same public
  tool, shared infrastructure).

## 5. Record
- `case_add_ioc` with context: source, intel score and TLP, warninglist result, first and last seen here.
- Findings for confirmed sightings; `ttp` memories for actor behavior observed here.
- MISP sightings or new events only when the brief asks.
