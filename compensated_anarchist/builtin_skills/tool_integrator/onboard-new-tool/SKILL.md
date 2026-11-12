---
name: onboard-new-tool
description: How the tool_integrator turns a tool the analyst supplied into a safe, declarative adapter (or approves a quarantined MCP server's tools), proves it in the sandbox, writes the usage skills and submits one proposal for review. Always on for tool_integrator.
expert: tool_integrator
source: Compensated Anarchist built-in
---

# Onboard a new tool

## 1. Discover (no network, nothing runs yet)
- `onboard_list`: is it already onboarded, waiting, or an MCP server in quarantine?
- `onboard_inspect` on the path the analyst gave: SHA-256, type (ELF, script, PE), permissions, and the README /
  docs / man page next to it. A binary writable by other users must be fixed by the analyst first.
- Note where the analyst said it came from (vendor release, version, signature checked or not): that is the
  provenance the analyst approves.

## 2. Characterize
- `onboard_help` with every variant in ONE call (`invocations: [[--help], [help], [-h], [--version]]`): one approval
  covers them all. Some tools reject `--help`; a subcommand's help is often `help <subcommand>`. Each approval costs
  the analyst attention, so batch.
- Work out: the subcommand and options for the job the experts need; inputs (files, folders); outputs (stdout or a
  file; JSON, NDJSON, CSV or text); whether it writes anywhere besides its output; whether it needs the network;
  whether any mode changes state (deletes, uploads, quarantines). Leave dangerous modes out of the adapter.
- Risk class: `read-only` (reads evidence, prints), `writes-artifacts` (writes output files), `touches-network`, or
  `state-changing`. The ROE tier can be no lower than: read-only / writes-artifacts -> auto,
  touches-network -> notify, state-changing -> approve. Propose the lowest tier that is safe.

## 3. Draft the adapter (YAML)
```yaml
name: hayabusa                        # becomes tool_hayabusa
description: Sigma-based EVTX threat hunting: a CSV timeline of rule hits from a folder of .evtx files
binary: /opt/hayabusa/hayabusa
sha256: <from onboard_inspect>
version_cmd: [--version]
risk: writes-artifacts
network: none                         # 'allowed' only for a touches-network tool, and only if it must
timeout_s: 1800
output: csv                           # json | ndjson | csv | lines | text
output_from: timeline                 # stdout, or an output_file param
params:
  - {name: evtx_dir, type: evidence_path, required: true, description: folder of .evtx files}
  - {name: min_level, type: enum, values: [informational, low, medium, high, critical], default: medium}
  - {name: timeline, type: output_file, ext: csv}   # made by the runner under the case; agents never pick paths
argv: [csv-timeline, -d, "{evtx_dir}", -m, "{min_level}", -o, "{timeline}", --no-wizard, -q]
roe: {tier: auto, note: read-only on evidence, writes its CSV under the case}
experts: [forensicator, endpoint_analyst]
```
- No shell, ever: argv is a list, and every value is one argument. Free-text `string` params need a `pattern`.
  Values may not start with `-` unless `allow_dash: true`.
- Evidence comes only through `evidence_path` params (checked against the evidence roots, mounted read-only).
- `pinned_paths`: the folders or files beside the binary that decide what it does (rules, config, signatures).
  `onboard_inspect` lists them with their size and a manifest digest. They are approved with the binary; a rule update
  or an edit blocks the tool until the analyst trusts it again.
- Optional params go inside `{if: <param>, args: [...]}` blocks, or have a default.

## 4. Prove it in the sandbox
- `onboard_trial` with the draft and sample evidence (the case folder or the analyst's sample set): one approved run per
  mode the experts will use, and one with bad input to see how it fails.
- Check: exit code 0, the output parses (rows > 0 on evidence that should hit), nothing was written outside the
  output folder, and no network was needed. Fix the draft and run again as needed.
- The trials are attached to the proposal as golden results: the tool is checked against them again whenever its
  binary or pinned data changes.
- Before proposing, run the FINAL spec at least once (after your last change to argv, params or pins): the proposal
  is refused unless a trial ran exactly what you propose, so the analyst approves what was tried.

## 5. Write a usage skill for each expert who gets it
For each expert in `experts`: when to use the tool (and when not), the exact call with arguments, how to read the
output (columns, levels, what a hit means), its false positives and blind spots, and how to verify a hit with
other evidence. Name it `<tool>-<expert-task>`, e.g. `hayabusa-evtx-triage`.

## 6. Submit
`onboard_propose` with kind `binary`, the final YAML, the skills, the provenance and notes for the analyst (anything
odd in the docs, the modes you left out and why, what to check before approving).

## MCP servers in quarantine
`onboard_list` shows their tools and descriptions (untrusted). For each tool decide the tier from what it does
(reads -> auto; changes, actions -> approve) and which experts need it; leave out tools nobody needs. Submit
`onboard_propose` with kind `mcp` and `{server, tools: {tool: {tier, experts, note}}}`, plus usage skills.
