# Playbook: Onboard a new tool
Objective: the team can use a new defensive tool the analyst supplied, safely, after the analyst approves it.

0. **From the analyst:** the tool's path (or the MCP server's name in harness.yaml, with `quarantine: true`), where
   it came from (vendor, version, whether its signature was checked), which experts should use it and for what, the
   folders it reads beside the binary (rules, config: they are pinned and approved with it), and sample evidence to
   try it on. Name the capability you want, not a guessed subcommand: the tool_integrator finds the command. Ask for what is missing. Never fetch a tool or its docs from the internet.
1. **Task the tool_integrator** with all of that. It inspects the tool, reads its docs and help (sandboxed, each run
   approved by the analyst), drafts the adapter, proves it on the sample evidence, writes a usage skill for each
   expert, and submits one onboarding proposal.
2. **Tell the analyst** the proposal is waiting (dashboard: Learning; CLI: `canarchist tools review`), with the
   tool_integrator's summary: what the tool does, its risk and proposed tier, the experts, the trial results, and
   anything the analyst should check first. Nothing is usable until they approve it.
3. **After approval** (only if the analyst asks): task one of the experts who got the tool with a small job on the
   sample evidence, so the analyst sees it used once with its usage skill.
