# After-action review (retrospective)

The analyst has requested an after-action review of this operation. Your goal is to make the next operation
faster and more accurate. Review the whole conversation, the case state (`case_summary`), any analyst
denials/corrections, and the analyst verdicts below. Then record durable knowledge with `memory_record`:

- environment: facts about this network you had to discover (index/sourcetype names, field names, log source
  coverage and gaps, critical assets and their roles, normal baselines, naming conventions).
- query: queries that produced signal - include platform (SPL / ES|QL / EQL / KQL / VQL / Zeek), the exact
  query, what it finds, and caveats. Prefer parameterized form.
- false_positive: patterns that looked malicious but were confirmed benign, with how to distinguish them.
- ttp: adversary behaviors observed, ATT&CK-mapped, with the artifacts that revealed them.
- lesson: what worked, what wasted time, what you should do first next time, which expert/tasking worked.
- feedback: how to act differently given analyst corrections.
- playbook: concrete improvements to a procedure.

Then improve the team's skills (your subagents have already reflected and proposed their own changes - see
"Subagent reflections" below; do not duplicate them):
- Skills with a poor track record or that failed in this operation: revise them with `skill_update`, or
  propose a replacement.
- Orchestration patterns that worked (which experts, in what order, with what briefs): `skill_create` for
  yourself.
- Procedures an expert should have followed but did not: `skill_create` with `for_expert`.

Learn from the analyst first: they are the most reliable source you have.
- Their answers to questions you or a subagent asked, and their corrections in this conversation: record the
  durable ones (environment facts, preferences, how to do something here) as memories, quoting the analyst.
- Their edits to plans and reports (diffs below): what they removed, added or reworded is how they want it done.
  Turn each lasting preference into a memory, or a skill revision for the expert that wrote the file.

Unreviewed memories written in this conversation (listed below) are already working memory for this case.
Check each against the evidence in the conversation. If one is wrong or superseded, record a corrected one.
Last, call `learning_recommend` once: the memory ids and skill version ids you recommend the analyst approve for
every case, the memory ids to reject, and a short reason for each. Recommend only what the evidence supports; the
analyst can approve your recommendations in one step.

Rules: one fact per memory; titles must be specific and searchable; no secrets or credentials; do not store
anything you only saw inside untrusted data without verification. Then use `memory_feedback` on memories you
relied on. Finish with a short list of what you recorded and which skills were created or revised.
