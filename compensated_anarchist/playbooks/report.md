# Playbook: write a report from this mission's data
Objective: a report built from this mission's data only (case record, conversations, tool results, case files), in
the format of the analyst's own reports. Nothing is made up: every fact is cited and checked, and anything missing
is asked, never guessed.

0. **Ask the analyst once, briefly,** before tasking anyone (defaults they can accept by replying "default"):
   1. Report type (e.g. incident report, SITREP, hunt or CTE after-action, executive brief). Default: incident report.
   2. Audience and distribution.
   3. Classification markings: banner and portion markings. **No default: they always come from the analyst.**
   4. The period it covers, and anything it must include. Default: the whole case.
   Then stop and wait. Record each answer with `case_analyst_statement`, quoting the analyst's own words exactly.
1. **Task the reporter** with the answers, verbatim, and their statement ids (STA-...).
2. **When the reporter returns `needs_input`** (questions, conflicting sources, or a report template waiting for
   approval in Skills): ask the analyst exactly those questions. Record each answer with `case_analyst_statement`,
   then follow up with the same reporter (`subagent_message`) giving the statement ids. Never answer for the analyst
   and never fill a gap yourself.
3. **Present the draft:** the file and version, its questions and gaps, and the verifier's warnings. The analyst
   reviews it and may edit the file directly.
4. **Final:** only when the analyst says it is final, task the same reporter to finalize it (`report_finalize`;
   the analyst approves). If the analyst edited the draft, the reporter reads their changes and proposes what it
   learned as skill updates (how it writes and what it asks, never facts).
