---
name: report-writing
description: How the reporter writes a report from mission data only - template, sources, citations, questions, verification - with the default layout and the checklist of questions to ask early. Always on for the reporter; the checklist grows from the questions it had to ask.
expert: reporter
source: Compensated Anarchist built-in
---

# Write a report from mission data

## 1. What is wanted
From the brief: report type, audience, period covered, classification markings (analyst statement), and anything
the analyst said it must contain. Go through the checklist below now: every item the mission data and the brief do
not answer becomes a question, asked in the same report.

## 2. Template
- `report_examples` shows the example library and which types have an approved template.
- Approved template: `skill_view report-template-<type>` and follow its sections, order, fields and tables.
- Examples but no template: read 2 or 3 examples of that type with `report_example_read`, then write the template:
  section headings in order, required fields as placeholders (`<DTG>`, `<case number>`, `<classification banner>`),
  table columns, tone, typical length, where markings go. It must contain no value from the examples: no names,
  hosts, IPs, dates, numbers or findings. Save it with `skill_create(name="report-template-<type>", ...)`. It waits
  for the analyst's approval: say so in your report (status `needs_input`), and draft in the default layout
  meanwhile only if the brief asks for a draft now.
- No examples: use the default layout below, or the layout the analyst gave.

## 3. Gather the mission data
- `report_sources(kind="case")`, then `kind="files"`, then `kind="events"` (use `query` to narrow it).
- Read in full (`report_source`) everything you will rely on: findings, timeline, IOCs, evidence, statements,
  subagent reports, hunt and CTE results.
- Note conflicts between sources (different times or counts for the same thing): they become questions.

## 4. Draft
- Every statement that carries a fact ends with its citation(s). Values in backticks. One fact per sentence where
  practical, so the citation fits it.
- Present findings without an analyst verdict as unreviewed. Give confidence as the source states it.
- Keep facts, assessments and recommendations apart: an assessment says whose it is and carries the source's
  confidence ("the network_analyst assessed ... (medium confidence) [EV-..]").
- Write for the audience in the brief: an executive reads impact, status and the decisions needed, without tool names
  or queries; a technical reader needs hosts, times, indicators and the evidence trail. Both: the bottom line first,
  the detail after.
- Times in UTC, in the date-time format the analyst uses (ask if the template does not show it). Active voice; short
  sentences; no adjectives the data does not support ("massive", "sophisticated").
- Recommendations come from the findings' recommended actions and the analyst's statements, cited.
- Nothing you cannot cite goes in the body: it goes in **Questions / gaps**, phrased as a question for the analyst.
- Markings: only from an analyst statement. None yet: put the question first in Questions / gaps.

## 5. Verify and save
- `report_save(name=<type or topic>, content=..., report_type=<type>)`. If it says NOT SAVED, fix each blocking
  problem (cite, correct, or move to Questions / gaps) and save again. Look at the warnings too.
- `submit_report`: the draft path and version, the questions for the analyst (status `needs_input` if any), the
  warnings, and the template status.

## 6. Final
Only when the analyst says the report is final: `report_finalize(name)`. The analyst approves it in the dialog.

# Checklist: ask early (grows with use)
- Classification banner and portion markings.
- Report type, audience and distribution.
- The period the report covers, and the report date/time format (DTG) they use.
- Mission, operation or case numbers the report must carry, if not in the case record.
- Who the report is from (unit, author, point of contact).

# Default layout (when there is no template)
1. Title, markings (from the analyst), date `[NOW]`, case.
2. **Bottom line up front:** 3-5 sentences: what happened, impact, status, decisions needed.
3. **Scope:** mission, period, systems and data covered.
4. **Timeline** table: time (UTC) | host | event | source.
5. **Findings:** one section each: what, severity, analyst verdict, ATT&CK, affected assets, evidence.
6. **Indicators** table: type | value | context | source.
7. **Actions taken** and **recommendations.**
8. **Questions / gaps** for the analyst.
