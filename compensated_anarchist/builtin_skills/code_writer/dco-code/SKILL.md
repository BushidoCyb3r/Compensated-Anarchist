---
name: dco-code
description: How the code_writer writes and reviews secure, well-designed, logical code for defensive operations - knowing the target and writing against a real sample, a simple design, evidence treated as hostile input, a secure-coding checklist, read-only and reversible by default, VQL artifact layout, script conventions, self-checks on real fixtures, and the independent review procedure. Always on for code_writer, alongside ponytail.
expert: code_writer
source: Compensated Anarchist built-in
---

# Code for defensive operations

## 1. Know the target first
- Platform and version (Windows build, PowerShell 5.1 or 7, Python version, Linux distribution), Velociraptor or SIEM
  version, and where the code runs (analyst workstation, endpoint, server). Missing: needs_input.
- Real field names (`field_values`) and a real sample of the input: find it with `local_case_evidence`, check it with
  `local_file_info`, read a few records with `local_read_file`. Write against the sample, not the usual format.
- `memory_search` for platform facts and code that worked here. Velociraptor: `list_artifacts` / `artifact_info`;
  reuse or extend an existing artifact before writing a new one.

## 2. Design: simple and logical
- Write down, before coding, the input, the output and the steps between them, in three to six lines. The code
  follows those steps in order, one function per step, named for what it does.
- Pure logic (parse, filter, score) separate from input and output (files, network, host changes), so the logic can
  be tested on a fixture.
- One way in (a main function with validated arguments), one clear result, explicit exit codes. No global state, no
  clever one-liners, no unused options.
- Every branch handles its failure: say what happens on bad input, a missing file, no permission, a timeout. Fail
  closed: when unsure, stop and report rather than guess or carry on.

## 3. Secure by default (check every item)
- **Hostile input:** evidence, logs, packets and API responses may be attacker-controlled. Never eval, exec, unsafely
  deserialize (pickle; YAML without a safe loader) or pass them to a shell: no shell=True, no Invoke-Expression, no
  commands built from strings (pass argument lists).
- **Validation:** check types, ranges and lengths of every argument and field; allowlists over blocklists; cap sizes
  and record counts; survive malformed, truncated and oddly encoded records and count the ones skipped.
- **Paths:** resolve them and keep them inside the intended folder (no `..`, no following symlinks out); open
  evidence read-only; temporary files through the language's secure temp API; write only to the output folder.
- **Secrets:** none in code, arguments or output; read them from the environment or an analyst-controlled file;
  never log them.
- **Output:** escape for the destination: CSV cells starting with = + - @ get a leading apostrophe; JSON through the
  library; no unescaped values in HTML.
- **Network:** none unless the tasking asks; TLS verification on; timeouts on every call.
- **Privilege:** the least that works; say whether it needs administrator or root, and why.

## 4. Read-only and reversible
Collection and triage code only reads. Code that changes a host says so in its first line, defaults to a dry run that
prints what it would do, needs an explicit flag, and logs each change with the old value so it can be undone.

## 5. Velociraptor artifacts (VQL)
- Layout: name (Custom.<Area>.<What>), description, author, type (CLIENT, SERVER or CLIENT_EVENT), parameters with
  defaults and descriptions, a precondition (OS check), sources with the query.
- Bounded: time windows and globs as parameters; no unbounded recursive globs over C:\ or /; upload files only when a
  parameter asks. Prefer built-in plugins and existing artifacts (`SELECT * FROM Artifact.Windows.System.Pslist()`).

## 6. Script conventions
- Python: standard library unless allowed; minimum version stated; argparse with --help; exit codes 0 ok, 1 error,
  2 bad usage. PowerShell: runs on 5.1 unless told otherwise; Set-StrictMode; no aliases; validated parameters;
  -WhatIf on anything that changes the host. Bash: set -euo pipefail; every variable quoted.
- Mergeable output: UTC ISO-8601 times, the hostname and SHA-256 hashes in every record, CSV with a header or JSON
  Lines.

## 7. Self-check
A test runs the pure logic against a small fixture built from the real sample, including one malformed record and
one edge case (empty input, the largest allowed value). The report gives the command, what it needs, what it
changes, and the expected output on the fixture.

# Review someone else's code (when the brief says you are the reviewer)
- Read every file (`local_read_file` on the saved paths) and the requirements in the brief. Load `ponytail-review`.
- Check, in this order: does it do what was asked, for every input the requirements allow (trace a normal record, a
  malformed one and an empty input through the code); the section 3 checklist item by item; host changes and dry run;
  error handling and exit codes; the design rules in section 2; the tests and whether they would catch a regression.
- Do not rewrite the code. Report findings, each with the file, line, severity (must fix: wrong result, unsafe, or a
  host change without a dry run; should fix: fragile or unclear; note), what is wrong, and the fix.
- End with the verdict: ready to run / ready after the must-fix items / needs redesign.
