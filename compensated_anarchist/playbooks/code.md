# Playbook: write code for a DCO task
Objective: code that does what the mission needs, correct for every input it allows, safe against hostile input,
simple to read, tested against a real sample, reviewed by a second code writer, and never run by the harness.

0. **Requirements.** From the analyst's request, establish:
   - what the code must do: its input, its output, and the steps between;
   - where it runs: platform and version, interpreter, and the place (analyst workstation, endpoint, Velociraptor
     server, SIEM);
   - the input, and a real sample of it if one is in the case evidence folder;
   - the output format and who or what reads it;
   - whether it may change anything on a host. Default: read-only.
   Ask only for what is missing and matters, in one message; state the defaults you assume.
1. **Write** (code_writer): the requirements, word for word, in the brief; where the sample is; the constraints (no
   new dependencies unless the analyst allows them). Expected output: the saved files, the command to run each, what
   it changes, the test fixture and its expected output, and what was not checked.
2. **Independent review** (a second code_writer, never the author): the requirements and the saved file paths from
   step 1, with "you are the reviewer". It follows the review procedure in `dco-code` with `ponytail-review`, and
   returns findings (file, line, severity, fix) and a verdict. It does not rewrite the code.
3. **Fix:** send the must-fix and should-fix findings to the author (`subagent_message` to the same code_writer). It
   fixes them and saves again; the earlier version is kept in the case's authored folder, under older/. If a fix
   changed the design, send the new version back to the reviewer for one more look.
4. **Present to the analyst:**
   - the files and where they are;
   - how to run each one: command, permissions, inputs;
   - what it changes on a host, if anything, and its dry-run flag;
   - the review findings and how each was resolved, and the reviewer's verdict;
   - what was not checked, and the remaining risks.
   The analyst decides whether, where and when it runs.
