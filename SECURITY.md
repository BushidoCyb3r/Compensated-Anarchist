# Security policy

Compensated Anarchist approves and runs actions against real networks, so its safety controls are its most important
feature. Reports of anything that weakens them are very welcome.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting instead: the repository's **Security** tab,
then **Report a vulnerability**. Include:

- what you found and why it matters;
- the steps or a minimal configuration that shows it (the scripted test model in `tests/test_harness.py` is a good
  way to show an agent doing something it should not);
- the version or commit, and the model profile if a model's behaviour is involved.

Please leave out real data from your own network: addresses, hostnames, keys, logs. Synthetic values work.

Reports are handled on a best-effort basis. Fixes are released on `main`, with credit to the reporter if they want it.

## In scope

Anything that lets an action happen without the controls the README describes, for example:

- running an action without the approval its ROE tier requires, or getting past a built-in floor (the human gate on
  endpoint actions, gate-everything for vulnerability assessment);
- acting on a target outside the ROE scope, or on a protected asset without approval;
- text in data the agents read (logs, alerts, files, tool output, documents) causing an action, a memory or a skill
  without the analyst's approval (prompt injection with an effect);
- escaping the forensic path jail or the bubblewrap tool sandbox, or running a file from evidence;
- signing in to the dashboard without the access token and the account password, cross-site request forgery,
  script injection into the dashboard;
- writes through a connector that is meant to be read-only (Security Onion, Elastic, Splunk, Archer, OpenCTI), or
  query injection into one;
- secrets leaking into logs, case files, reports, model requests or the repository;
- tampering with the audit log without `canarchist audit-verify` detecting it.

## Out of scope

- Vulnerabilities in the connected products themselves (Security Onion, Velociraptor, Splunk, Elastic, MISP,
  OpenCTI, Archer) or in model servers. Please report those to their projects.
- Attacks that need root, or the harness account itself, on the harness host.
- A model following planted instructions when the harness still stopped the action. That is the model's weakness, and
  `canarchist redteam` measures it; it is in scope only if the harness let the action through.
- Missing hardening that the documentation already lists as a known limit (README, *Known limits*).

## Checking it yourself

- `canarchist redteam --model <profile>` runs the prompt-injection scenarios against a model, with stub tools only.
- `tests/test_hardening.py` and the rest of the suite (`scripts/install.sh --test`) cover the controls.
- The README's *Security checks* section lists the static analysis, dependency audit and secret scan run before a
  release.
