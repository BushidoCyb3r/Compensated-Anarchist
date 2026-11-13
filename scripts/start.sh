#!/usr/bin/env bash
# Start Compensated Anarchist (the web dashboard) and print this start's access token.
#
#   scripts/start.sh                                   # defaults: dashboard.serve in config/harness.yaml
#   scripts/start.sh --case IR-0042 --posture respond  # pick the case / allow response actions
#   scripts/start.sh --host 0.0.0.0                    # every interface: browsers on other devices too (HTTPS)
#   scripts/start.sh --localhost                       # only this host's browser (http://127.0.0.1)
#   scripts/start.sh --foreground                      # stay attached to this terminal (Ctrl+C stops it)
#
# The very first run builds the installation: it runs scripts/install.sh (Python environment, config files,
# every folder) and asks you to create the dashboard account (username + password, stored as a salted hash).
# Every run asks three questions - posture (observe/respond), address (0.0.0.0 or 127.0.0.1) and
# case - where Enter keeps your last choice (--yes skips them; options such as --posture skip one), then starts
# a new session: a new access token, with nothing overwritten or deleted. The Settings page in the dashboard can
# change the same three while it runs.
# Cases, conversations, memory, skills, audit logs, plans, reports and the account stay as they are.
# If it is already running, it offers to restart it with a new token. Stop it with scripts/stop.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -x .venv/bin/canarchist ]; then
  echo "First run: building Compensated Anarchist (scripts/install.sh) before starting it."
  echo
  scripts/install.sh
  echo
fi
exec .venv/bin/canarchist start "$@"
