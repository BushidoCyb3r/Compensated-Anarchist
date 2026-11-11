#!/usr/bin/env bash
# Stop Compensated Anarchist (the web dashboard). It shuts down cleanly: the audit log and chat history are
# closed properly. Nothing is deleted - your cases, conversations, memory, skills and audit logs stay; only this
# start's access token stops working. Start it again with scripts/start.sh (which prints a new token).
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -x .venv/bin/canarchist ]; then
  echo "Compensated Anarchist is not installed here: nothing to stop." >&2
  exit 0
fi
exec .venv/bin/canarchist stop "$@"
