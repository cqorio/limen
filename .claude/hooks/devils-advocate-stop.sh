#!/usr/bin/env bash
# Stop hook: trigger the devils-advocate subagent to adversarially review the work before the turn
# ends. Guards against an infinite loop via stop_hook_active: once this hook has already blocked
# (review ran, Claude stopped again), stop_hook_active is true and we let the turn end.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "devils-advocate-stop: python3 not found; skipping review (fail-open)" >&2
  exit 0
fi

python3 -c '
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    print("devils-advocate-stop: unparseable hook input; skipping review (fail-open)", file=sys.stderr)
    sys.exit(0)

if data.get("stop_hook_active"):
    sys.exit(0)

reason = (
    "Before finishing, launch the devils-advocate subagent (Agent tool, "
    "subagent_type: \"devils-advocate\") to adversarially review the work just "
    "completed. Pass it the original request and let it run git diff itself. "
    "Address every [CRITICAL] and [HIGH] blocking objection it raises (fix, or "
    "justify with reasoning). The turn may end once the subagent emits its "
    "APPROVED line, or once you have relayed its blocking objections to the user "
    "for a decision. Do not re-run the review after it has already run this turn."
)

print(json.dumps({"decision": "block", "reason": reason}))
'
