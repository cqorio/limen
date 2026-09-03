#!/usr/bin/env python3
"""Make "run ponytail before each commit" enforceable instead of remembered.

Two modes, one file:
  record   PostToolUse(Skill) -- stamp a marker when a ponytail skill runs
  gate     PreToolUse(Bash)   -- refuse `git commit` if the marker predates HEAD

WHY BLOCKING. This was wired as a PostToolUse reminder after every Edit/Write and it drifted badly: 22
commits, 4 passes, one stretch of 8 with none. The graphify guard beside it -- same event, but blocking --
was obeyed every time in that same session. A reminder on every edit becomes noise; a gate in front of the
commit does not.

Only exit 2 blocks a tool call, so every other failure (bad JSON, no git, no interpreter) already falls
through as "allow". That is the behaviour we want and it costs no code to get.
"""
import json
import os
import pathlib
import subprocess
import sys


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    data = json.load(sys.stdin)
    root = data.get("cwd") or os.getcwd()
    marker = pathlib.Path(root, ".claude", ".ponytail-pass")

    if mode == "record":
        if "ponytail" in str((data.get("tool_input") or {}).get("skill", "")):
            marker.touch()          # creates it, and bumps mtime when it already exists
        return 0

    cmd = (data.get("tool_input") or {}).get("command", "")
    if data.get("tool_name") != "Bash" or "git commit" not in cmd:
        return 0
    head = subprocess.run(["git", "-C", root, "log", "-1", "--format=%ct"],
                          capture_output=True, text=True, timeout=10)
    if head.returncode != 0:
        return 0                                    # no commits yet: nothing to gate against
    if marker.exists() and marker.stat().st_mtime > int(head.stdout.strip()):
        return 0                                    # a pass has run since the last commit

    print('BLOCKED: no ponytail pass since the last commit.\n'
          'Invoke the Skill tool with skill="ponytail:ponytail" (and "ponytail:ponytail-audit") on THIS\n'
          'diff, act on what it finds, then commit. The pass is recorded automatically.',
          file=sys.stderr)
    return 2                                        # 2 = block the call, stderr goes to the model


if __name__ == "__main__":
    sys.exit(main())
