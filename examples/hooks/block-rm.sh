#!/usr/bin/env bash
# PreToolUse hook: block destructive rm -rf commands with exit code 2.
input=$(cat)
if printf '%s' "$input" | grep -Eq '"command"[[:space:]]*:[[:space:]]*"[^"]*rm -rf'; then
  echo "Blocked: rm -rf is not allowed by policy" >&2
  exit 2
fi
exit 0
