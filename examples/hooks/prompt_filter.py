#!/usr/bin/env python3
"""UserPromptSubmit hook: block prompts containing secrets, add context otherwise."""
import json, re, sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
prompt = str(data.get("prompt", "")) if isinstance(data, dict) else ""
if re.search(r"(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})", prompt):
    print(json.dumps({"decision": "block", "reason": "Prompt appears to contain a secret key"}))
    sys.exit(0)
print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": "Project uses pytest."}}))
