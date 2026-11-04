#!/usr/bin/env node
// PreToolUse hook: JSON decisions. Denies writes to .env, asks for git push, allows the rest.
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  let p;
  try { p = JSON.parse(raw); } catch { process.exit(0); } // never crash on bad input
  const input = (p && typeof p.tool_input === "object" && p.tool_input) || {};
  const out = (permissionDecision, permissionDecisionReason) =>
    console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason } }));
  const file = String(input.file_path ?? "");
  const cmd = String(input.command ?? "");
  if (/(^|[\\/])\.env($|\.)/.test(file)) return out("deny", "Writing .env files is not allowed");
  if (/\bgit\s+push\b/.test(cmd)) return out("ask", "Confirm before pushing");
  if (/^(npm test|ls|pwd)\b/.test(cmd)) return out("allow", "Safe read-only command");
  process.exit(0);
});
