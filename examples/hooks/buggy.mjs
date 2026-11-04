#!/usr/bin/env node
// A deliberately fragile hook used to demo `hookfuzz fuzz`.
let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  const p = JSON.parse(raw);                         // crashes on malformed stdin
  const cmd = p.tool_input.command;                 // crashes when tool_input missing
  if (cmd.length > 100000) for (;;) {}              // hangs on huge input
  if (cmd.includes("🌍")) console.log("{not json}"); // invalid JSON output
  else console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "maybe" } })); // schema error
});
