// Shared helper for the dsh-* adapters: reads a Claude Code PreToolUse payload
// from stdin and prints a deny decision when `decide` returns a reason.
// The command text is only analysed, never executed.
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

/** Import a module from a local clone of an acus9345/dsh-* repo (built with `npm run build`). */
export function dsh(rel) {
  const root = process.env.DSH_TARGETS ?? resolve(process.cwd(), "dsh-targets");
  return import(pathToFileURL(resolve(root, rel)).href);
}

export function run(decide) {
  let raw = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (d) => (raw += d));
  process.stdin.on("end", async () => {
    let p;
    try { p = JSON.parse(raw); } catch { process.exit(0); }
    if (!p || typeof p !== "object") process.exit(0);
    const input = p.tool_input && typeof p.tool_input === "object" ? p.tool_input : {};
    const reason = await decide(input, p);
    if (reason) console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: String(reason).slice(0, 2000) } }));
    process.exit(0);
  });
}
