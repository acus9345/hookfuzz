import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { isToolEvent } from "./events.js";

export interface PayloadOptions {
  tool?: string;
  input?: Record<string, unknown>;
  cwd?: string;
  sessionId?: string;
  overrides?: Record<string, unknown>;
}

const DEFAULT_TOOL_INPUT: Record<string, Record<string, unknown>> = {
  Bash: { command: "npm test", description: "Run test suite" },
  Write: { file_path: "/tmp/project/src/index.ts", content: "export {};\n" },
  Edit: { file_path: "/tmp/project/src/index.ts", old_string: "a", new_string: "b" },
  Read: { file_path: "/tmp/project/README.md" },
};

/** Deep-merge plain objects (arrays and scalars replace). `null` in overrides deletes a key. */
export function deepMerge(base: Record<string, unknown>, over: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(over)) {
    if (v === null) delete out[k];
    else if (isObj(v) && isObj(out[k])) out[k] = deepMerge(out[k] as Record<string, unknown>, v);
    else out[k] = v;
  }
  return out;
}
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Build a realistic stdin payload for a hook event, mirroring what Claude Code sends. */
export function buildPayload(event: string, opts: PayloadOptions = {}): Record<string, unknown> {
  const cwd = opts.cwd ?? process.cwd();
  const sid = opts.sessionId ?? "hookfuzz-" + randomUUID().slice(0, 8);
  const p: Record<string, unknown> = {
    session_id: sid,
    transcript_path: join(cwd, ".claude", "transcripts", `${sid}.jsonl`),
    cwd,
    permission_mode: "default",
    hook_event_name: event,
  };
  const tool = opts.tool ?? "Bash";
  const toolInput = opts.input ?? DEFAULT_TOOL_INPUT[tool] ?? {};
  if (isToolEvent(event)) {
    Object.assign(p, { tool_name: tool, tool_input: toolInput, tool_use_id: "toolu_hookfuzz_" + randomUUID().slice(0, 12) });
    if (event === "PostToolUse") p.tool_response = { stdout: "", stderr: "", interrupted: false };
    if (event === "PostToolUseFailure") p.error = "Command failed with exit code 1";
  } else {
    switch (event) {
      case "UserPromptSubmit": p.prompt = (opts.input?.prompt as string) ?? "Write a function to parse CSV"; break;
      case "Notification": Object.assign(p, { message: "Claude needs your permission to use Bash", notification_type: "permission_prompt" }); break;
      case "Stop": case "SubagentStop": Object.assign(p, { stop_hook_active: false, last_assistant_message: "Done." }); break;
      case "SessionStart": Object.assign(p, { source: "startup", model: "claude-sonnet-4-5" }); break;
      case "SessionEnd": p.reason = "other"; break;
      case "PreCompact": case "PostCompact": Object.assign(p, { trigger: "manual", custom_instructions: "" }); break;
      case "SubagentStart": p.agent_type = "general-purpose"; break;
      case "Setup": p.trigger = "init"; break;
      case "DirectoryAdded": p.source = "slash_command"; break;
      case "Elicitation": case "ElicitationResult": p.mcp_server_name = "example-server"; break;
    }
    if (opts.input && event !== "UserPromptSubmit") Object.assign(p, opts.input);
  }
  return opts.overrides ? deepMerge(p, opts.overrides) : p;
}
