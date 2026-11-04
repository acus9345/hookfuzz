/** Hook events known to hookfuzz (from the Claude Code hooks reference, Nov 2026). */
export const TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied"] as const;
export const EVENTS = [
  ...TOOL_EVENTS,
  "UserPromptSubmit", "UserPromptExpansion", "Notification", "MessageDisplay", "Stop", "StopFailure", "SubagentStart", "SubagentStop",
  "SessionStart", "SessionEnd", "Setup", "PreCompact", "PostCompact", "PostToolBatch", "TaskCreated", "TaskCompleted",
  "TeammateIdle", "InstructionsLoaded", "ConfigChange", "CwdChanged", "DirectoryAdded", "FileChanged", "WorktreeCreate",
  "WorktreeRemove", "PreModelSwitch", "PostModelSwitch", "Elicitation", "ElicitationResult",
] as const;
export type HookEvent = (typeof EVENTS)[number] | (string & {});

/** Events where exit code 2 blocks the action. */
export const BLOCKING_EVENTS = new Set<string>([
  "PreToolUse", "UserPromptSubmit", "UserPromptExpansion", "Stop", "SubagentStop", "TeammateIdle", "TaskCreated",
  "TaskCompleted", "ConfigChange", "PostToolBatch", "PreCompact", "PreModelSwitch", "Elicitation", "ElicitationResult",
  "WorktreeCreate", "WorktreeRemove",
]);

export function isToolEvent(e: string): boolean {
  return (TOOL_EVENTS as readonly string[]).includes(e);
}

export function normalizeEvent(e: string): string {
  const hit = (EVENTS as readonly string[]).find((x) => x.toLowerCase() === e.toLowerCase());
  return hit ?? e;
}
