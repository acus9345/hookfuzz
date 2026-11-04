/** Validation of hook stdout, following the Claude Code hooks reference rules. */
export type StdoutKind = "empty" | "text" | "json" | "invalid-json";
export interface ParsedStdout { kind: StdoutKind; json?: Record<string, unknown>; error?: string }

/** Claude Code treats stdout as JSON only if it is one object: starts with `{` and ends with `}` (trimmed). */
export function parseStdout(stdout: string): ParsedStdout {
  const t = stdout.trim();
  if (!t) return { kind: "empty" };
  if (!(t.startsWith("{") && t.endsWith("}"))) return { kind: "text" };
  try {
    const v = JSON.parse(t);
    if (typeof v !== "object" || v === null || Array.isArray(v)) return { kind: "text" };
    return { kind: "json", json: v };
  } catch (e) {
    return { kind: "invalid-json", error: (e as Error).message };
  }
}

const UNIVERSAL: Record<string, string> = {
  continue: "boolean", stopReason: "string", suppressOutput: "boolean", systemMessage: "string", terminalSequence: "string",
  decision: "string", reason: "string", hookSpecificOutput: "object",
};
const PERMISSION_DECISIONS = ["allow", "deny", "ask", "defer"];

export interface ValidationResult { valid: boolean; errors: string[]; warnings: string[] }

export function validateOutput(event: string, out: Record<string, unknown>): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const [k, v] of Object.entries(out)) {
    const want = UNIVERSAL[k];
    if (!want) { warnings.push(`unknown top-level field "${k}"`); continue; }
    const got = Array.isArray(v) ? "array" : v === null ? "null" : typeof v;
    if (got !== want) errors.push(`"${k}" must be ${want}, got ${got}`);
  }
  if (typeof out.decision === "string" && out.decision !== "block") {
    if (event === "PreToolUse" && ["approve", "block"].includes(out.decision))
      warnings.push(`top-level decision "${out.decision}" is deprecated for PreToolUse; use hookSpecificOutput.permissionDecision`);
    else errors.push(`"decision" only accepts "block", got "${out.decision}"`);
  }
  const hso = out.hookSpecificOutput as Record<string, unknown> | undefined;
  if (hso && typeof hso === "object" && !Array.isArray(hso)) {
    if (hso.hookEventName === undefined) errors.push("hookSpecificOutput.hookEventName is required");
    else if (hso.hookEventName !== event) errors.push(`hookSpecificOutput.hookEventName "${String(hso.hookEventName)}" does not match event "${event}"`);
    if (hso.additionalContext !== undefined && typeof hso.additionalContext !== "string") errors.push("hookSpecificOutput.additionalContext must be string");
    if (typeof hso.additionalContext === "string" && hso.additionalContext.length > 10000) warnings.push("additionalContext exceeds 10,000 chars and will be truncated to a file preview");
    if (event === "PreToolUse") {
      const pd = hso.permissionDecision;
      if (pd !== undefined && !PERMISSION_DECISIONS.includes(pd as string)) errors.push(`permissionDecision must be one of ${PERMISSION_DECISIONS.join("/")}`);
      if (hso.permissionDecisionReason !== undefined && typeof hso.permissionDecisionReason !== "string") errors.push("permissionDecisionReason must be string");
      if (hso.updatedInput !== undefined && (typeof hso.updatedInput !== "object" || hso.updatedInput === null)) errors.push("updatedInput must be object");
    }
    if (event === "PermissionRequest" && hso.decision !== undefined) {
      const d = hso.decision as Record<string, unknown>;
      if (typeof d !== "object" || !d || !["allow", "deny"].includes(d.behavior as string)) errors.push("decision.behavior must be allow or deny");
    }
  }
  for (const k of ["systemMessage"]) if (typeof out[k] === "string" && (out[k] as string).length > 10000) warnings.push(`${k} exceeds 10,000 chars`);
  return { valid: errors.length === 0, errors, warnings };
}
