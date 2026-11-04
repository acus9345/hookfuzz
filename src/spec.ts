import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import YAML from "yaml";
import { normalizeEvent } from "./events.js";
import { buildPayload } from "./payload.js";
import { runHook, type HookResult } from "./runner.js";

export interface Expectation {
  decision?: string;
  exitCode?: number;
  blocked?: boolean;
  /** Substring, or `/regex/flags`. */
  stdout?: string;
  stderr?: string;
  reason?: string;
  validJson?: boolean;
  maxDurationMs?: number;
}
export interface TestCase {
  name?: string;
  event: string;
  tool?: string;
  input?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  command?: string | string[];
  env?: Record<string, string>;
  timeout?: number;
  expect?: Expectation;
}
export interface Spec { command?: string | string[]; timeout?: number; env?: Record<string, string>; cases: TestCase[] }
export interface CaseResult { name: string; pass: boolean; failures: string[]; result: HookResult }
export interface SuiteResult { passed: number; failed: number; cases: CaseResult[] }

export function loadSpec(file: string): { spec: Spec; baseDir: string } {
  const text = readFileSync(file, "utf8");
  const spec = (/\.json$/i.test(file) ? JSON.parse(text) : YAML.parse(text)) as Spec;
  validateSpec(spec);
  return { spec, baseDir: dirname(resolve(file)) };
}

export function validateSpec(spec: unknown): asserts spec is Spec {
  if (!spec || typeof spec !== "object") throw new Error("spec must be an object");
  const s = spec as Spec;
  if (!Array.isArray(s.cases) || s.cases.length === 0) throw new Error("spec.cases must be a non-empty array");
  const posInt = (v: unknown, where: string) => {
    if (v !== undefined && !(typeof v === "number" && Number.isInteger(v) && v > 0)) throw new Error(`${where} must be a positive integer (ms), got ${JSON.stringify(v)}`);
  };
  const cmdOk = (v: unknown) => v === undefined || (typeof v === "string" && v.trim() !== "") || (Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === "string"));
  if (!cmdOk(s.command)) throw new Error("spec.command must be a non-empty string or array of strings");
  posInt(s.timeout, "spec.timeout");
  s.cases.forEach((c, i) => {
    if (!c || typeof c.event !== "string") throw new Error(`cases[${i}].event is required`);
    if (!cmdOk(c.command)) throw new Error(`cases[${i}].command must be a non-empty string or array of strings`);
    if (!c.command && !s.command) throw new Error(`cases[${i}] has no command and spec has no default command`);
    posInt(c.timeout, `cases[${i}].timeout`);
    if (c.expect !== undefined && (typeof c.expect !== "object" || c.expect === null || Array.isArray(c.expect))) throw new Error(`cases[${i}].expect must be an object`);
    if (c.expect) {
      posInt(c.expect.maxDurationMs, `cases[${i}].expect.maxDurationMs`);
      const known = ["decision", "exitCode", "blocked", "stdout", "stderr", "reason", "validJson", "maxDurationMs"];
      for (const k of Object.keys(c.expect)) if (!known.includes(k)) throw new Error(`cases[${i}].expect.${k} is not a known expectation (${known.join(", ")})`);
    }
  });
}

export function matchText(actual: string, pattern: string): boolean {
  const m = /^\/(.*)\/([a-z]*)$/s.exec(pattern);
  return m ? new RegExp(m[1], m[2]).test(actual) : actual.includes(pattern);
}

export function checkExpectation(r: HookResult, e: Expectation = {}): string[] {
  const f: string[] = [];
  if (e.decision !== undefined && r.decision !== e.decision) f.push(`decision: expected ${e.decision}, got ${r.decision}`);
  if (e.exitCode !== undefined && r.exitCode !== e.exitCode) f.push(`exitCode: expected ${e.exitCode}, got ${r.exitCode}`);
  if (e.blocked !== undefined && r.blocked !== e.blocked) f.push(`blocked: expected ${e.blocked}, got ${r.blocked}`);
  if (e.stdout !== undefined && !matchText(r.stdout, e.stdout)) f.push(`stdout does not match ${e.stdout}`);
  if (e.stderr !== undefined && !matchText(r.stderr, e.stderr)) f.push(`stderr does not match ${e.stderr}`);
  if (e.reason !== undefined && !matchText(r.reason ?? "", e.reason)) f.push(`reason "${r.reason ?? ""}" does not match ${e.reason}`);
  if (e.validJson !== undefined) {
    const ok = r.output.kind === "json" && !!r.validation?.valid;
    if (ok !== e.validJson) f.push(`validJson: expected ${e.validJson}, got ${ok}${r.validation?.errors.length ? " (" + r.validation.errors.join("; ") + ")" : ""}`);
  }
  if (e.maxDurationMs !== undefined && r.durationMs > e.maxDurationMs) f.push(`duration ${r.durationMs}ms > ${e.maxDurationMs}ms`);
  if (r.timedOut && e.decision !== "timeout") f.push("hook timed out");
  if (r.spawnError && e.decision !== "spawn-error") f.push(`spawn error: ${r.spawnError}`);
  return f;
}

export async function runSuite(spec: Spec, baseDir = process.cwd(), onCase?: (c: CaseResult) => void): Promise<SuiteResult> {
  validateSpec(spec);
  const cases: CaseResult[] = [];
  for (const [i, c] of spec.cases.entries()) {
    const event = normalizeEvent(c.event);
    const payload = buildPayload(event, { tool: c.tool, input: c.input, overrides: c.payload, cwd: baseDir });
    const result = await runHook((c.command ?? spec.command)!, payload, {
      cwd: baseDir, timeoutMs: c.timeout ?? spec.timeout ?? 10_000, env: { ...spec.env, ...c.env },
    });
    const failures = checkExpectation(result, c.expect);
    const cr = { name: c.name ?? `#${i + 1} ${event}${c.tool ? ":" + c.tool : ""}`, pass: failures.length === 0, failures, result };
    cases.push(cr); onCase?.(cr);
  }
  const passed = cases.filter((c) => c.pass).length;
  return { passed, failed: cases.length - passed, cases };
}
