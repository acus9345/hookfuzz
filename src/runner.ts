import { spawn, spawnSync } from "node:child_process";
import { statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { performance } from "node:perf_hooks";
import { BLOCKING_EVENTS } from "./events.js";
import { parseStdout, validateOutput, type ParsedStdout, type ValidationResult } from "./schema.js";

export type Decision = "allow" | "deny" | "ask" | "defer" | "block" | "stop" | "none" | "error" | "timeout" | "spawn-error";

export interface RunOptions {
  timeoutMs?: number;
  cwd?: string;
  env?: Record<string, string>;
  /** Event used to interpret the result; defaults to the payload's hook_event_name. */
  event?: string;
  /** Force shell form (string through a shell) even when argv has several entries. */
  shell?: boolean;
  /** Raw stdin override (used by the fuzzer for malformed JSON). */
  rawStdin?: string;
  /** Max characters kept per stream (stdout, stderr); the rest is drained and dropped. Default 16 MiB. */
  maxOutput?: number;
}

export interface HookResult {
  event: string;
  command: string | string[];
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  spawnError?: string;
  output: ParsedStdout;
  validation?: ValidationResult;
  decision: Decision;
  reason?: string;
  /** True when Claude Code would block / prevent the action. */
  blocked: boolean;
  /** Set when stdout and/or stderr went over `maxOutput` and were cut. */
  truncated?: { stdout: boolean; stderr: boolean };
}

/** Quote a single argument for cmd.exe. */
export function quoteWindowsArg(a: string): string {
  if (a !== "" && !/[\s"&|<>^%()!]/.test(a)) return a;
  return '"' + a.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1") + '"';
}
// `:` is included so `%VAR:a=b%` / `%VAR:~0,5%` can't expand: cmd's %-expansion runs before carets
// are removed, and an escaped `^:` ends the variable name at a name that doesn't exist.
const CMD_META = /([()\][%!^"`<>&|;,: *?])/g;
/**
 * Quote one argument for a command line that cmd.exe will parse (`shell: true` on Windows).
 * After normal quoting every cmd metacharacter, `%` included, is caret-escaped, so cmd never
 * sees a quoted region and cannot expand `%VAR%`. `.cmd`/`.bat` shims parse their arguments a
 * second time, so for them (`shim = true`) the escaping is applied twice.
 */
export function quoteCmdArg(a: string, shim = false): string {
  let q = a.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, "$1$1");
  q = `"${q}"`.replace(CMD_META, "^$1");
  return shim ? q.replace(CMD_META, "^$1") : q;
}
/** {@link quoteCmdArg} for a `.cmd`/`.bat` shim (double-escaped). */
export function quoteCmdShimArg(a: string): string {
  return quoteCmdArg(a, true);
}
/** Escape a .cmd/.bat path for cmd.exe (metacharacters caret-escaped, no quotes). A leading drive colon (`C:`) is kept. */
export function escapeCmdShimPath(p: string): string {
  const drive = /^[a-zA-Z]:/.exec(p)?.[0] ?? "";
  return drive + p.slice(drive.length).replace(CMD_META, "^$1");
}

const isBatch = (p: string) => /\.(cmd|bat)$/i.test(p);
const envGet = (env: Record<string, string | undefined>, k: string) => env[Object.keys(env).find((x) => x.toLowerCase() === k.toLowerCase()) ?? k];
const isFile = (p: string) => { try { return statSync(p).isFile(); } catch { return false; } };
/**
 * `{ ...base, ...over }`, except that on Windows, where variable names are case-insensitive, a key in
 * `over` also replaces any `base` key that differs only in case (an override `PATH` replaces `Path`).
 */
function mergeEnv(base: Record<string, string | undefined>, over: Record<string, string | undefined> = {}, win = process.platform === "win32"): Record<string, string | undefined> {
  const out = { ...base };
  if (win) for (const k of Object.keys(over)) for (const b of Object.keys(out)) if (b !== k && b.toLowerCase() === k.toLowerCase()) delete out[b];
  return Object.assign(out, over);
}

/**
 * Resolve a Windows command name the way cmd.exe does (current directory first, then PATH, each
 * with the PATHEXT extensions) and return the file it finds, or undefined. Used to tell whether a
 * bare name like `npx` is really a `.cmd`/`.bat` shim that re-parses its arguments with `%*`.
 * The files are on this machine, so paths are joined natively; only the list syntax is Windows'.
 */
export function resolveWindowsCommand(name: string, env: Record<string, string | undefined> = process.env, cwd = process.cwd()): string | undefined {
  if (!name) return undefined;
  const exts = (envGet(env, "PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").split(";").map((e) => e.trim()).filter(Boolean);
  const hasExt = exts.some((e) => name.toLowerCase().endsWith(e.toLowerCase()));
  const candidates = (base: string) => (hasExt ? [base] : exts.flatMap((e) => [base + e, base + e.toLowerCase()]));
  const hasDir = /[\\/]/.test(name) || /^[a-zA-Z]:/.test(name);
  const dirs = hasDir ? [isAbsolute(name) || /^[a-zA-Z]:/.test(name) ? name : join(cwd, name)]
    : [cwd, ...(envGet(env, "PATH") ?? "").split(";").map((d) => d.trim().replace(/^"(.*)"$/, "$1")).filter(Boolean)].map((d) => join(d, name));
  for (const b of dirs) for (const c of candidates(b)) if (isFile(c)) return c;
  return undefined;
}

export interface SpawnSpec { file: string; args: string[]; shell: boolean }
/**
 * Work out what to spawn for a hook command (exported for tests; `platform` lets POSIX tests
 * build the Windows command line). A bare name that resolves through PATHEXT to a `.cmd`/`.bat`
 * shim is double-escaped, the same as an explicit `x.cmd`, both with and without `--shell`.
 */
export function spawnSpec(command: string | string[], opts: Pick<RunOptions, "shell" | "env" | "cwd"> = {}, platform: NodeJS.Platform = process.platform): SpawnSpec {
  const isWin = platform === "win32";
  const env = mergeEnv(process.env, opts.env, isWin);
  const cwd = opts.cwd ?? process.cwd();
  const batch = (c0: string) => isBatch(c0) || isBatch(resolveWindowsCommand(c0, env, cwd) ?? "");
  if (typeof command === "string") return { file: command, args: [], shell: true };
  const [c0 = "", ...rest] = command;
  if (opts.shell) {
    if (!isWin) return { file: command.map(quotePosixArg).join(" "), args: [], shell: true };
    // exec form forced through cmd.exe (--shell): escape like the shim path so %VAR% stays literal
    const shim = batch(c0);
    return { file: [escapeCmdShimPath(c0), ...rest.map((x) => quoteCmdArg(x, shim))].join(" "), args: [], shell: true };
  }
  if (isWin) {
    // .cmd/.bat shims can't be spawned without a shell on Windows; a bare `npx` is resolved to npx.cmd first
    const shimPath = isBatch(c0) ? c0 : (() => { const r = resolveWindowsCommand(c0, env, cwd); return r && isBatch(r) ? r : undefined; })();
    if (shimPath) return { file: [escapeCmdShimPath(shimPath), ...rest.map(quoteCmdShimArg)].join(" "), args: [], shell: true };
  }
  return { file: c0, args: rest, shell: false };
}
/** Quote a single argument for POSIX sh. */
export function quotePosixArg(a: string): string {
  if (a !== "" && /^[\w@%+=:,./-]+$/.test(a)) return a;
  return "'" + a.replace(/'/g, "'\\''") + "'";
}

/** Hook processes (process-group leaders on POSIX) that are still running. */
const ACTIVE = new Set<number>();
/**
 * Kill every hook process tree runHook started that is still running. On POSIX hooks run in their
 * own process group (so a timeout can kill grandchildren), which also means Ctrl-C in a terminal
 * does not reach them: the hookfuzz CLI calls this from its SIGINT/SIGTERM/SIGHUP handlers, and
 * library users that handle those signals should too.
 */
export function killActiveHooks(): void {
  for (const pid of ACTIVE) killTree(pid);
  ACTIVE.clear();
}

function killTree(pid: number | undefined): void {
  if (!pid) return;
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-pid, "SIGKILL");
  } catch { /* already gone */ }
}

/**
 * Run a hook command with a JSON payload on stdin.
 * `command` as a string = shell form (sh -c / cmd.exe), as an array = exec form (no shell),
 * mirroring Claude Code's `command` vs `command`+`args`.
 */
export function runHook(command: string | string[], payload: Record<string, unknown>, opts: RunOptions = {}): Promise<HookResult> {
  const event = opts.event ?? String(payload.hook_event_name ?? "");
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const isWin = process.platform === "win32";
  const { file, args, shell: useShell } = spawnSpec(command, opts);
  const maxOutput = opts.maxOutput ?? 16 * 1024 * 1024;
  const stdin = opts.rawStdin ?? JSON.stringify(payload);
  return new Promise((resolve) => {
    const t0 = performance.now();
    let stdout = ""; let stderr = ""; let timedOut = false; let spawnError: string | undefined; let done = false;
    const cut = { stdout: false, stderr: false };
    const child = spawn(file, args, {
      shell: useShell, cwd: opts.cwd, env: mergeEnv({ ...process.env, CLAUDE_PROJECT_DIR: opts.cwd ?? process.cwd() }, opts.env) as NodeJS.ProcessEnv,
      detached: !isWin, windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
    });
    if (child.pid) ACTIVE.add(child.pid);
    const timer = setTimeout(() => { timedOut = true; killTree(child.pid); }, timeoutMs);
    // keep reading past the cap (so the hook never blocks on a full pipe) but drop the excess
    child.stdout.setEncoding("utf8").on("data", (d: string) => { if (stdout.length + d.length <= maxOutput) stdout += d; else { stdout += d.slice(0, Math.max(0, maxOutput - stdout.length)); cut.stdout = true; } });
    child.stderr.setEncoding("utf8").on("data", (d: string) => { if (stderr.length + d.length <= maxOutput) stderr += d; else { stderr += d.slice(0, Math.max(0, maxOutput - stderr.length)); cut.stderr = true; } });
    child.stdin.on("error", () => { /* hook closed stdin early (EPIPE) */ });
    child.on("error", (e) => { spawnError = e.message; finish(null, null); });
    child.on("close", (code, sig) => finish(code, sig));
    child.stdin.end(stdin);
    function finish(code: number | null, sig: NodeJS.Signals | null) {
      if (done) return; done = true; clearTimeout(timer);
      if (child.pid) ACTIVE.delete(child.pid);
      const durationMs = Math.round((performance.now() - t0) * 10) / 10;
      const truncated = cut.stdout || cut.stderr ? { ...cut } : undefined;
      resolve(interpret({ event, command, exitCode: code, signal: sig, stdout, stderr, durationMs, timedOut, spawnError, truncated }));
    }
  });
}

type Raw = Pick<HookResult, "event" | "command" | "exitCode" | "signal" | "stdout" | "stderr" | "durationMs" | "timedOut" | "spawnError" | "truncated">;

/** Turn raw process results into a decision, following the reference's exit-code/stdout table. */
export function interpret(r: Raw): HookResult {
  const output = parseStdout(r.stdout);
  const base = { ...r, output } as HookResult;
  if (r.spawnError) return { ...base, decision: "spawn-error", reason: r.spawnError, blocked: false };
  if (r.timedOut) return { ...base, decision: "timeout", reason: "hook exceeded timeout", blocked: false };
  if (r.truncated?.stdout) return { ...base, decision: "error", reason: `stdout exceeded ${r.stdout.length} characters and was cut; hookfuzz cannot judge it`, blocked: false };
  // WorktreeCreate / WorktreeRemove: any non-zero exit fails the operation, whatever stdout says
  if ((r.event === "WorktreeCreate" || r.event === "WorktreeRemove") && r.exitCode !== 0) {
    const reason = r.stderr.split(/\r?\n/)[0] || `exit code ${r.exitCode ?? r.signal}`;
    return { ...base, decision: "block", reason, blocked: true };
  }
  const canBlock = BLOCKING_EVENTS.has(r.event);
  if (output.kind === "json" && output.json) base.validation = validateOutput(r.event, output.json);
  const json = output.kind === "json" && base.validation?.valid ? output.json! : undefined;
  if (r.exitCode === 2) {
    const reason = (json && jsonReason(json)) || r.stderr.trim();
    return { ...base, decision: canBlock ? "block" : "none", reason, blocked: canBlock };
  }
  if (output.kind === "invalid-json" || (output.kind === "json" && !base.validation?.valid))
    return { ...base, decision: "error", reason: output.error ?? base.validation?.errors.join("; "), blocked: false };
  if (json) {
    // valid JSON: decides regardless of exit code (non 0/2 codes are ignored), except that
    // Elicitation/ElicitationResult only apply hookSpecificOutput on exit 0
    const elicit = r.event === "Elicitation" || r.event === "ElicitationResult";
    const d = jsonDecision(r.event, elicit && r.exitCode !== 0 ? { ...json, hookSpecificOutput: undefined } : json);
    return { ...base, ...d };
  }
  if (r.exitCode === 0) return { ...base, decision: "none", blocked: false };
  return { ...base, decision: "error", reason: r.stderr.split(/\r?\n/)[0] || `exit code ${r.exitCode ?? r.signal}`, blocked: false };
}

function jsonReason(j: Record<string, unknown>): string | undefined {
  const h = (j.hookSpecificOutput ?? {}) as Record<string, any>;
  return h.permissionDecisionReason ?? h.decision?.message ?? (j.reason as string) ?? (j.stopReason as string);
}

function jsonDecision(event: string, j: Record<string, unknown>): Pick<HookResult, "decision" | "reason" | "blocked"> {
  const reason = jsonReason(j);
  if (j.continue === false) return { decision: "stop", reason, blocked: true };
  const h = (j.hookSpecificOutput ?? {}) as Record<string, any>;
  if (event === "PreToolUse" && h.permissionDecision) return { decision: h.permissionDecision, reason, blocked: h.permissionDecision === "deny" };
  if (event === "PermissionRequest" && h.decision?.behavior) return { decision: h.decision.behavior, reason, blocked: h.decision.behavior === "deny" };
  if ((event === "Elicitation" || event === "ElicitationResult") && typeof h.action === "string") {
    if (h.action === "accept") return { decision: "allow", reason, blocked: false };
    if (h.action === "decline" || h.action === "cancel") return { decision: "block", reason: reason ?? h.action, blocked: true };
  }
  if (j.decision === "block") return { decision: "block", reason, blocked: true };
  if (event === "PreToolUse" && j.decision === "approve") return { decision: "allow", reason, blocked: false };
  return { decision: "none", reason, blocked: false };
}
