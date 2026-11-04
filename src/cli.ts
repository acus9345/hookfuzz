#!/usr/bin/env node
import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { EVENTS, normalizeEvent } from "./events.js";
import { fuzzHook } from "./fuzz.js";
import { bypassHook } from "./bypass.js";
import { buildPayload } from "./payload.js";
import { killActiveHooks, runHook, type HookResult } from "./runner.js";
import { scanSettings } from "./scan.js";
import { loadSpec, runSuite } from "./spec.js";

// hooks run in their own process group on POSIX, so Ctrl-C does not reach them: kill them ourselves
for (const [sig, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]] as const) {
  process.on(sig, () => { killActiveHooks(); process.exit(code); });
}
process.stdout.on("error", (e: NodeJS.ErrnoException) => { if (e.code === "EPIPE") process.exit(process.exitCode ?? 0); throw e; });
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: number) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = c(31), green = c(32), yellow = c(33), dim = c(2), bold = c(1);

const HELP = `hookfuzz - test harness & fuzzer for Claude Code hooks

Usage:
  hookfuzz run <event> [--tool T] [--input JSON|@file] [--payload JSON|@file] [--timeout ms] [--json] [--shell] -- <hook command>
  hookfuzz test [spec] [--json]            spec defaults to hookfuzz.yml|hookfuzz.yaml|hookfuzz.json
  hookfuzz fuzz [--event E] [--tool T] [--timeout ms] [--json] [--shell] -- <hook command>
  hookfuzz bypass --command "rm -rf /" [--tool T] [--timeout ms] [--json] [--shell] -- <hook command>
                                           try equivalent variants of a blocked command; report the ones let through
  hookfuzz scan [--project dir] [--json]   list hooks in ~/.claude and ./.claude settings
  hookfuzz payload <event> [--tool T] [--input JSON] [--payload JSON]   print the payload that would be sent
  hookfuzz events                          list known hook events

Options: --timeout takes a positive integer in ms; --shell runs a multi-argument hook command
through the shell anyway (sh -c / cmd.exe, with arguments quoted and %VAR% escaped).
Exit codes: 0 ok, 1 failures found (failed cases, crashes and other hook errors, timeouts,
invalid output, bypasses, missing hooks), 2 usage error. For run, exit 1 means the decision was
error, timeout or spawn-error, or stdout failed validation.

Hook command: a single argument after -- is run through the shell (like Claude Code's
"command"); several arguments are spawned directly with no shell (like "command" + "args").`;

/** Default spec files, in order. */
const SPEC_FILES = ["hookfuzz.yml", "hookfuzz.yaml", "hookfuzz.json"];

interface Args { _: string[]; rest: string[]; flags: Record<string, string | boolean> }
export function parseArgs(argv: string[]): Args {
  const a: Args = { _: [], rest: [], flags: {} };
  const dd = argv.indexOf("--");
  const head = dd >= 0 ? argv.slice(0, dd) : argv;
  if (dd >= 0) a.rest = argv.slice(dd + 1);
  for (let i = 0; i < head.length; i++) {
    const t = head[i];
    if (t.startsWith("--")) {
      const [k, v] = t.slice(2).split(/=(.*)/s, 2);
      if (v !== undefined) a.flags[k] = v;
      else if (["json", "help", "version", "shell"].includes(k)) a.flags[k] = true;
      else a.flags[k] = head[++i] ?? "";
    } else if (t === "-h") a.flags.help = true;
    else a._.push(t);
  }
  return a;
}

function jsonFlag(v: string | boolean | undefined, name: string): Record<string, unknown> | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v === "") throw new UsageError(`--${name} needs a JSON object or @file`);
  let txt = v;
  if (v.startsWith("@")) {
    try { txt = readFileSync(v.slice(1), "utf8"); } catch (e) { throw new UsageError(`--${name}: cannot read ${v.slice(1)} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`); }
  }
  let parsed: unknown;
  try { parsed = JSON.parse(txt); } catch (e) { throw new UsageError(`--${name} is not valid JSON: ${(e as Error).message}`); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new UsageError(`--${name} must be a JSON object`);
  return parsed as Record<string, unknown>;
}
function hookCommand(a: Args): string | string[] {
  if (!a.rest.length || a.rest[0] === "") throw new UsageError("missing hook command after --  (e.g. hookfuzz run PreToolUse -- node hook.mjs)");
  return a.rest.length === 1 ? a.rest[0] : a.rest;
}
/** Thrown for bad invocations; the CLI prints it with a usage hint and exits 2. */
export class UsageError extends Error {}

/** Parse a positive integer flag (e.g. --timeout ms); absent means `d`. */
export function intFlag(a: Args, name: string, d: number): number {
  const v = a.flags[name];
  if (v === undefined) return d;
  if (typeof v !== "string" || !/^\d+$/.test(v.trim()) || Number(v) <= 0 || !Number.isSafeInteger(Number(v)))
    throw new UsageError(`--${name} must be a positive integer (milliseconds), got ${typeof v === "string" && v !== "" ? JSON.stringify(v) : "nothing"}`);
  return Number(v);
}

const FLAGS: Record<string, string[]> = {
  run: ["tool", "input", "payload", "timeout", "json", "shell"],
  payload: ["tool", "input", "payload"],
  test: ["json"],
  fuzz: ["event", "tool", "timeout", "json", "shell"],
  bypass: ["command", "tool", "timeout", "json", "shell"],
  scan: ["project", "json"],
  events: [],
};
/** Reject flags a subcommand does not know (a typo like --timout would otherwise be ignored). */
export function checkFlags(cmd: string, a: Args): void {
  const ok = FLAGS[cmd];
  if (!ok) return;
  for (const k of Object.keys(a.flags)) if (!ok.includes(k) && !["help", "version"].includes(k)) throw new UsageError(`unknown option --${k} for "${cmd}"`);
}

function printResult(r: HookResult) {
  const dc = r.blocked ? red : r.decision === "error" || r.decision === "timeout" || r.decision === "spawn-error" ? yellow : green;
  console.log(`${bold("event")}     ${r.event}`);
  console.log(`${bold("exit")}      ${r.exitCode ?? "-"}${r.signal ? ` (signal ${r.signal})` : ""}${r.timedOut ? red(" TIMED OUT") : ""}`);
  console.log(`${bold("decision")}  ${dc(r.decision)}${r.blocked ? red(" (blocks)") : ""}${r.reason ? dim(` - ${r.reason}`) : ""}`);
  console.log(`${bold("time")}      ${r.durationMs} ms`);
  const v = r.validation;
  const out = r.output.kind === "json" ? (v?.valid ? green("valid JSON") : red("JSON fails schema: " + v?.errors.join("; "))) : r.output.kind === "invalid-json" ? red("invalid JSON: " + r.output.error) : r.output.kind;
  console.log(`${bold("stdout")}    ${out}`);
  for (const w of v?.warnings ?? []) console.log(`          ${yellow("warn")} ${w}`);
  if (r.stdout.trim()) console.log(dim(indent(r.stdout.trim())));
  if (r.stderr.trim()) { console.log(bold("stderr")); console.log(dim(indent(r.stderr.trim()))); }
  if (r.spawnError) console.log(red(`spawn error: ${r.spawnError}`));
}
const indent = (s: string) => s.slice(0, 4000).split("\n").map((l) => "  │ " + l).join("\n");

async function main(argv: string[]): Promise<number> {
  const a = parseArgs(argv);
  const cmd = a._[0];
  if (a.flags.version) { console.log(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version); return 0; }
  if (!cmd || a.flags.help || cmd === "help") { (cmd || a.flags.help ? console.log : console.error)(HELP); return cmd || a.flags.help ? 0 : 2; }
  const json = !!a.flags.json;
  checkFlags(cmd, a);
  const strFlag = (k: string): string | undefined => {
    const v = a.flags[k];
    if (v === undefined) return undefined;
    if (typeof v !== "string" || v === "") throw new UsageError(`--${k} needs a value`);
    return v;
  };

  if (cmd === "events") { console.log(EVENTS.join("\n")); return 0; }

  if (cmd === "payload" || cmd === "run") {
    if (!a._[1]) throw new UsageError(`usage: hookfuzz ${cmd} <event> ...  (see hookfuzz events)`);
    const event = normalizeEvent(a._[1]);
    const payload = buildPayload(event, { tool: strFlag("tool"), input: jsonFlag(a.flags.input, "input"), overrides: jsonFlag(a.flags.payload, "payload") });
    if (cmd === "payload") { console.log(JSON.stringify(payload, null, 2)); return 0; }
    const r = await runHook(hookCommand(a), payload, { timeoutMs: intFlag(a, "timeout", 60_000), shell: !!a.flags.shell });
    if (json) console.log(JSON.stringify({ payload, ...r }, null, 2)); else printResult(r);
    // a crash (non-0/2 exit without valid JSON), invalid output, timeout or spawn error is a failure
    return ["error", "timeout", "spawn-error"].includes(r.decision) || (r.validation && !r.validation.valid) ? 1 : 0;
  }

  if (cmd === "test") {
    const file = a._[1] ?? SPEC_FILES.find((f) => existsSync(f));
    if (!file) throw new Error("no spec file found (hookfuzz.yml / hookfuzz.yaml / hookfuzz.json)");
    const { spec, baseDir } = loadSpec(resolve(file));
    const res = await runSuite(spec, baseDir, json ? undefined : (cr) => {
      console.log(`${cr.pass ? green("✓") : red("✗")} ${cr.name} ${dim(`(${cr.result.decision}, exit ${cr.result.exitCode}, ${cr.result.durationMs}ms)`)}`);
      for (const f of cr.failures) console.log(`    ${red(f)}`);
    });
    if (json) console.log(JSON.stringify(res, null, 2));
    else console.log(`\n${res.failed ? red(bold(`${res.failed} failed`)) + ", " : ""}${green(`${res.passed} passed`)}, ${res.cases.length} total`);
    return res.failed ? 1 : 0;
  }

  if (cmd === "fuzz") {
    const rep = await fuzzHook(hookCommand(a), {
      shell: !!a.flags.shell,
      event: strFlag("event") !== undefined ? normalizeEvent(strFlag("event")!) : undefined, tool: strFlag("tool"), timeoutMs: intFlag(a, "timeout", 5000),
      onCase: json ? undefined : (f) => console.log(`${f.verdict === "ok" ? green("ok  ") : red(f.verdict.toUpperCase().padEnd(4))} ${f.case.padEnd(28)} ${dim(f.detail)} ${dim(`${f.result.durationMs}ms`)}`),
    });
    if (json) console.log(JSON.stringify(rep.findings.map(({ result, ...f }) => ({ ...f, exitCode: result.exitCode, durationMs: result.durationMs })), null, 2));
    else console.log(`\n${rep.problems ? red(`${rep.problems} problem(s)`) : green("no problems")} in ${rep.total} cases`);
    return rep.problems ? 1 : 0;
  }

  if (cmd === "bypass") {
    if (typeof a.flags.command !== "string" || !a.flags.command) throw new UsageError('bypass needs --command "<a command the hook should block>"');
    const rep = await bypassHook(hookCommand(a), a.flags.command, {
      shell: !!a.flags.shell,
      tool: strFlag("tool"), timeoutMs: intFlag(a, "timeout", 5000),
      onCase: json ? undefined : (f) => console.log(`${f.bypassed ? red("BYPASS ") : green("blocked")} ${f.technique.padEnd(22)} ${dim(JSON.stringify(f.command))}`),
    });
    if (json) { console.log(JSON.stringify({ baselineBlocked: rep.baselineBlocked, bypasses: rep.bypasses, findings: rep.findings.map(({ result, ...f }) => ({ ...f, decision: result.decision, exitCode: result.exitCode })) }, null, 2)); }
    else {
      if (!rep.baselineBlocked) console.log(yellow(`warning: the hook does not block the original command (decision ${rep.baseline.decision})`));
      console.log(`\n${rep.bypasses ? red(`${rep.bypasses} bypass(es)`) : green("no bypasses")} in ${rep.total} variants`);
    }
    return rep.bypasses || !rep.baselineBlocked ? 1 : 0;
  }

  if (cmd === "scan") {
    const project = strFlag("project") ?? process.cwd();
    if (!existsSync(project) || !statSync(project).isDirectory()) throw new UsageError(`--project ${project} is not a directory`);
    const res = scanSettings({ projectDir: project });
    if (json) { console.log(JSON.stringify(res, null, 2)); return res.hooks.some((h) => h.exists === false) ? 1 : 0; }
    for (const f of res.files) console.log(`${f.found ? (f.error ? red("✗") : green("✓")) : dim("·")} ${f.path}${f.found ? "" : dim(" (not found)")}${f.error ? red(" " + f.error) : ""}`);
    if (!res.hooks.length) { console.log("\nno hooks configured"); return 0; }
    console.log("");
    for (const h of res.hooks) {
      const mark = h.exists === false ? red("MISSING") : h.exists === null ? yellow("?      ") : h.problem ? yellow("WARN   ") : green("ok     ");
      const what = h.type === "command" ? [h.command, ...(h.args ?? [])].join(" ") : `(${h.type})`;
      console.log(`${mark} ${h.event}[${h.matcher}] ${what}${h.problem ? dim("  - " + h.problem) : ""}`);
    }
    const missing = res.hooks.filter((h) => h.exists === false).length;
    console.log(`\n${res.hooks.length} hook(s), ${missing ? red(`${missing} missing`) : green("0 missing")}`);
    return missing ? 1 : 0;
  }
  throw new UsageError(`unknown command "${cmd}". Run hookfuzz --help`);
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => {
  console.error(red(`hookfuzz: ${(e as Error).message}`));
  if (e instanceof UsageError) console.error(dim("run hookfuzz --help for usage"));
  process.exitCode = 2;
});
