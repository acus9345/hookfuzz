import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildPayload, runHook, runSuite, loadSpec, fuzzHook, scanSettings } from "../src/index.js";
import { EX, HOOKS, PY, hasBash, cli } from "./helpers.js";

const node = (f: string) => [process.execPath, join(HOOKS, f)];

test("node hook: deny / ask / allow / passthrough (exec form)", async () => {
  const deny = await runHook(node("guard.mjs"), buildPayload("PreToolUse", { tool: "Write", input: { file_path: "/x/.env" } }));
  assert.equal(deny.decision, "deny"); assert.ok(deny.blocked); assert.ok(deny.validation?.valid);
  assert.equal((await runHook(node("guard.mjs"), buildPayload("PreToolUse", { input: { command: "git push" } }))).decision, "ask");
  assert.equal((await runHook(node("guard.mjs"), buildPayload("PreToolUse", { input: { command: "ls" } }))).decision, "allow");
  assert.equal((await runHook(node("guard.mjs"), buildPayload("PreToolUse", { input: { command: "make" } }))).decision, "none");
});

test("shell form with quoted path containing spaces", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hook shot "));
  const f = join(dir, "my hook.mjs");
  writeFileSync(f, 'process.stdin.resume();process.stdin.on("end",()=>{console.error("from hook");process.exit(2)})');
  const r = await runHook(`"${process.execPath}" "${f}"`, buildPayload("PreToolUse"));
  assert.equal(r.exitCode, 2); assert.equal(r.decision, "block"); assert.equal(r.reason, "from hook");
  const r2 = await runHook([process.execPath, f], buildPayload("PreToolUse"), { shell: true });
  assert.equal(r2.exitCode, 2);
});

test("python hook blocks secrets and adds context", { skip: !PY && "python not found" }, async () => {
  const cmd = [PY!, join(HOOKS, "prompt_filter.py")];
  const b = await runHook(cmd, buildPayload("UserPromptSubmit", { input: { prompt: "key AKIAABCDEFGHIJKLMNOP" } }));
  assert.equal(b.decision, "block"); assert.ok(b.blocked);
  const ok = await runHook(cmd, buildPayload("UserPromptSubmit", { input: { prompt: "hello" } }));
  assert.equal(ok.decision, "none"); assert.ok(ok.validation?.valid); assert.match(ok.stdout, /pytest/);
});

test("bash hook blocks rm -rf via exit 2", { skip: !hasBash && "bash not available" }, async () => {
  const r = await runHook(`bash "${join(HOOKS, "block-rm.sh")}"`, buildPayload("PreToolUse", { input: { command: "rm -rf /" } }));
  assert.equal(r.exitCode, 2); assert.equal(r.decision, "block"); assert.match(r.stderr, /Blocked/);
  const ok = await runHook(`bash "${join(HOOKS, "block-rm.sh")}"`, buildPayload("PreToolUse", { input: { command: "ls" } }));
  assert.equal(ok.decision, "none");
});

test("timeout kills a hanging hook (and its children)", async () => {
  const t0 = Date.now();
  const r = await runHook([process.execPath, "-e", "setInterval(()=>{},1000)"], buildPayload("Stop"), { timeoutMs: 500 });
  assert.ok(r.timedOut); assert.equal(r.decision, "timeout");
  assert.ok(Date.now() - t0 < 5000);
});

test("missing executable is a spawn error / shell 'not found'", async () => {
  const r = await runHook(["definitely-not-real-xyz"], buildPayload("Stop"));
  assert.equal(r.decision, "spawn-error");
  const s = await runHook("definitely-not-real-xyz", buildPayload("Stop"));
  assert.notEqual(s.exitCode, 0); assert.equal(s.decision, "error");
});

test("runSuite on the example spec passes", { skip: !PY && "python not found" }, async () => {
  const { spec, baseDir } = loadSpec(join(EX, "hookfuzz.yml"));
  for (const c of spec.cases) if (Array.isArray(c.command) && c.command[0] === "python3") c.command[0] = PY!;
  const res = await runSuite(spec, baseDir);
  assert.equal(res.failed, 0, JSON.stringify(res.cases.filter((c) => !c.pass).map((c) => c.failures)));
  assert.equal(res.passed, 7);
});

test("runSuite reports failures", async () => {
  const res = await runSuite({ command: [process.execPath, join(HOOKS, "guard.mjs")], cases: [{ event: "PreToolUse", input: { command: "ls" }, expect: { decision: "deny" } }] }, EX);
  assert.equal(res.failed, 1); assert.match(res.cases[0].failures[0], /expected deny, got allow/);
});

test("fuzz: robust hook has no problems, buggy hook is flagged", async () => {
  const good = await fuzzHook(node("guard.mjs"), { timeoutMs: 5000 });
  assert.equal(good.problems, 0, JSON.stringify(good.findings.filter((f) => f.verdict !== "ok").map((f) => [f.case, f.detail])));
  const bad = await fuzzHook(node("buggy.mjs"), { timeoutMs: 1500 });
  const v = new Set(bad.findings.map((f) => f.verdict));
  for (const k of ["crash", "hang", "invalid-output"]) assert.ok(v.has(k as any), k);
});

test("scan lists hooks and flags missing commands", () => {
  const res = scanSettings({ projectDir: join(EX, "project"), home: mkdtempSync(join(tmpdir(), "home-")) });
  assert.equal(res.hooks.length, 5);
  const by = Object.fromEntries(res.hooks.map((h) => [h.event + (h.args ? ":args" : ""), h]));
  assert.equal(by["Stop"].exists, false);
  assert.equal(by["Notification"].exists, false);
  assert.equal(by["PreToolUse:args"].exists, true);
  if (hasBash) assert.equal(by["PreToolUse"].exists, true);
});

test("scan tolerates broken JSON and reads ~/.claude", () => {
  const home = mkdtempSync(join(tmpdir(), "home-"));
  mkdirSync(join(home, ".claude"));
  writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "node -v" }, { type: "prompt", prompt: "x" }] }] } }));
  const proj = mkdtempSync(join(tmpdir(), "proj-"));
  mkdirSync(join(proj, ".claude"));
  writeFileSync(join(proj, ".claude", "settings.json"), "{ not json");
  const res = scanSettings({ projectDir: proj, home });
  assert.equal(res.hooks.length, 2);
  assert.equal(res.hooks[0].exists, true);
  assert.ok(res.files.find((f) => f.error));
});

test("CLI end to end: run, payload, test, fuzz, scan, help", () => {
  const run = cli(["run", "PreToolUse", "--tool", "Write", "--input", '{"file_path":"/a/.env"}', "--json", "--", process.execPath, join(HOOKS, "guard.mjs")]);
  assert.equal(run.code, 0, run.err);
  const j = JSON.parse(run.out);
  assert.equal(j.decision, "deny"); assert.equal(j.payload.tool_name, "Write");
  const p = JSON.parse(cli(["payload", "stop"]).out);
  assert.equal(p.hook_event_name, "Stop");
  const t = cli(["test", "hookfuzz.yml"], EX);
  if (PY === "python3") { assert.equal(t.code, 0, t.out); assert.match(t.out, /7 passed/); }
  const f = cli(["fuzz", "--timeout", "1500", "--", process.execPath, join(HOOKS, "buggy.mjs")]);
  assert.equal(f.code, 1); assert.match(f.out, /CRASH/); assert.match(f.out, /HANG/);
  const s = cli(["scan"], join(EX, "project"));
  assert.equal(s.code, 1); assert.match(s.out, /MISSING/);
  assert.equal(cli(["--help"]).code, 0);
  assert.equal(cli(["bogus"]).code, 2);
  assert.match(cli(["--version"]).out, /^\d+\.\d+\.\d+/);
});

test("CLI test exits nonzero on failure", () => {
  const dir = mkdtempSync(join(tmpdir(), "spec-"));
  writeFileSync(join(dir, "hookfuzz.json"), JSON.stringify({ command: [process.execPath, "-e", "process.exit(0)"], cases: [{ event: "Stop", expect: { exitCode: 2 } }] }));
  const r = cli(["test"], dir);
  assert.equal(r.code, 1); assert.match(r.out, /1 failed/);
});
