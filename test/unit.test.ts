import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildPayload, deepMerge, parseStdout, validateOutput, interpret, quotePosixArg, quoteWindowsArg,
  tokenize, matchText, checkExpectation, validateSpec, fuzzCases, classify, normalizeEvent, EVENTS,
} from "../src/index.js";
import { errorLine } from "../src/fuzz.js";

const raw = (o: Partial<Parameters<typeof interpret>[0]>) =>
  interpret({ event: "PreToolUse", command: "x", exitCode: 0, signal: null, stdout: "", stderr: "", durationMs: 1, timedOut: false, ...o });

test("buildPayload: PreToolUse has common + tool fields", () => {
  const p = buildPayload("PreToolUse", { tool: "Bash", input: { command: "rm -rf /" }, cwd: "/repo" });
  for (const k of ["session_id", "transcript_path", "cwd", "permission_mode", "hook_event_name", "tool_name", "tool_input", "tool_use_id"]) assert.ok(k in p, k);
  assert.equal(p.cwd, "/repo");
  assert.deepEqual(p.tool_input, { command: "rm -rf /" });
});
test("buildPayload: event-specific fields", () => {
  assert.equal(buildPayload("UserPromptSubmit", { input: { prompt: "hi" } }).prompt, "hi");
  assert.equal(buildPayload("Stop").stop_hook_active, false);
  assert.equal(buildPayload("SessionStart").source, "startup");
  assert.equal(buildPayload("Notification").notification_type, "permission_prompt");
  assert.ok("tool_response" in buildPayload("PostToolUse"));
  assert.equal(buildPayload("PreCompact").trigger, "manual");
});
test("buildPayload: overrides deep-merge and null deletes", () => {
  const p = buildPayload("PreToolUse", { overrides: { tool_input: { extra: 1 }, session_id: null, permission_mode: "plan" } });
  assert.equal((p.tool_input as any).extra, 1);
  assert.equal((p.tool_input as any).command, "npm test");
  assert.ok(!("session_id" in p));
  assert.equal(p.permission_mode, "plan");
  assert.deepEqual(deepMerge({ a: [1] }, { a: [2] }), { a: [2] });
});
test("parseStdout follows the Claude Code JSON detection rules", () => {
  assert.equal(parseStdout("").kind, "empty");
  assert.equal(parseStdout("  \n").kind, "empty");
  assert.equal(parseStdout("hello").kind, "text");
  assert.equal(parseStdout("[1,2]").kind, "text");
  assert.equal(parseStdout('"str"').kind, "text");
  assert.equal(parseStdout('{"a":1}\n').kind, "json");
  assert.equal(parseStdout("{oops}").kind, "invalid-json");
});
test("validateOutput catches schema errors", () => {
  assert.ok(validateOutput("PreToolUse", { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny" } }).valid);
  assert.ok(!validateOutput("PreToolUse", { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "maybe" } }).valid);
  assert.ok(!validateOutput("PreToolUse", { hookSpecificOutput: { permissionDecision: "deny" } }).valid);
  assert.ok(!validateOutput("Stop", { hookSpecificOutput: { hookEventName: "PreToolUse" } }).valid);
  assert.ok(!validateOutput("Stop", { continue: "no" }).valid);
  assert.ok(!validateOutput("Stop", { decision: "allow" }).valid);
  assert.ok(validateOutput("Stop", { decision: "block", reason: "x" }).valid);
  assert.ok(!validateOutput("PermissionRequest", { hookSpecificOutput: { hookEventName: "PermissionRequest", decision: { behavior: "x" } } }).valid);
  const w = validateOutput("Stop", { weird: 1 });
  assert.ok(w.valid); assert.match(w.warnings[0], /unknown/);
  assert.match(validateOutput("PreToolUse", { decision: "approve" }).warnings[0], /deprecated/);
});
test("interpret: exit codes and JSON decisions", () => {
  assert.equal(raw({ exitCode: 0 }).decision, "none");
  const b = raw({ exitCode: 2, stderr: "nope\n" });
  assert.deepEqual([b.decision, b.blocked, b.reason], ["block", true, "nope"]);
  assert.equal(raw({ exitCode: 2, event: "PostToolUse" }).blocked, false);
  assert.equal(raw({ exitCode: 1, stderr: "boom\nmore" }).reason, "boom");
  assert.equal(raw({ exitCode: 1 }).decision, "error");
  const deny = raw({ stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "r" } }) });
  assert.deepEqual([deny.decision, deny.blocked, deny.reason], ["deny", true, "r"]);
  // valid JSON wins over a non 0/2 exit code
  assert.equal(raw({ exitCode: 1, stdout: '{"decision":"block","reason":"x"}', event: "Stop" }).decision, "block");
  assert.equal(raw({ stdout: '{"continue":false,"stopReason":"s"}' }).decision, "stop");
  assert.equal(raw({ stdout: "{bad" + "}" }).decision, "error");
  assert.equal(raw({ timedOut: true, exitCode: null }).decision, "timeout");
  assert.equal(raw({ spawnError: "ENOENT" }).decision, "spawn-error");
  assert.equal(raw({ event: "PermissionRequest", stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PermissionRequest", decision: { behavior: "allow" } } }) }).decision, "allow");
});
test("argument quoting", () => {
  assert.equal(quotePosixArg("abc"), "abc");
  assert.equal(quotePosixArg("it's here"), "'it'\\''s here'");
  assert.equal(quotePosixArg(""), "''");
  assert.equal(quoteWindowsArg("C:\\Program Files\\x"), '"C:\\Program Files\\x"');
  assert.equal(quoteWindowsArg('say "hi"'), '"say \\"hi\\""');
  assert.equal(quoteWindowsArg("plain"), "plain");
});
test("tokenize handles quotes", () => {
  assert.deepEqual(tokenize(`bash "\${X}/a b.sh" --flag 'c d'`), ["bash", "${X}/a b.sh", "--flag", "c d"]);
  assert.deepEqual(tokenize(`  node  x.js `), ["node", "x.js"]);
  assert.deepEqual(tokenize(`echo ""`), ["echo", ""]);
});
test("matchText substring and regex", () => {
  assert.ok(matchText("Hello World", "World"));
  assert.ok(matchText("Hello World", "/^hello/i"));
  assert.ok(!matchText("Hello", "/^world/"));
});
test("checkExpectation reports each mismatch", () => {
  const r = raw({ exitCode: 2, stderr: "blocked" });
  assert.deepEqual(checkExpectation(r, { decision: "block", exitCode: 2, stderr: "blocked", blocked: true }), []);
  const f = checkExpectation(r, { decision: "allow", exitCode: 0, validJson: true, reason: "/zzz/" });
  assert.equal(f.length, 4);
});
test("validateSpec rejects bad specs", () => {
  assert.throws(() => validateSpec({}), /cases/);
  assert.throws(() => validateSpec({ cases: [{}] }), /event/);
  assert.throws(() => validateSpec({ cases: [{ event: "Stop" }] }), /command/);
  validateSpec({ command: "x", cases: [{ event: "Stop" }] });
});
test("fuzzCases + classify", () => {
  const cs = fuzzCases("PreToolUse");
  assert.ok(cs.length >= 15);
  assert.equal(new Set(cs.map((c) => c.name)).size, cs.length);
  assert.ok(cs.some((c) => c.rawStdin === ""));
  assert.equal(classify(raw({ exitCode: 1, stderr: "TypeError: x is undefined" })).verdict, "crash");
  assert.equal(classify(raw({ exitCode: 2 })).verdict, "ok");
  assert.equal(classify(raw({ timedOut: true })).verdict, "hang");
  assert.equal(classify(raw({ stdout: "{x}" })).verdict, "invalid-output");
  assert.equal(errorLine("at foo\nTypeError: bad thing\n\nNode.js v24"), "TypeError: bad thing");
});
test("events", () => {
  assert.equal(normalizeEvent("pretooluse"), "PreToolUse");
  for (const e of ["PreToolUse", "PostToolUse", "UserPromptSubmit", "Notification", "Stop", "SubagentStop", "SessionStart", "PreCompact"]) assert.ok((EVENTS as readonly string[]).includes(e));
});
