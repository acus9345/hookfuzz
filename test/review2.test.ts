import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildPayload, quoteCmdArg, quoteCmdShimArg, runHook, validateSpec } from "../src/index.js";
import { ROOT, cli, isWin } from "./helpers.js";

// (1) README scan sample is a real run.
test("README scan sample matches a real scan of examples/project", () => {
  // a Windows checkout may have CRLF line endings
  const readme = readFileSync(join(ROOT, "README.md"), "utf8").replace(/\r\n/g, "\n");
  const block = /\$ cd examples\/project && hookfuzz scan\n([\s\S]*?)```/.exec(readme)![1];
  // an empty home, so the user's own ~/.claude hooks do not show up
  const home = mkdtempSync(join(tmpdir(), "home-"));
  const r = cli(["scan"], join(ROOT, "examples", "project"), { HOME: home, USERPROFILE: home });
  const norm = (s: string) => s.split("\n").filter((l) => /^(ok|MISSING|WARN|\?)\s/.test(l) || /hook\(s\)/.test(l))
    .map((l) => l.replace(/ {2}- .*$/, "").replace(/\s+$/, ""));
  // python3 may legitimately be missing on a test machine; compare everything else
  const drop = (xs: string[]) => xs.filter((l) => !l.includes("prompt_filter.py") && !/hook\(s\)/.test(l));
  assert.deepEqual(drop(norm(r.out)), drop(norm(block)));
  assert.match(block, /5 hook\(s\), 2 missing/);
});

// (2) package metadata points at the real repo; README has no stale/relative links.
test("package metadata points at the hookfuzz repo and README has no stale links", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.equal(pkg.repository?.url, "git+https://github.com/acus9345/hookfuzz.git");
  assert.equal(pkg.homepage, "https://github.com/acus9345/hookfuzz#readme");
  assert.equal(pkg.bugs?.url, "https://github.com/acus9345/hookfuzz/issues");
  const readme = readFileSync(join(ROOT, "README.md"), "utf8");
  assert.doesNotMatch(readme, /github\.com\/acus9345\/claude-hookshot/);
  // relative links break on npmjs.com without a repository field
  assert.doesNotMatch(readme, /\]\((?!https?:\/\/|#)[^)]+\)/);
});

// (3) --shell exec form escapes %VAR% on Windows.
test("quoteCmdArg caret-escapes %VAR% once (exe) or twice (shim)", () => {
  assert.equal(quoteCmdArg("%PATH%"), '^"^%PATH^%^"');
  assert.equal(quoteCmdArg("%PATH%", true), quoteCmdShimArg("%PATH%"));
  assert.doesNotMatch(quoteCmdArg("a%b%c&d").replace(/\^./g, ""), /[%&"]/);
});

test("--shell exec form keeps %VAR% and $VAR literal", async () => {
  const echo = [process.execPath, "-e", "process.stderr.write(JSON.stringify(process.argv.slice(1)))", "%PATH%", "$HOME", "a&b"];
  const r = await runHook(echo, buildPayload("Stop"), { shell: true });
  assert.deepEqual(JSON.parse(r.stderr), ["%PATH%", "$HOME", "a&b"], isWin ? "cmd.exe" : "sh");
});

// (4) numeric flags are validated.
test("bad numeric flags are usage errors (exit 2)", () => {
  for (const [cmd, v] of [["run", "abc"], ["run", "0"], ["fuzz", "-5"], ["bypass", "1.5"], ["fuzz", ""]] as const) {
    const extra = cmd === "run" ? ["Stop"] : cmd === "bypass" ? ["--command", "rm -rf /"] : [];
    const r = cli([cmd, ...extra, "--timeout", v, "--", process.execPath, "-e", "0"]);
    assert.equal(r.code, 2, `${cmd} --timeout ${JSON.stringify(v)}: ${r.err}`);
    assert.match(r.err, /--timeout must be a positive integer/);
  }
  assert.equal(cli(["run", "Stop", "--timeout=250", "--", process.execPath, "-e", "0"]).code, 0);
});

// (5) other review items.
test("unknown options, bad JSON flags and bad --project are usage errors", () => {
  const r1 = cli(["run", "Stop", "--timout", "5", "--", process.execPath, "-e", "0"]);
  assert.equal(r1.code, 2); assert.match(r1.err, /unknown option --timout/);
  const r2 = cli(["payload", "PreToolUse", "--input", "[1]"]);
  assert.equal(r2.code, 2); assert.match(r2.err, /must be a JSON object/);
  const r3 = cli(["payload", "PreToolUse", "--input", "@/nonexistent/x.json"]);
  assert.equal(r3.code, 2); assert.match(r3.err, /cannot read/);
  const r4 = cli(["scan", "--project", "/nonexistent/dir"]);
  assert.equal(r4.code, 2); assert.match(r4.err, /not a directory/);
  const r5 = cli(["run", "Stop", "--"]);
  assert.equal(r5.code, 2); assert.match(r5.err, /missing hook command/);
  const r6 = cli([]);
  assert.equal(r6.code, 2); assert.match(r6.err, /Usage:/);
});

test("spec validation rejects bad timeouts, commands and expectation keys", () => {
  const ok = { command: "x", cases: [{ event: "Stop" }] };
  assert.doesNotThrow(() => validateSpec(ok));
  assert.throws(() => validateSpec({ ...ok, timeout: "1s" }), /spec.timeout must be a positive integer/);
  assert.throws(() => validateSpec({ cases: [{ event: "Stop", command: [] }] }), /command must be/);
  assert.throws(() => validateSpec({ ...ok, cases: [{ event: "Stop", expect: { decison: "deny" } }] }), /expect.decison is not a known/);
  assert.throws(() => validateSpec({ ...ok, cases: [{ event: "Stop", expect: { maxDurationMs: -1 } }] }), /maxDurationMs/);
  const dir = mkdtempSync(join(tmpdir(), "spec-"));
  writeFileSync(join(dir, "hookfuzz.json"), JSON.stringify({ ...ok, timeout: 0 }));
  const r = cli(["test"], dir);
  assert.equal(r.code, 2); assert.match(r.err, /spec.timeout/);
});

test("transcript_path uses the platform path separator", () => {
  const p = buildPayload("Stop", { cwd: join(tmpdir(), "proj"), sessionId: "s1" });
  assert.equal(p.transcript_path, join(tmpdir(), "proj", ".claude", "transcripts", "s1.jsonl"));
});
