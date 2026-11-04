import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkCommand, escapeCmdShimPath, findOnPath, fuzzCases, fuzzHook, quoteCmdShimArg, runHook, tokenize } from "../src/index.js";
import { isWin } from "./helpers.js";

// H1: quoted Windows paths survive tokenizing on win32; POSIX keeps its escape rules.
test("tokenize keeps backslashes literal on win32", () => {
  assert.deepEqual(tokenize('powershell -File "C:\\Users\\x\\hook.ps1"', "win32"), ["powershell", "-File", "C:\\Users\\x\\hook.ps1"]);
  assert.deepEqual(tokenize("node C:\\hooks\\a.mjs", "win32"), ["node", "C:\\hooks\\a.mjs"]);
  assert.deepEqual(tokenize('node "C:\\dir\\"', "win32"), ["node", "C:\\dir\\"]);
});

test("tokenize follows POSIX backslash rules", () => {
  // inside double quotes only \" \\ \$ \` and \newline are escapes
  assert.deepEqual(tokenize('echo "a\\"b" "c\\\\d" "e\\$f" "g\\h" "i\\`j"', "linux"), ["echo", 'a"b', "c\\d", "e$f", "g\\h", "i`j"]);
  assert.deepEqual(tokenize("echo 'a\\b' c\\ d", "linux"), ["echo", "a\\b", "c d"]);
  assert.deepEqual(tokenize("a \\\nb", "linux"), ["a", "b"]);
});

test("scan does not report a quoted Windows-style script path as missing", () => {
  const dir = mkdtempSync(join(tmpdir(), "hs-win-"));
  mkdirSync(join(dir, "hooks"));
  writeFileSync(join(dir, "hooks", "x.mjs"), "");
  const r = checkCommand(`"${process.execPath}" "${join(dir, "hooks", "x.mjs")}"`, undefined, dir);
  assert.equal(r.exists, true, r.problem);
});

// M1: execution aliases and PATHEXT.
test("findOnPath accepts WindowsApps-style aliases that stat cannot follow", (t) => {
  const apps = mkdtempSync(join(tmpdir(), "WindowsApps-"));
  // a dangling link behaves like an App Execution Alias: lstat works, stat fails
  try { symlinkSync(join(apps, "does-not-exist"), join(apps, "python3.exe"), "file"); } catch (e) { t.skip(`cannot create symlinks here: ${(e as Error).message}`); return; }
  assert.equal(findOnPath("python3", { PATH: apps, PATHEXT: ".COM;.EXE;.BAT;.CMD" }, "win32"), join(apps, "python3.exe"));
  // on POSIX a dangling link is not an executable
  if (!isWin) assert.equal(findOnPath("python3.exe", { PATH: apps }, "linux"), undefined);
});

test("findOnPath honors PATHEXT order and names that already carry an extension", () => {
  const bin = mkdtempSync(join(tmpdir(), "pathext-"));
  writeFileSync(join(bin, "tool.CMD"), "");
  writeFileSync(join(bin, "tool.PS1"), "");
  assert.equal(findOnPath("tool", { PATH: bin, PATHEXT: ".EXE;.CMD" }, "win32"), join(bin, "tool.CMD"));
  assert.equal(findOnPath("tool", { PATH: bin, PATHEXT: ".PS1;.CMD" }, "win32"), join(bin, "tool.PS1"));
  assert.equal(findOnPath("tool.CMD", { PATH: bin, PATHEXT: ".EXE;.CMD" }, "win32"), join(bin, "tool.CMD"));
  assert.equal(findOnPath("tool", { Path: bin, PATHEXT: ".CMD" }, "win32"), join(bin, "tool.CMD"));
});

// M2: the cases that drop hook_event_name really drop it.
test("fuzz cases that omit hook_event_name keep it omitted on stdin", async () => {
  const cases = fuzzCases("PreToolUse");
  for (const name of ["missing-hook_event_name", "empty-object"]) {
    const c = cases.find((x) => x.name === name)!;
    assert.equal("hook_event_name" in c.payload, false, name);
  }
  const echo = [process.execPath, "-e", "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{process.stderr.write(s);process.exit(0)})"];
  const seen: Record<string, string> = {};
  await fuzzHook(echo, { timeoutMs: 10_000, onCase: (f) => { seen[f.case] = f.result.stderr; } });
  for (const name of ["missing-hook_event_name", "empty-object"]) assert.equal("hook_event_name" in JSON.parse(seen[name]), false, name);
  assert.equal(JSON.parse(seen["baseline"]).hook_event_name, "PreToolUse");
});

test("runHook uses opts.event to interpret a payload without hook_event_name", async () => {
  const r = await runHook([process.execPath, "-e", "process.exit(2)"], {}, { event: "PreToolUse" });
  assert.equal(r.event, "PreToolUse");
  assert.equal(r.blocked, true);
});

// M4: cmd metacharacters in .cmd/.bat shim arguments.
test("quoteCmdShimArg caret-escapes % and other cmd metacharacters", () => {
  for (const a of ["100%", "%PATH%", "a&b", "x|y", "<in>", "^", "!v!", "(p)", 'say "hi"']) {
    const q = quoteCmdShimArg(a);
    // strip escaped pairs: nothing unescaped may remain
    assert.doesNotMatch(q.replace(/\^./g, ""), /[%&|<>!()"]/, `${a} -> ${q}`);
  }
  assert.equal(quoteCmdShimArg("100%"), '^^^"100^^^%^^^"');
  assert.equal(escapeCmdShimPath("C:\\Program Files (x86)\\a.cmd"), "C:\\Program^ Files^ ^(x86^)\\a.cmd");
});

test("a .cmd shim receives % and & literally on Windows", { skip: !isWin && "needs cmd.exe (Windows only)" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "shim-"));
  const shim = join(dir, "echoargs.cmd");
  writeFileSync(join(dir, "echoargs.mjs"), "process.stderr.write(JSON.stringify(process.argv.slice(2)))");
  writeFileSync(shim, `@"${process.execPath}" "%~dp0echoargs.mjs" %*\r\n`);
  const r = await runHook([shim, "100%", "%PATH%", "a&b"], { hook_event_name: "Stop" });
  assert.deepEqual(JSON.parse(r.stderr), ["100%", "%PATH%", "a&b"]);
});
