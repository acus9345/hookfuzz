import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BLOCKING_EVENTS, EVENTS, bypassVariants, escapeCmdShimPath, interpret, quoteCmdArg, quoteCmdShimArg,
  resolveWindowsCommand, runHook, spawnSpec,
} from "../src/index.js";
import { CLI, ROOT, cli, isWin } from "./helpers.js";

// Remove every caret-escaped pair; anything left over is a metacharacter cmd.exe would act on.
const unescaped = (s: string) => s.replace(/\^./g, "");

// N-1: `:` is escaped, so %VAR:a=b% / %VAR:~n,m% can't expand.
test("quoteCmdArg escapes ':' so %VAR:a=b% and %VAR:~0,5% stay literal", () => {
  for (const a of ["%PATH:\\=/%", "%PATH:~0,5%", "%CD:a=b%", "x:y"]) {
    for (const shim of [false, true]) {
      const q = quoteCmdArg(a, shim);
      assert.doesNotMatch(unescaped(q), /[%:]/, `${a} (shim=${shim}) -> ${q}`);
    }
  }
  assert.equal(quoteCmdArg("%PATH:~0,5%"), '^"^%PATH^:~0^,5^%^"');
  assert.equal(quoteCmdShimArg("a:b"), '^^^"a^^^:b^^^"');
});

test("escapeCmdShimPath keeps the drive colon and escapes any other ':'", () => {
  assert.equal(escapeCmdShimPath("C:\\tools\\x.cmd"), "C:\\tools\\x.cmd");
  assert.equal(escapeCmdShimPath("C:\\a:b\\x.cmd"), "C:\\a^:b\\x.cmd");
  assert.equal(escapeCmdShimPath("tools\\%X:a=b%.cmd"), "tools\\^%X^:a=b^%.cmd");
});

// N-2: a bare name that resolves through PATHEXT to a .cmd shim is double-escaped, with or without --shell.
function fakeWinPath() {
  const bin = mkdtempSync(join(tmpdir(), "pathext-r3-"));
  writeFileSync(join(bin, "npx.cmd"), "@echo off\r\nnode npx-cli.js %*\r\n");
  writeFileSync(join(bin, "tool.exe"), "");
  return { bin, env: { PATH: bin, PATHEXT: ".COM;.EXE;.BAT;.CMD" } };
}

test("resolveWindowsCommand follows cwd, PATH and PATHEXT", () => {
  const { bin, env } = fakeWinPath();
  const elsewhere = mkdtempSync(join(tmpdir(), "cwd-"));
  assert.equal(resolveWindowsCommand("npx", env, elsewhere)?.toLowerCase(), join(bin, "npx.cmd").toLowerCase());
  assert.equal(resolveWindowsCommand("tool", env, elsewhere)?.toLowerCase(), join(bin, "tool.exe").toLowerCase());
  assert.equal(resolveWindowsCommand("npx.cmd", env, elsewhere)?.toLowerCase(), join(bin, "npx.cmd").toLowerCase());
  assert.equal(resolveWindowsCommand("nope", env, elsewhere), undefined);
  // the current directory is searched first, like cmd.exe
  assert.equal(resolveWindowsCommand("npx", { PATH: "", PATHEXT: ".CMD" }, bin)?.toLowerCase(), join(bin, "npx.cmd").toLowerCase());
});

test("--shell double-escapes a bare name that resolves to a .cmd shim (npx -> npx.cmd)", () => {
  const { env } = fakeWinPath();
  const evil = 'x"&calc&"';
  const viaShell = spawnSpec(["npx", "pkg", evil], { shell: true, env }, "win32");
  assert.equal(viaShell.shell, true);
  assert.equal(viaShell.file, `npx ${quoteCmdShimArg("pkg")} ${quoteCmdShimArg(evil)}`);
  // after cmd's first pass the shim must still see every metacharacter escaped once
  const pass1 = viaShell.file.replace(/\^(.)/g, "$1");
  assert.doesNotMatch(unescaped(pass1.slice(4)), /[&"%]/, pass1);
  // a real .exe keeps single escaping
  assert.equal(spawnSpec(["tool", evil], { shell: true, env }, "win32").file, `tool ${quoteCmdArg(evil)}`);
});

test("exec form resolves a bare shim name to its .cmd path and double-escapes, like an explicit x.cmd", () => {
  const { bin, env } = fakeWinPath();
  const s = spawnSpec(["npx", "%PATH:~0,3%"], { env }, "win32");
  assert.equal(s.shell, true);
  assert.match(s.file, /npx\.cmd /i);
  assert.ok(s.file.endsWith(" " + quoteCmdShimArg("%PATH:~0,3%")), s.file);
  assert.ok(s.file.toLowerCase().startsWith(escapeCmdShimPath(join(bin, "npx.cmd")).toLowerCase()));
  // .exe and unknown names are spawned directly
  assert.deepEqual(spawnSpec(["tool", "a"], { env }, "win32"), { file: "tool", args: ["a"], shell: false });
  assert.deepEqual(spawnSpec(["nope", "a"], { env }, "win32"), { file: "nope", args: ["a"], shell: false });
  // POSIX is untouched
  assert.deepEqual(spawnSpec(["npx", "a"], { env }, "linux"), { file: "npx", args: ["a"], shell: false });
});

test("a bare-name .cmd shim under --shell receives :, %, & and quotes literally on Windows", { skip: !isWin && "needs cmd.exe (Windows only)" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "shim3-"));
  writeFileSync(join(dir, "echoargs.mjs"), "process.stderr.write(JSON.stringify(process.argv.slice(2)))");
  writeFileSync(join(dir, "echoargs3.cmd"), `@"${process.execPath}" "%~dp0echoargs.mjs" %*\r\n`);
  const args = ["%PATH:\\=/%", "%PATH:~0,5%", 'x"&echo PWN&"', "a&b"];
  for (const shell of [true, false]) {
    const r = await runHook(["echoargs3", ...args], { hook_event_name: "Stop" }, { shell, env: { PATH: `${dir};${process.env.PATH}` } });
    assert.deepEqual(JSON.parse(r.stderr), args, `shell=${shell}`);
  }
});

// N-3: run exits 1 when the hook crashes.
test("run exits 1 for a crashing hook, 0 for allow/deny/block", () => {
  const crash = cli(["run", "PreToolUse", "--", process.execPath, "-e", "throw new Error('boom')"]);
  assert.equal(crash.code, 1, crash.out); assert.match(crash.out, /decision\s+error/);
  assert.equal(cli(["run", "Stop", "--", process.execPath, "-e", "process.exit(3)"]).code, 1);
  assert.equal(cli(["run", "PreToolUse", "--", process.execPath, "-e", "process.exit(2)"]).code, 0);
  assert.equal(cli(["run", "Stop", "--", process.execPath, "-e", "0"]).code, 0);
  assert.equal(cli(["run", "Stop", "--", "definitely-not-a-real-binary-xyz"]).code, 1);
});

test("help text and package metadata use the hookfuzz name", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.equal(pkg.name, "hookfuzz");
  assert.deepEqual(pkg.bin, { hookfuzz: "dist/cli.js" });
  const help = cli(["--help"]).out;
  assert.match(help, /^hookfuzz - /);
  assert.doesNotMatch(help, /hookshot/);
  assert.match(help, /crashes/);
  const readme = readFileSync(join(ROOT, "README.md"), "utf8");
  assert.doesNotMatch(readme, /hookshot/);
});

// L1: events from the reference.
test("EVENTS covers the reference, with the WorktreeCreate and Elicitation rules", () => {
  for (const e of ["MessageDisplay", "DirectoryAdded", "WorktreeCreate", "WorktreeRemove", "Elicitation", "ElicitationResult"]) assert.ok((EVENTS as readonly string[]).includes(e), e);
  assert.equal(EVENTS.length, 33);
  assert.equal(new Set(EVENTS).size, EVENTS.length);
  for (const e of BLOCKING_EVENTS) assert.ok((EVENTS as readonly string[]).includes(e), e);
  const raw = { command: "x", signal: null, stderr: "nope", durationMs: 1, timedOut: false };
  assert.equal(interpret({ ...raw, event: "WorktreeCreate", exitCode: 1, stdout: "/tmp/wt" }).blocked, true);
  assert.equal(interpret({ ...raw, event: "WorktreeCreate", exitCode: 0, stdout: "/tmp/wt" }).blocked, false);
  assert.equal(interpret({ ...raw, event: "WorktreeRemove", exitCode: 1, stdout: '{"continue":true}' }).decision, "block");
  const decline = JSON.stringify({ hookSpecificOutput: { hookEventName: "Elicitation", action: "decline" } });
  assert.equal(interpret({ ...raw, event: "Elicitation", exitCode: 0, stdout: decline }).decision, "block");
  assert.equal(interpret({ ...raw, event: "Elicitation", exitCode: 1, stdout: decline }).blocked, false);
  assert.equal(cli(["events"]).out.trim().split("\n").length, 33);
});

// L6: output is capped.
test("stdout/stderr are capped at maxOutput and a cut stdout is an error", async () => {
  const r = await runHook([process.execPath, "-e", "process.stdout.write('x'.repeat(200000));process.stderr.write('y'.repeat(200000))"], { hook_event_name: "Stop" }, { maxOutput: 1000 });
  assert.equal(r.stdout.length, 1000); assert.equal(r.stderr.length, 1000);
  assert.deepEqual(r.truncated, { stdout: true, stderr: true });
  assert.equal(r.decision, "error"); assert.equal(r.exitCode, 0);
  const ok = await runHook([process.execPath, "-e", "0"], { hook_event_name: "Stop" });
  assert.equal(ok.truncated, undefined);
});

// L7: absolute heads.
test("bypassVariants never doubles an absolute path and drops no-op variants", () => {
  const v = bypassVariants("/bin/rm -rf /");
  const cmds = v.map((x) => x.command);
  assert.ok(!cmds.some((c) => c.includes("//bin/") || c.includes("/bin//")), cmds.join("\n"));
  assert.ok(!cmds.includes("/bin/rm -rf /"));
  assert.ok(cmds.includes("rm -rf /"));
  assert.ok(cmds.includes("/usr/bin/rm -rf /"));
  assert.ok(v.some((x) => x.technique === "long-flags"));
  assert.equal(bypassVariants("rm -rf /tmp/x").length, 24);
});

// L11: Ctrl-C on the CLI kills the hook's process group.
test("SIGINT to the CLI kills the running hook", { skip: isWin && "POSIX process groups" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sigint-"));
  const pidFile = join(dir, "pid");
  const hook = `require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setInterval(() => {}, 1000)`;
  const child = spawn(process.execPath, [CLI, "run", "Stop", "--timeout", "60000", "--", process.execPath, "-e", hook], { stdio: "ignore" });
  const t0 = Date.now();
  while (!existsSync(pidFile) || !readFileSync(pidFile, "utf8")) { if (Date.now() - t0 > 10_000) throw new Error("hook never started"); await new Promise((r) => setTimeout(r, 50)); }
  const pid = Number(readFileSync(pidFile, "utf8"));
  const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
  child.kill("SIGINT");
  assert.equal(await exited, 130);
  const alive = () => { try { process.kill(pid, 0); return true; } catch { return false; } };
  const t1 = Date.now();
  while (alive() && Date.now() - t1 < 5000) await new Promise((r) => setTimeout(r, 50));
  assert.equal(alive(), false, `hook ${pid} survived Ctrl-C`);
});
