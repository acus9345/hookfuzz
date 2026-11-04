import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bypassHook, bypassVariants } from "../src/index.js";
import { HOOKS, hasBash } from "./helpers.js";

function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => { for (const n of readdirSync(d).sort()) { const p = join(d, n); const s = statSync(p); out.push(`${p}|${s.isDirectory() ? "d" : s.size}|${s.mtimeMs}`); if (s.isDirectory()) walk(p); } };
  walk(dir); return out;
}

test("bypassVariants generates distinct equivalent forms", () => {
  const v = bypassVariants("rm -rf /");
  assert.ok(v.length >= 20);
  const cmds = v.map((x) => x.command);
  assert.ok(cmds.includes("rm -r -f /"));
  assert.ok(cmds.includes("/bin/rm -rf /"));
  assert.ok(cmds.includes("rm --recursive --force /"));
  assert.equal(new Set(v.map((x) => x.technique)).size, v.length);
});

test("SAFETY: variants are only fed on stdin, never executed (canary)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hookfuzz-canary-"));
  const keep = join(dir, "keep");
  mkdirSync(keep); writeFileSync(join(keep, "file.txt"), "keep me");
  const before = snapshot(dir);
  // allow-everything hook that just drains stdin; it never acts on the command
  const allowAll = [process.execPath, "-e", "process.stdin.resume();process.stdin.on('end',()=>process.exit(0))"];
  const canaries = [`touch ${join(dir, "PWNED")}`, `rm -rf ${keep}`, `echo pwned > ${join(dir, "PWNED2")}`];
  const seen: string[] = [];
  for (const c of canaries) {
    const rep = await bypassHook(allowAll, c, { cwd: dir, onCase: (f) => seen.push(f.command) });
    assert.equal(rep.baselineBlocked, false);
    assert.equal(rep.bypasses, rep.total); // everything "allowed", so every variant counts as a bypass
  }
  assert.ok(seen.some((s) => s.startsWith("bash -c")) && seen.some((s) => s.includes("| sh")) && seen.some((s) => s.startsWith("eval")));
  assert.ok(!existsSync(join(dir, "PWNED")), "canary file must never be created");
  assert.ok(!existsSync(join(dir, "PWNED2")), "canary file must never be created");
  assert.ok(existsSync(join(keep, "file.txt")), "keep dir must survive");
  assert.deepEqual(snapshot(dir), before, "tmpdir contents must be unchanged");
});

test("bypass finds holes in a naive regex guard", { skip: !hasBash && "bash not available" }, async () => {
  const rep = await bypassHook(["bash", join(HOOKS, "block-rm.sh")], "rm -rf /tmp/x");
  assert.equal(rep.baselineBlocked, true);
  const by = new Set(rep.findings.filter((f) => f.bypassed).map((f) => f.technique));
  assert.ok(by.has("split-flags"), [...by].join(","));
  assert.ok(by.has("long-flags"));
});
