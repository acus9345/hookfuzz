import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
// compiled to build-test/test/*.js -> repo root is two levels up
export const ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "..");
export const EX = join(ROOT, "examples");
export const HOOKS = join(EX, "hooks");
export const CLI = join(ROOT, "dist", "cli.js");
export const isWin = process.platform === "win32";
export const PY = ["python3", "python"].find((p) => spawnSync(p, ["--version"]).status === 0);
/**
 * A usable bash: any bash on POSIX; on Windows only Git Bash / MSYS2 / Cygwin (OSTYPE msys or cygwin),
 * not the WSL launcher in System32, which would get Windows paths it cannot open.
 */
export const hasBash = (() => {
  const r = spawnSync("bash", ["-c", "echo $OSTYPE"], { encoding: "utf8" });
  return r.status === 0 && (!isWin || /^(msys|cygwin)/.test(r.stdout.trim()));
})();
export function cli(args: string[], cwd = ROOT, env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8", env: { ...process.env, NO_COLOR: "1", ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
