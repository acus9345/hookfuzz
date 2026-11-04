import { accessSync, constants, existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export interface ScannedHook {
  source: string; event: string; matcher: string; type: string;
  command?: string; args?: string[]; timeout?: number;
  executable?: string; exists: boolean | null; problem?: string;
}
export interface ScanResult { files: { path: string; found: boolean; error?: string }[]; hooks: ScannedHook[] }

/** Settings files Claude Code reads hooks from (user + project + local). */
export function settingsFiles(projectDir = process.cwd(), home = homedir()): string[] {
  return [join(home, ".claude", "settings.json"), join(projectDir, ".claude", "settings.json"), join(projectDir, ".claude", "settings.local.json")];
}

/**
 * Split a hook command line into tokens, the way the shell that runs it would.
 * On win32 a backslash is a path separator, never an escape (so "C:\\x\\hook.ps1" stays intact).
 * On POSIX a backslash escapes any character outside quotes, but inside double quotes
 * only before `"`, `\\`, `$`, `` ` `` or a newline; inside single quotes it is literal.
 */
export function tokenize(cmd: string, platform: NodeJS.Platform = process.platform): string[] {
  const win = platform === "win32";
  const out: string[] = []; let cur = ""; let q: string | null = null; let has = false;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (q) {
      if (ch === q) q = null;
      else if (ch === "\\" && q === '"' && !win && i + 1 < cmd.length && '"\\$`\n'.includes(cmd[i + 1])) { const n = cmd[++i]; if (n !== "\n") cur += n; }
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { q = ch; has = true; continue; }
    if (ch === "\\" && !win && i + 1 < cmd.length) { const n = cmd[++i]; if (n !== "\n") { cur += n; has = true; } continue; }
    if (/\s/.test(ch)) { if (has || cur) out.push(cur); cur = ""; has = false; continue; }
    cur += ch; has = true;
  }
  if (has || cur) out.push(cur);
  return out;
}

const INTERPRETERS = new Set(["bash", "sh", "zsh", "node", "python", "python3", "deno", "bun", "ruby", "perl", "pwsh", "powershell", "powershell.exe", "uv", "npx"]);

export function expandVars(s: string, env: Record<string, string | undefined>): string {
  return s.replace(/\$\{(\w+)\}|\$(\w+)|%(\w+)%/g, (m, a, b, c) => env[a ?? b ?? c] ?? m).replace(/^~(?=$|[/\\])/, homedir());
}

/**
 * Find an executable on PATH. On win32 this honors PATHEXT (a name that already carries
 * one of its extensions is tried as-is first) and accepts App Execution Aliases such as
 * `python3` in %LOCALAPPDATA%\\Microsoft\\WindowsApps: zero-byte reparse points that
 * `stat` cannot follow, so they are detected with `lstat`.
 */
export function findOnPath(name: string, env: Record<string, string | undefined> = process.env, platform: NodeJS.Platform = process.platform): string | undefined {
  const win = platform === "win32";
  // the files live on this machine, so join natively; only the PATH list syntax follows `platform`
  const delimiter = win ? ";" : ":";
  const pathVar = win ? (env.PATH ?? env.Path ?? env.path ?? "") : (env.PATH ?? "");
  const pathext = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  const hasExt = pathext.some((e) => name.toLowerCase().endsWith(e.toLowerCase()));
  const exts = win ? (hasExt ? ["", ...pathext] : [...pathext, ...pathext.map((e) => e.toLowerCase())]) : [""];
  for (const dir of pathVar.split(delimiter)) {
    if (!dir) continue;
    for (const e of exts) {
      const p = join(dir.replace(/^"|"$/g, ""), name + e);
      try { if (statSync(p).isFile()) return p; } catch { /* maybe an execution alias */ }
      if (win) { try { const l = lstatSync(p); if (!l.isDirectory()) return p; } catch { /* next */ } }
    }
  }
  return undefined;
}

/** Determine whether a hook's command (and its script argument, for interpreters) exists. */
export function checkCommand(command: string, args: string[] | undefined, projectDir: string): Pick<ScannedHook, "executable" | "exists" | "problem"> {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: projectDir } as Record<string, string | undefined>;
  const toks = args ? [command, ...args] : tokenize(command);
  // skip leading VAR=value assignments
  while (toks.length && /^\w+=/.test(toks[0])) toks.shift();
  if (!toks.length) return { exists: false, problem: "empty command" };
  const exe = expandVars(toks[0], env);
  if (/\$/.test(exe)) return { executable: exe, exists: null, problem: "unresolved variable; cannot verify" };
  const isPath = /[/\\]/.test(exe);
  const resolved = isPath ? resolve(projectDir, exe) : findOnPath(exe);
  // PATH hits are trusted: WindowsApps aliases exist but fail existsSync (stat)
  if (!resolved || (isPath && !existsSync(resolved))) return { executable: exe, exists: false, problem: isPath ? `file not found: ${resolved}` : `not on PATH: ${exe}` };
  if (isPath && process.platform !== "win32") {
    try { accessSync(resolved, constants.X_OK); } catch { return { executable: resolved, exists: true, problem: "file is not executable (chmod +x)" }; }
  }
  const base = exe.split(/[/\\]/).pop()!.replace(/\.exe$/i, "").toLowerCase();
  if (INTERPRETERS.has(base)) {
    const script = toks.slice(1).find((t) => !t.startsWith("-") && /[/\\]|\.(sh|js|mjs|cjs|ts|py|rb|pl|ps1)$/i.test(t));
    if (script) {
      const sp = resolve(projectDir, expandVars(script, env));
      if (/\$/.test(sp)) return { executable: resolved, exists: null, problem: "script path has unresolved variable" };
      if (!existsSync(sp)) return { executable: resolved, exists: false, problem: `script not found: ${sp}` };
    }
  }
  return { executable: resolved, exists: true };
}

export function scanSettings(opts: { projectDir?: string; home?: string; files?: string[] } = {}): ScanResult {
  const projectDir = resolve(opts.projectDir ?? process.cwd());
  const files = opts.files ?? settingsFiles(projectDir, opts.home);
  const res: ScanResult = { files: [], hooks: [] };
  for (const f of files) {
    if (!existsSync(f)) { res.files.push({ path: f, found: false }); continue; }
    let json: any;
    try { json = JSON.parse(readFileSync(f, "utf8")); } catch (e) { res.files.push({ path: f, found: true, error: (e as Error).message }); continue; }
    res.files.push({ path: f, found: true });
    const hooks = json?.hooks ?? {};
    for (const [event, groups] of Object.entries<any>(hooks)) {
      if (!Array.isArray(groups)) continue;
      for (const g of groups) for (const h of g?.hooks ?? []) {
        const entry: ScannedHook = { source: f, event, matcher: g.matcher ?? "*", type: h.type ?? "command", command: h.command, args: h.args, timeout: h.timeout, exists: null };
        if (entry.type === "command") {
          if (typeof h.command !== "string") Object.assign(entry, { exists: false, problem: "missing command" });
          else Object.assign(entry, checkCommand(h.command, h.args, projectDir));
        }
        res.hooks.push(entry);
      }
    }
  }
  return res;
}
