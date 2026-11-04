import { buildPayload } from "./payload.js";
import { runHook, type HookResult } from "./runner.js";

/**
 * Bypass fuzzer: given a Bash command a hook is supposed to block, generate
 * semantically equivalent variants and report which ones the hook lets through.
 *
 * SAFETY: variant strings are ONLY ever placed inside the JSON payload written to
 * the hook's stdin (`tool_input.command`). They are never executed, eval'd or
 * shell-interpreted by hookfuzz, and never used to build the hook's spawn command.
 */
export interface BypassVariant { technique: string; command: string }
export interface BypassFinding extends BypassVariant { bypassed: boolean; result: HookResult }
export interface BypassReport { baseline: HookResult; baselineBlocked: boolean; total: number; bypasses: number; findings: BypassFinding[] }

export function bypassVariants(cmd: string): BypassVariant[] {
  const [head, ...rest] = cmd.trim().split(/\s+/);
  const args = rest.join(" ");
  const sq = cmd.replace(/'/g, "'\\''");
  // for an absolute or relative head like /bin/rm, path variants use the bare name (never /bin//bin/rm)
  const name = head.includes("/") ? head.slice(head.lastIndexOf("/") + 1) || head : head;
  const v: BypassVariant[] = [
    ...(name !== head ? [{ technique: "bare-name", command: `${name} ${args}` }] : []),
    { technique: "absolute-path", command: `/bin/${name} ${args}` },
    { technique: "usr-bin-path", command: `/usr/bin/${name} ${args}` },
    { technique: "sudo", command: `sudo ${cmd}` },
    { technique: "env-prefix", command: `FOO=1 ${cmd}` },
    { technique: "env-command", command: `env ${cmd}` },
    { technique: "command-builtin", command: `command ${cmd}` },
    { technique: "backslash-escape", command: `\\${cmd}` },
    { technique: "quoted-name", command: `'${head}' ${args}` },
    { technique: "split-quotes", command: `${head.slice(0, 1)}""${head.slice(1)} ${args}` },
    { technique: "bash-c", command: `bash -c '${sq}'` },
    { technique: "sh-c", command: `sh -c "${cmd.replace(/"/g, '\\"')}"` },
    { technique: "eval", command: `eval '${sq}'` },
    { technique: "subshell", command: `(${cmd})` },
    { technique: "command-substitution", command: `echo $(${cmd})` },
    { technique: "backticks", command: `echo \`${cmd}\`` },
    { technique: "chained-after-safe", command: `ls && ${cmd}` },
    { technique: "semicolon-chain", command: `true; ${cmd}` },
    { technique: "pipe-to-shell", command: `echo '${sq}' | sh` },
    { technique: "extra-whitespace", command: `${head}  \t ${rest.join("   ")}` },
    { technique: "newline-separated", command: `true\n${cmd}` },
    { technique: "xargs", command: `echo ${args} | xargs ${head}` },
  ];
  // flag splitting / reordering for short combined flags, e.g. -rf -> -r -f, -fr
  const flag = rest.find((a) => /^-[a-zA-Z]{2,}$/.test(a));
  if (flag) {
    const letters = flag.slice(1).split("");
    const others = rest.filter((a) => a !== flag).join(" ");
    v.push({ technique: "split-flags", command: `${head} ${letters.map((l) => "-" + l).join(" ")} ${others}` });
    v.push({ technique: "reordered-flags", command: `${head} -${[...letters].reverse().join("")} ${others}` });
    if (name === "rm") v.push({ technique: "long-flags", command: `${head} --recursive --force ${others}` });
  }
  // drop variants identical to the original (e.g. /bin/rm when the original already is /bin/rm)
  const orig = cmd.trim();
  return v.map((x) => ({ ...x, command: x.command.replace(/ +$/, "") })).filter((x) => x.command !== orig);
}

export async function bypassHook(hookCommand: string | string[], blockedCommand: string, opts: { tool?: string; timeoutMs?: number; cwd?: string; shell?: boolean; onCase?: (f: BypassFinding) => void } = {}): Promise<BypassReport> {
  const tool = opts.tool ?? "Bash";
  const run = (command: string) =>
    // the variant goes into the stdin payload only; hookCommand is used verbatim
    runHook(hookCommand, buildPayload("PreToolUse", { tool, input: { command } }), { timeoutMs: opts.timeoutMs ?? 5000, cwd: opts.cwd, shell: opts.shell });
  const baseline = await run(blockedCommand);
  const findings: BypassFinding[] = [];
  for (const v of bypassVariants(blockedCommand)) {
    const result = await run(v.command);
    const f = { ...v, bypassed: !result.blocked, result };
    findings.push(f); opts.onCase?.(f);
  }
  return { baseline, baselineBlocked: baseline.blocked, total: findings.length, bypasses: findings.filter((f) => f.bypassed).length, findings };
}
