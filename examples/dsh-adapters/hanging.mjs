// Adapter: wraps the public rule function `analyzeCommand` from
// https://github.com/acus9345/dsh-block-hanging-commands (a DeepSeek Harness plugin)
// as a Claude Code PreToolUse hook, so hookfuzz can test it. Set DSH_TARGETS to the
// directory holding a built clone of the repo. Commands are analysed, never run.
import { run, dsh } from "./_common.mjs";
const { analyzeCommand } = await dsh("dsh-block-hanging-commands/lib/rules.js");
run((i) => {
  if (typeof i.command !== "string" || i.run_in_background === true) return;
  const f = analyzeCommand(i.command, { pty: false, dialect: "posix" });
  return f && `blocked (${f.rule ?? f.id ?? "rule"})`;
});
