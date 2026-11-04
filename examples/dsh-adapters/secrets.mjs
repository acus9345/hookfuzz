// Adapter: wraps the public rule function `analyzeCommand` from dsh-block-secret-leaks in
// https://github.com/acus9345/dsh-guard-pack (a DeepSeek Harness plugin) as a Claude Code
// PreToolUse hook, using the plugin's DEFAULT_SECRET_FILES globs. Set DSH_TARGETS to the
// directory holding a built clone of dsh-guard-pack. Commands are analysed, never run.
import { run, dsh } from "./_common.mjs";
const pkg = "dsh-guard-pack/packages/dsh-block-secret-leaks/lib/";
const { analyzeCommand } = await dsh(pkg + "commands.js");
const { DEFAULT_SECRET_FILES } = await dsh(pkg + "index.js");
const { matchesAny } = await dsh(pkg + "shared/glob.js");
const { resolvePath } = await dsh(pkg + "shared/files.js");
run((i, p) => {
  if (typeof i.command !== "string") return;
  const ws = typeof p.cwd === "string" ? p.cwd : process.cwd();
  const isSecretFile = (path) => matchesAny(resolvePath(path, ws).relative.replace(/^(\.\.\/)+/, ""), [...DEFAULT_SECRET_FILES]);
  const f = analyzeCommand(i.command, { dialect: "posix", isSecretFile, known: [], stageable: () => [] });
  return f.length && "blocked (" + f.map((x) => x.rule).join(",") + ")";
});
