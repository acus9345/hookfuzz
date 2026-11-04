# hookfuzz

**Test harness, spec runner and fuzzer for [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks)** — in any language.

Claude Code hooks are scripts that receive a JSON payload on stdin and answer with an exit code
(`0` ok, `2` block with stderr fed back) and optional JSON on stdout. They are easy to get subtly
wrong: a typo in `hookEventName`, a crash on an unexpected payload, a hook that hangs, a path in
`settings.json` that doesn't exist (so your "policy" hook silently never runs). `hookfuzz` catches
all of these before a real session does.

```
npm i -D hookfuzz     # binary: hookfuzz
```

Node 20+, Linux / macOS / Windows, one runtime dependency (`yaml`).

## Commands

### `hookfuzz run` — fire one realistic event at a hook

```console
$ hookfuzz run PreToolUse --tool Bash --input '{"command":"rm -rf /"}' -- bash hooks/block-rm.sh
event     PreToolUse
exit      2
decision  block (blocks) - Blocked: rm -rf is not allowed by policy
time      6.9 ms
stdout    empty
stderr
  │ Blocked: rm -rf is not allowed by policy

$ hookfuzz run PreToolUse --tool Write --input '{"file_path":"a/.env"}' -- "node hooks/guard.mjs"
event     PreToolUse
exit      0
decision  deny (blocks) - Writing .env files is not allowed
time      31.2 ms
stdout    valid JSON
  │ {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
```

* `--tool`, `--input JSON|@file` — tool name and `tool_input` (or event fields like `prompt`).
* `--payload JSON|@file` — deep-merge overrides into the payload (`null` deletes a key).
* `--timeout ms` (default 60000; must be a positive integer), `--json` for machine-readable output.
* `--shell` runs a multi-argument hook command through the shell anyway (`sh -c` / `cmd.exe`); arguments
  are quoted, and on Windows cmd metacharacters such as `%VAR%`, `%VAR:a=b%` and `%VAR:~0,5%` are
  caret-escaped so they stay literal. A first word that cmd resolves to a `.cmd`/`.bat` shim through
  `PATHEXT` (e.g. `npx` → `npx.cmd`) gets the shim's double escaping.
* Exit code: `0` when the hook ran and gave a usable answer (including a block or deny); `1` when the
  decision is `error` (a crash, i.e. a non-0/2 exit without valid JSON, or invalid/schema-violating
  output), `timeout` or `spawn-error`; `2` on a usage error. Unknown options and bad values are usage errors.
* `hookfuzz payload <event>` prints the payload without running anything.

The decision is derived exactly like Claude Code's table in the hooks reference: exit 2 blocks on
blocking events (but not e.g. `PostToolUse`/`Notification`); valid JSON on stdout decides regardless
of a non-0/2 exit code; JSON is only considered JSON if stdout is a single `{...}` object; invalid
JSON or schema violations (bad `permissionDecision`, missing/mismatched `hookSpecificOutput.hookEventName`,
wrong types, `decision` other than `"block"`) are reported as errors.

Decisions: `allow` `deny` `ask` `defer` `block` `stop` (`continue:false`) `none` `error` `timeout` `spawn-error`.

Event-specific rules from the reference are modelled too: any non-zero exit fails `WorktreeCreate` /
`WorktreeRemove` (decision `block`); `Elicitation` / `ElicitationResult` only honour `hookSpecificOutput`
(`action: accept|decline|cancel`) on exit 0. `hookfuzz events` lists all 33 known events.

**Hook command form.** One argument after `--` runs through the shell, like a settings `command`
string (`sh -c` on POSIX, `cmd.exe` on Windows). Several arguments are spawned directly with no shell,
like `command` + `args` (exec form) — no quoting problems with spaces, `$` or quotes. On Windows
`.cmd`/`.bat` shims, and bare names such as `npx` that resolve to one through `PATHEXT`, are wrapped in a
correctly-quoted, double-escaped shell call automatically. Timeouts kill the whole process tree (process
group on POSIX, `taskkill /T` on Windows), and so does Ctrl-C / SIGTERM to `hookfuzz` itself. Each of
stdout and stderr is kept up to 16 MiB (`maxOutput` in the API); the rest is drained and dropped, and
cut stdout is reported as decision `error`.

### `hookfuzz test` — spec-driven suites for CI

`hookfuzz.yml` (or `.yaml` / `.json`, or pass a path):

```yaml
command: node hooks/guard.mjs        # default for all cases; string = shell form, list = exec form
timeout: 10000
cases:
  - name: denies writing .env
    event: PreToolUse
    tool: Write
    input: { file_path: /repo/.env, content: "SECRET=1" }
    expect: { decision: deny, blocked: true, validJson: true, reason: /\.env/ }
  - name: survives missing tool_input
    event: PreToolUse
    payload: { tool_input: null }      # deep-merge overrides
    expect: { exitCode: 0 }
  - name: python blocks secrets in prompts
    event: UserPromptSubmit
    command: [python3, hooks/prompt_filter.py]
    input: { prompt: "use key sk-abcdefghijklmnopqrstuvwx" }
    expect: { decision: block, reason: secret }
```

`expect` keys: `decision`, `exitCode`, `blocked`, `stdout`, `stderr`, `reason` (substring or `/regex/flags`),
`validJson`, `maxDurationMs`. Commands run with the spec's directory as cwd and `CLAUDE_PROJECT_DIR` set.

```console
$ hookfuzz test examples/hookfuzz.yml
✓ denies writing .env (deny, exit 0, 31.1ms)
✓ asks before git push (ask, exit 0, 29.6ms)
...
7 passed, 7 total
```

Exit code is `1` if any case fails (`2` for usage/spec errors). `--json` emits a full report.

### `hookfuzz fuzz` — malformed and edge-case payloads

```console
$ hookfuzz fuzz --timeout 2000 -- node hooks/buggy.mjs
INVALID-OUTPUT baseline                     permissionDecision must be one of allow/deny/ask/defer
CRASH empty-stdin                  exit 1: SyntaxError: Unexpected end of JSON input
CRASH missing-tool_input           exit 1: TypeError: Cannot read properties of undefined (reading 'command')
HANG huge-command-1MB             no exit within timeout (2005.3ms)
INVALID-OUTPUT unicode-emoji-rtl            stdout is not valid JSON: ...
...
20 problem(s) in 20 cases
```

Cases: empty object/stdin, malformed JSON, non-object JSON, each common field missing, `null`/string/
wrong-typed fields, 1 MB strings, emoji/RTL/NUL unicode, Windows & traversal paths, shell metacharacters,
control chars, 200-deep nesting, unknown future fields, MCP tool names. `--event` / `--tool` pick the
base event (default `PreToolUse`/`Bash`). A hook passes when it exits 0 or 2 (or prints valid JSON),
within the timeout, with schema-valid output.

### `hookfuzz bypass` — find equivalent commands your guard lets through

```console
$ hookfuzz bypass --command "rm -rf /tmp/x" -- bash hooks/block-rm.sh
blocked absolute-path          "/bin/rm -rf /tmp/x"
blocked bash-c                 "bash -c 'rm -rf /tmp/x'"
BYPASS  quoted-name            "'rm' -rf /tmp/x"
BYPASS  split-flags            "rm -r -f /tmp/x"
BYPASS  reordered-flags        "rm -fr /tmp/x"
BYPASS  long-flags             "rm --recursive --force /tmp/x"
...
8 bypass(es) in 24 variants
```

Give it a command your `PreToolUse` hook should block. It generates about 24 equivalent variants (absolute
paths, or the bare name if the command already starts with a path, `sudo`/`env`/`command` prefixes, quoting tricks, `bash -c`, `eval`, `$()`, backticks, chaining,
pipes to `sh`, `xargs`, split/reordered/long flags) and reports every variant the hook does not block.
Exits `1` if there are bypasses, or if the original command isn't blocked.

> **Safety guarantee:** variant commands are **only ever placed inside the JSON payload** written to the
> hook's stdin (`tool_input.command`). hookfuzz never executes, evals or shell-interprets a variant,
> not even in a sandbox, and never builds the hook's own spawn command from variant text. A test
> (`test/bypass.test.ts`) runs canary variants such as `touch <tmp>/PWNED` and `rm -rf <tmp>/keep` against an
> allow-everything hook. It asserts that the canary file is never created, the keep directory survives,
> and the temp directory is byte-for-byte unchanged. (Your *hook* could still choose to run what it
> receives; that would be a bug in the hook.)

### `hookfuzz scan` — audit configured hooks

```console
$ cd examples/project && hookfuzz scan
· /home/me/.claude/settings.json (not found)
✓ <repo>/examples/project/.claude/settings.json
· <repo>/examples/project/.claude/settings.local.json (not found)

ok      PreToolUse[Bash] bash "${CLAUDE_PROJECT_DIR}/../hooks/block-rm.sh"
ok      PreToolUse[Bash] node ${CLAUDE_PROJECT_DIR}/../hooks/guard.mjs
ok      UserPromptSubmit[*] python3 ../hooks/prompt_filter.py
MISSING Stop[*] ${CLAUDE_PROJECT_DIR}/.claude/hooks/does-not-exist.sh  - file not found: <repo>/examples/project/.claude/hooks/does-not-exist.sh
MISSING Notification[*] definitely-not-a-real-binary-xyz --notify  - not on PATH: definitely-not-a-real-binary-xyz

5 hook(s), 2 missing
```

Reads `~/.claude/settings.json`, `.claude/settings.json` and `.claude/settings.local.json`, expands
`${CLAUDE_PROJECT_DIR}`/env vars, resolves executables on `PATH` (with `PATHEXT` on Windows), checks the
script argument of interpreters (`bash x.sh`, `node x.js`, `python3 x.py`, ...) and the executable bit.
Exits `1` when something is missing. `--project dir`, `--json`.

## Programmatic API

```ts
import { buildPayload, runHook, runSuite, fuzzHook, scanSettings, validateOutput } from "hookfuzz";
import { test } from "node:test";
import assert from "node:assert/strict";

test("guard denies .env writes", async () => {
  const r = await runHook(["node", "hooks/guard.mjs"],
    buildPayload("PreToolUse", { tool: "Write", input: { file_path: ".env" } }));
  assert.equal(r.decision, "deny");
  assert.ok(r.validation?.valid);
});
```

Also exported: `bypassHook`, `bypassVariants`, `interpret`, `parseStdout`, `loadSpec`, `checkExpectation`, `fuzzCases`, `classify`,
`checkCommand`, `tokenize`, `findOnPath`, `quotePosixArg`, `quoteWindowsArg`, `quoteCmdArg`, `quoteCmdShimArg`,
`escapeCmdShimPath`, `resolveWindowsCommand`, `spawnSpec`, `killActiveHooks`, `EVENTS`, `BLOCKING_EVENTS`.

## Examples

`examples/hooks/` has real hooks in bash (`block-rm.sh`), Node (`guard.mjs`), Python (`prompt_filter.py`)
and a deliberately broken one (`buggy.mjs`); `examples/hookfuzz.yml` / `hookfuzz.posix.yml` are suites;
`examples/project/.claude/settings.json` is a scan target.

## Real-world example: guards from the dsh-* plugins

hookfuzz is not limited to native Claude Code hooks. Any guard with a pure "should this command run?" function can be wrapped in a small stdin adapter and tested the same way. We tried this on two command guards by [acus9345](https://github.com/acus9345). Both are DeepSeek Harness plugins, so we called their rule functions through a read-only adapter that turns a PreToolUse payload into a deny decision:

- [dsh-block-hanging-commands](https://github.com/acus9345/dsh-block-hanging-commands): blocks commands that would hang an agent's shell, such as editors, dev servers, `tail -f`, an interactive `git commit` and bare REPLs. Its parser sees through wrappers like `sudo`, `env`, `command` and `bash -c`, through quoting tricks, absolute paths, subshells and newline-chained commands.
- [dsh-block-secret-leaks](https://github.com/acus9345/dsh-guard-pack/tree/main/packages/dsh-block-secret-leaks), from dsh-guard-pack: blocks reading, copying, staging or uploading secret files like `.env`. It resolves quoted, escaped, absolute-path and `bash -c` forms of the command.

The adapters live in `examples/dsh-adapters/` of the hookfuzz source tree. They are not shipped in the npm package, and the source is not public yet. Point `DSH_TARGETS` at a folder that contains built clones of the repos:

```sh
export DSH_TARGETS=/path/to/clones   # holds dsh-block-hanging-commands/ and dsh-guard-pack/
hookfuzz bypass --command "tail -f app.log" -- node examples/dsh-adapters/hanging.mjs
hookfuzz bypass --command "cat .env" -- node examples/dsh-adapters/secrets.mjs
hookfuzz fuzz -- node examples/dsh-adapters/hanging.mjs
```

All 20 fuzz cases passed against both guards, with no crashes or hangs. The command variants are only ever placed in the stdin payload and are never executed.

## How this differs

| Tool | Runs hooks in any language as a black box | Declarative test specs | Fuzzing | Output schema validation | Settings scan |
| --- | --- | --- | --- | --- | --- |
| **hookfuzz** | yes, any command (shell or exec form) | YAML/JSON | yes, 20 malformed/edge cases, crash/hang/invalid-output verdicts | yes, per documented rules | yes, flags missing executables/scripts |
| [cc-hook-test](https://www.npmjs.com/package/cc-hook-test) ([GitHub](https://github.com/yurukusa/cc-hook-test)) | `.sh`/`.js`/`.py` only (picked by file extension) | JSON list; asserts exit code + stderr | no; auto-generates cases by grepping the script for keywords like `rm -rf` | no | no |
| [cc-hooks](https://github.com/basitalisandhu/cc-hooks) (Python, not on npm) | runs configured command hooks in dry-run mode; built around its Python SDK | recorded JSON payload fixtures | no | yes, via typed dataclasses and decision builders | yes, and stronger: merges settings and applies matchers (`explain`) |
| [auto-harness](https://github.com/zircote-plugins/auto-harness) (Claude Code plugin, not on npm) | no; tests drive Claude itself through a `UserPromptSubmit` hook | YAML/JSON | no | no | no |
| [claude-code-hook-tester](https://github.com/VoxCore84/claude-code-hook-tester) | `.py` hooks only | no (one mock payload per event) | no | JSON-parse check only | reads settings to map events |
| [@aeriondyseti/hook-kit](https://github.com/aeriondyseti/hook-kit) | no; in-process, only for hooks written with the library | code (vitest) | no | yes, for its own output | no |
| [vigiles](https://github.com/zernie/vigiles) | yes (`runHook`) | code files | no | asserts decisions | no |
| [crucible](https://github.com/klashkaan-cmyk/crucible) | no; runs real headless Claude sessions | YAML scenarios | no | no | no |

Of these, hookfuzz is the only one with a **policy-bypass fuzzer** (`hookfuzz bypass`), and the only one that combines black-box runs of any command, declarative specs,
a payload fuzzer and output validation against the documented rules in one zero-config npm CLI. Both fuzzers
(crash/hang and bypass) are things no other tool offers. If you want matcher-accurate "which hooks fire" analysis or a typed
Python SDK, use cc-hooks.

## Limitations

* Validates the documented JSON output fields for common events; less common event-specific fields are
  accepted with an "unknown field" warning rather than strict checking.
* Payloads are realistic but synthetic (the `transcript_path` file isn't created).
* Does not evaluate `matcher` / `if` filters, or run `http`, `mcp_tool`, `prompt` and `agent` hooks
  (scan lists them but cannot check them).
* Shell form uses `sh` / `cmd.exe`, while Claude Code on Windows prefers Git Bash: test bash-syntax
  hooks on Windows by passing `bash -c "..."` or exec form.

## License

MIT
