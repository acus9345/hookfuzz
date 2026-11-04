export { buildPayload, deepMerge, type PayloadOptions } from "./payload.js";
export { runHook, interpret, quotePosixArg, quoteWindowsArg, quoteCmdArg, quoteCmdShimArg, escapeCmdShimPath, resolveWindowsCommand, spawnSpec, killActiveHooks, type SpawnSpec, type HookResult, type RunOptions, type Decision } from "./runner.js";
export { parseStdout, validateOutput, type ParsedStdout, type ValidationResult } from "./schema.js";
export { loadSpec, runSuite, validateSpec, checkExpectation, matchText, type Spec, type TestCase, type Expectation, type SuiteResult, type CaseResult } from "./spec.js";
export { fuzzHook, fuzzCases, classify, type FuzzReport, type FuzzFinding, type FuzzVerdict } from "./fuzz.js";
export { scanSettings, settingsFiles, checkCommand, tokenize, findOnPath, type ScanResult, type ScannedHook } from "./scan.js";
export { EVENTS, TOOL_EVENTS, BLOCKING_EVENTS, isToolEvent, normalizeEvent, type HookEvent } from "./events.js";
export { bypassHook, bypassVariants, type BypassReport, type BypassFinding, type BypassVariant } from "./bypass.js";
