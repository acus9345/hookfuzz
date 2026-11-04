// Runs every compiled build-test/test/*.test.js. `node --test` only expands glob patterns itself
// from Node 21 on, and cmd.exe/PowerShell never expand them, so list the files here (Node 20 support).
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const files = readdirSync(dir).filter((f) => f.endsWith(".test.js")).sort().map((f) => join(dir, f));
const r = spawnSync(process.execPath, ["--test", "--test-reporter=spec", ...files], { stdio: "inherit" });
process.exit(r.status ?? 1);
