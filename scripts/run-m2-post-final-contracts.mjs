import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const outputPath = join(
  root,
  "artifacts",
  "verification",
  "m2",
  "post-final-contracts.log",
);
const chunks = [];

const exitCode = await new Promise((resolveExit, reject) => {
  const child = spawn(
    process.execPath,
    ["--test", "tests/contracts/m2-evidence-contracts.test.mjs"],
    { cwd: root, windowsHide: true },
  );
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => {
      chunks.push(chunk);
      process.stdout.write(chunk);
    });
  }
  child.on("error", reject);
  child.on("close", (code) => resolveExit(code ?? 1));
});

const raw = Buffer.concat(chunks).toString("utf8").replaceAll("\r\n", "\n");
const normalized = raw.length === 0 ? "" : `${raw.replace(/\n+$/u, "")}\n`;
writeFileSync(outputPath, normalized);
if (exitCode !== 0) process.exitCode = exitCode;
