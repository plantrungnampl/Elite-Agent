import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertEvidenceOnlyChanges } from "./m2-evidence-worktree.mjs";
import { commands, containmentCases } from "./m2-evidence-spec.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const artifactRoot = join(root, "artifacts", "verification", "m2");
const outputRoot = join(artifactRoot, "outputs");
const manifestPath = join(artifactRoot, "manifest.json");
const temporaryManifestPath = `${manifestPath}.tmp`;
let isolatedTempRoot;

try {
  assertEvidenceOnlyChanges(root);
  mkdirSync(artifactRoot, { recursive: true });
  isolatedTempRoot = mkdtempSync(join(artifactRoot, ".tmp-"));
  process.env.TEMP = isolatedTempRoot;
  process.env.TMP = isolatedTempRoot;
  rmSync(outputRoot, { recursive: true, force: true });
  mkdirSync(outputRoot, { recursive: true });
  rmSync(join(artifactRoot, "post-final-contracts.log"), { force: true });
  rmSync(manifestPath, { force: true });
  rmSync(temporaryManifestPath, { force: true });

  const sourceCommit = commandOutput("git rev-parse HEAD");
  const toolVersions = currentToolVersions();
  writeFileSync(
    join(artifactRoot, "toolchain.txt"),
    `${Object.entries(toolVersions)
      .map(([name, value]) => `${name}=${value}`)
      .join("\n")}\n`,
  );

  const commandEvidence = [];
  for (const [name, command] of commands) {
    commandEvidence.push(await runCommand(name, command));
  }

  const manifest = {
    schemaVersion: 1,
    finalized: true,
    generatedAtUtc: new Date().toISOString(),
    sourceCommit,
    platform: `${process.platform}-${process.arch}`,
    outputCapture: "combined stdout/stderr bytes normalized to LF",
    toolVersions,
    commands: commandEvidence,
    containmentCases,
    artifactSha256: Object.fromEntries(
      ["review.md", "known-limitations.md", "toolchain.txt"].map((name) => [
        name,
        hash(readFileSync(join(artifactRoot, name))),
      ]),
    ),
  };
  writeFileSync(temporaryManifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  renameSync(temporaryManifestPath, manifestPath);
  console.log(`M2 evidence generated for ${sourceCommit}`);
} catch (error) {
  rmSync(temporaryManifestPath, { force: true });
  console.error(`M2 evidence generation failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  if (isolatedTempRoot !== undefined) {
    rmSync(isolatedTempRoot, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 200,
    });
  }
}

async function runCommand(name, command) {
  const startedAtUtc = new Date().toISOString();
  const started = process.hrtime.bigint();
  const chunks = [];
  const exitCode = await new Promise((resolveExit, reject) => {
    const child = spawn(command, {
      cwd: root,
      shell: true,
      windowsHide: true,
    });
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => {
        chunks.push(chunk);
        process.stdout.write(chunk);
      });
    }
    child.on("error", reject);
    child.on("close", (code) => resolveExit(code ?? 1));
  });
  const durationMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
  const output = normalizeOutput(Buffer.concat(chunks));
  const outputFile = `outputs/${name}.log`;
  writeFileSync(join(artifactRoot, outputFile), output);
  if (exitCode !== 0) throw new Error(`${command} exited with ${exitCode}`);
  if (output.toString("utf8").includes("# SKIP")) {
    throw new Error(`${command} skipped an approval-critical case`);
  }
  return {
    name,
    command,
    exitCode,
    startedAtUtc,
    durationMs,
    outputFile,
    outputSha256: hash(output),
  };
}

function currentToolVersions() {
  return {
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    node: process.version,
    pnpm: commandOutput("pnpm --version"),
    git: commandOutput("git --version"),
    rustup: commandOutput("rustup --version").split("\n")[0],
    rustToolchain: commandOutput("rustup show active-toolchain"),
    rustc: commandOutput("rustc --version"),
    cargo: commandOutput("cargo --version"),
  };
}

function commandOutput(command) {
  const result = spawnSync(command, {
    cwd: root,
    encoding: "utf8",
    shell: true,
    windowsHide: true,
  });
  if (result.status !== 0) throw new Error(`unable to run ${command}`);
  return result.stdout.trim();
}

function normalizeOutput(output) {
  const normalized = output.toString("utf8").replaceAll("\r\n", "\n");
  return Buffer.from(
    normalized.length === 0 ? "" : `${normalized.replace(/\n+$/u, "")}\n`,
    "utf8",
  );
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
