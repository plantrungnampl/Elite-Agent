import { createHash, randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  lstatSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  commands,
  credentialCanary,
  verificationMatrices,
} from "./m3-evidence-spec.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const artifactRoot = join(root, "artifacts", "verification", "m3");
const manifestPath = join(artifactRoot, "manifest.json");
const temporaryManifestPath = `${manifestPath}.tmp`;
const allowedGeneratedPath = /^artifacts\/verification\/m3(?:\/|$)/u;
const allowedPlanPath =
  "docs/superpowers/plans/2026-07-23-m3-protocol-adapter.md";

let stagingRoot;
let isolatedTempRoot;
let temporaryManifestCreated = false;
let pendingGenerationPath;
let activeManifestCommitted = false;
let originalTemp;
let originalTmp;
let originalTmpdir;
let tempEnvironmentCaptured = false;

try {
  assertEvidenceOnlyChanges();

  stagingRoot = mkdtempSync(join(os.tmpdir(), "m3-evidence-stage-"));
  const stagedOutputRoot = join(stagingRoot, "outputs");
  mkdirSync(stagedOutputRoot, { recursive: true });
  isolatedTempRoot = mkdtempSync(join(os.tmpdir(), "m3-evidence-tmp-"));
  ({ originalTemp, originalTmp, originalTmpdir } = captureTempEnvironment());
  tempEnvironmentCaptured = true;
  process.env.TEMP = isolatedTempRoot;
  process.env.TMP = isolatedTempRoot;
  process.env.TMPDIR = isolatedTempRoot;

  const sourceCommit = commandOutput("git rev-parse HEAD");
  const toolVersions = currentToolVersions();
  const rawCanary = `${credentialCanary.markerPrefix}${randomBytes(24).toString("hex")}`;
  const canaryPattern = new RegExp(
    `${escapeRegExp(credentialCanary.markerPrefix)}[A-Za-z0-9][A-Za-z0-9_-]*`,
    "gu",
  );
  const childEnvironment = {
    ...process.env,
    OPENAI_API_KEY: rawCanary,
    TEMP: isolatedTempRoot,
    TMP: isolatedTempRoot,
    TMPDIR: isolatedTempRoot,
  };

  writeFileSync(
    join(stagingRoot, "toolchain.txt"),
    `${Object.entries(toolVersions)
      .map(([name, value]) => `${name}=${value}`)
      .join("\n")}\n`,
  );

  const commandEvidence = [];
  for (const [name, command] of commands) {
    commandEvidence.push(
      await runCommand({
        name,
        command,
        childEnvironment,
        canaryPattern,
        outputRoot: stagedOutputRoot,
      }),
    );
  }

  verifyMatrices(commandEvidence, stagedOutputRoot);
  verifyRetainedEvidence(stagingRoot, canaryPattern);

  const artifactSha256 = Object.fromEntries(
    ["review.md", "known-limitations.md", "toolchain.txt"].map((name) => {
      const path = name === "toolchain.txt" ? join(stagingRoot, name) : join(artifactRoot, name);
      return [name, hash(readFileSync(path))];
    }),
  );
  const manifest = {
    schemaVersion: 1,
    finalized: true,
    generatedAtUtc: new Date().toISOString(),
    sourceCommit,
    platform: `${process.platform}-${process.arch}`,
    outputCapture: "combined stdout/stderr bytes normalized to LF",
    toolVersions,
    commands: commandEvidence,
    verificationMatrices,
    credentialCanary: {
      markerPrefix: credentialCanary.markerPrefix,
      sha256: hash(Buffer.from(rawCanary, "utf8")),
      absentFromCapturedEvidence: true,
    },
    artifactSha256,
  };

  publishArtifacts(stagingRoot, manifest);
  console.log(`M3 evidence generated for ${sourceCommit}`);
} catch (error) {
  if (temporaryManifestCreated) {
    rmSync(temporaryManifestPath, { force: true });
  }
  if (pendingGenerationPath !== undefined && !activeManifestCommitted) {
    rmSync(pendingGenerationPath, { recursive: true, force: true });
  }
  console.error(`M3 evidence generation failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  restoreTempEnvironment();
  if (isolatedTempRoot !== undefined) {
    rmSync(isolatedTempRoot, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 200,
    });
  }
  if (stagingRoot !== undefined) {
    rmSync(stagingRoot, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 200,
    });
  }
}

async function runCommand({
  name,
  command,
  childEnvironment,
  canaryPattern,
  outputRoot: stagedOutputRoot,
}) {
  console.log(`M3 evidence command: ${name}`);
  const startedAtUtc = new Date().toISOString();
  const started = process.hrtime.bigint();
  const chunks = [];
  const exitCode = await new Promise((resolveExit, reject) => {
    const child = spawn(command, {
      cwd: root,
      env: childEnvironment,
      shell: true,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    }
    child.on("error", reject);
    child.on("close", (code) => resolveExit(code ?? 1));
  });
  const durationMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
  const normalizedOutput = normalizeOutput(Buffer.concat(chunks));
  const outputText = normalizedOutput.toString("utf8");
  const canaryFound = canaryPattern.test(outputText);
  canaryPattern.lastIndex = 0;
  const safeOutput = canaryFound
    ? Buffer.from(outputText.replace(canaryPattern, "[REDACTED_CREDENTIAL_CANARY]"), "utf8")
    : normalizedOutput;
  const outputFile = `outputs/${name}.log`;
  writeFileSync(join(stagedOutputRoot, `${name}.log`), safeOutput);
  process.stdout.write(safeOutput);

  if (canaryFound) {
    throw new Error(`credential canary marker observed in command output: ${name}`);
  }
  if (exitCode !== 0) {
    throw new Error(`command failed: ${name} (exit ${exitCode})`);
  }
  if (hasSkippedTests(outputText)) {
    throw new Error(`command skipped an approval-critical case: ${name}`);
  }

  return {
    name,
    command,
    exitCode,
    startedAtUtc,
    durationMs,
    outputFile,
    outputSha256: hash(safeOutput),
  };
}

function verifyMatrices(commandEvidence, stagedOutputRoot) {
  const outputByCommand = new Map(commandEvidence.map((entry) => [entry.name, entry]));
  for (const matrix of verificationMatrices) {
    if (!Array.isArray(matrix.evidence) || matrix.evidence.length === 0) {
      throw new Error(`matrix has no evidence: ${matrix.name}`);
    }
    for (const evidence of matrix.evidence) {
      const command = outputByCommand.get(evidence.command);
      if (command === undefined) {
        throw new Error(`matrix command missing: ${matrix.name} -> ${evidence.command}`);
      }
      const output = readFileSync(join(stagedOutputRoot, command.name + ".log"), "utf8");
      if (!output.includes(evidence.needle)) {
        throw new Error(`matrix evidence not observed: ${matrix.name} -> ${evidence.needle}`);
      }
    }
  }
}

function verifyRetainedEvidence(stagedRoot, canaryPattern) {
  const retainedFiles = [
    ...collectEvidenceFiles(artifactRoot),
    ...collectEvidenceFiles(join(stagedRoot, "outputs")),
    join(stagedRoot, "toolchain.txt"),
  ];
  for (const file of retainedFiles) {
    const contents = readFileSync(file, "utf8");
    canaryPattern.lastIndex = 0;
    if (canaryPattern.test(contents)) {
      throw new Error(`credential canary leaked in ${relativePath(file)}`);
    }
  }
}

function publishArtifacts(stagedRoot, manifest) {
  const generationName = `.generations/${Date.now()}-${randomBytes(12).toString("hex")}`;
  const generationPath = join(artifactRoot, generationName);
  pendingGenerationPath = generationPath;
  mkdirSync(join(generationPath, "outputs"), { recursive: true });
  for (const file of collectEvidenceFiles(join(stagedRoot, "outputs"))) {
    copyFileSync(
      file,
      join(generationPath, "outputs", file.slice(join(stagedRoot, "outputs").length + 1)),
    );
  }
  copyFileSync(join(stagedRoot, "toolchain.txt"), join(generationPath, "toolchain.txt"));

  if (process.env.M3_EVIDENCE_INJECT_PUBLISH_FAILURE === "after-generation") {
    throw new Error("injected publication failure after generation staging");
  }

  temporaryManifestCreated = true;
  writeFileSync(
    temporaryManifestPath,
    `${JSON.stringify({ ...manifest, evidenceRoot: generationName }, null, 2)}\n`,
  );
  renameSync(temporaryManifestPath, manifestPath);
  temporaryManifestCreated = false;
  activeManifestCommitted = true;
}

function assertEvidenceOnlyChanges() {
  const paths = new Set([
    ...gitPaths(["diff", "--name-only", "-z"]),
    ...gitPaths(["diff", "--cached", "--name-only", "-z"]),
    ...gitPaths(["ls-files", "--others", "--exclude-standard", "-z"]),
  ]);
  const sourceChanges = [...paths]
    .map((path) => path.replaceAll("\\", "/"))
    .filter(
      (path) =>
        path.length > 0 &&
        !allowedGeneratedPath.test(path) &&
        path !== allowedPlanPath,
    );
  if (sourceChanges.length > 0) {
    throw new Error(`dirty tracked source: ${sourceChanges.sort().join(", ")}`);
  }
}

function gitPaths(arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`unable to inspect worktree: git ${arguments_.join(" ")}`);
  }
  return result.stdout.split("\0");
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
  if (result.status !== 0) {
    throw new Error(`unable to run ${command}`);
  }
  return result.stdout.trim();
}

function normalizeOutput(output) {
  const normalized = output.toString("utf8").replace(/\r\n|\r/gu, "\n");
  return Buffer.from(
    normalized.length === 0 ? "" : `${normalized.replace(/\n+$/u, "")}\n`,
    "utf8",
  );
}

function collectEvidenceFiles(directory) {
  const files = [];
  if (!existsSync(directory)) return files;
  const directoryMetadata = lstatSync(directory);
  if (directoryMetadata.isSymbolicLink()) {
    throw new Error(`evidence tree contains a symlink or junction: ${relativePath(directory)}`);
  }
  if (!directoryMetadata.isDirectory()) {
    throw new Error(`evidence tree root is not a directory: ${relativePath(directory)}`);
  }
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(`evidence tree contains a symlink or junction: ${relativePath(path)}`);
    }
    if (metadata.isDirectory()) files.push(...collectEvidenceFiles(path));
    else if (metadata.isFile()) files.push(path);
    else throw new Error(`unsupported evidence tree entry: ${relativePath(path)}`);
  }
  return files;
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function hasSkippedTests(output) {
  return (
    output.includes("# SKIP") ||
    /\b[1-9]\d*\s+(?:ignored|skipped)\b/iu.test(output) ||
    /\bskipped\s+[1-9]\d*\b/iu.test(output)
  );
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function captureTempEnvironment() {
  return {
    originalTemp: process.env.TEMP,
    originalTmp: process.env.TMP,
    originalTmpdir: process.env.TMPDIR,
  };
}

function restoreTempEnvironment() {
  if (!tempEnvironmentCaptured) return;
  if (originalTemp === undefined) delete process.env.TEMP;
  else process.env.TEMP = originalTemp;
  if (originalTmp === undefined) delete process.env.TMP;
  else process.env.TMP = originalTmp;
  if (originalTmpdir === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = originalTmpdir;
}

function relativePath(path) {
  return path.startsWith(root) ? path.slice(root.length + 1).replaceAll("\\", "/") : path;
}
