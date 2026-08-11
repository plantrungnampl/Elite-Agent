import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  commands,
  credentialCanary,
  verificationMatrices,
} from "./m4-evidence-spec.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const artifactRoot = join(root, "artifacts", "verification", "m4");
const generationsRoot = join(artifactRoot, ".generations");
const generationName = `${Date.now()}-${randomBytes(12).toString("hex")}`;
const evidenceRoot = `.generations/${generationName}`;
const stagingRoot = join(artifactRoot, `.staging-${generationName}`);
const finalRoot = join(generationsRoot, generationName);
const manifestPath = join(artifactRoot, "manifest.json");
const temporaryManifestPath = `${manifestPath}.tmp`;

try {
  assertEvidenceOnlyChanges();
  ensureReviewArtifacts();
  mkdirSync(join(stagingRoot, "outputs"), { recursive: true });
  const sourceCommit = commandOutput("git rev-parse HEAD");
  const toolVersions = currentToolVersions();
  writeFileSync(join(stagingRoot, "toolchain.txt"), canonicalToolchain(toolVersions));
  const canaryValue = `${credentialCanary.markerPrefix}${randomBytes(24).toString("hex")}`;
  const commandEvidence = [];

  for (const [name, command] of commands) {
    process.stdout.write(`M4 evidence: running ${name}\n`);
    commandEvidence.push(runCommand(name, command, canaryValue));
  }

  verifyMatrices(commandEvidence);
  verifyCanaryAbsence(stagingRoot, canaryValue);
  const generatedAtUtc = new Date().toISOString();
  const manifest = {
    schemaVersion: 1,
    finalized: true,
    generatedAtUtc,
    sourceCommit,
    evidenceRoot,
    platform: `${process.platform}-${process.arch}`,
    outputCapture: "combined stdout/stderr bytes normalized to LF",
    toolVersions,
    commands: commandEvidence,
    verificationMatrices,
    credentialCanary: {
      markerPrefix: credentialCanary.markerPrefix,
      sha256: hash(Buffer.from(canaryValue)),
      absentFromCapturedEvidence: true,
    },
    artifactSha256: {
      "review.md": hash(readFileSync(join(artifactRoot, "review.md"))),
      "known-limitations.md": hash(readFileSync(join(artifactRoot, "known-limitations.md"))),
      "toolchain.txt": hash(readFileSync(join(stagingRoot, "toolchain.txt"))),
    },
  };

  mkdirSync(generationsRoot, { recursive: true });
  renameSync(stagingRoot, finalRoot);
  writeFileSync(temporaryManifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  renameSync(temporaryManifestPath, manifestPath);
  verifyCanaryAbsence(artifactRoot, canaryValue);
  process.stdout.write(`M4 evidence generated at ${relative(root, manifestPath)}\n`);
} catch (error) {
  rmSync(stagingRoot, { recursive: true, force: true });
  rmSync(temporaryManifestPath, { force: true });
  process.stderr.write(`M4 evidence failed: ${error.message}\n`);
  process.exitCode = 1;
}

function runCommand(name, command, canaryValue) {
  const startedAtUtc = new Date().toISOString();
  const startedAt = Date.now();
  const result = spawnSync(command, {
    cwd: root,
    encoding: "buffer",
    env: {
      ...process.env,
      M4_EVIDENCE_CREDENTIAL_CANARY: canaryValue,
    },
    maxBuffer: 128 * 1024 * 1024,
    shell: true,
    windowsHide: true,
  });
  const output = normalizeOutput(Buffer.concat([
    result.stdout ?? Buffer.alloc(0),
    result.stderr ?? Buffer.alloc(0),
  ]));
  const outputFile = `outputs/${name}.log`;
  writeFileSync(join(stagingRoot, outputFile), output);
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${name} exited with ${result.status}; inspect ${outputFile}`);
  }
  if (hasSkippedTests(output.toString("utf8"))) {
    throw new Error(`${name} reported skipped approval-critical tests`);
  }
  return {
    name,
    command,
    approvalCritical: true,
    exitCode: result.status,
    skipped: 0,
    startedAtUtc,
    durationMs: Date.now() - startedAt,
    outputFile,
    outputSha256: hash(output),
  };
}

function verifyMatrices(commandEvidence) {
  const byName = new Map(commandEvidence.map((entry) => [entry.name, entry]));
  for (const matrix of verificationMatrices) {
    for (const evidence of matrix.evidence) {
      const command = byName.get(evidence.command);
      if (!command) throw new Error(`unknown matrix command: ${evidence.command}`);
      const output = readFileSync(join(stagingRoot, command.outputFile), "utf8");
      if (!output.includes(evidence.needle)) {
        throw new Error(`missing ${matrix.name} evidence: ${evidence.needle}`);
      }
    }
  }
}

function verifyCanaryAbsence(directory, canaryValue) {
  for (const path of collectFiles(directory)) {
    if (readFileSync(path, "utf8").includes(canaryValue)) {
      throw new Error(`credential canary leaked in ${relative(directory, path)}`);
    }
  }
}

function ensureReviewArtifacts() {
  mkdirSync(artifactRoot, { recursive: true });
  for (const name of ["review.md", "known-limitations.md"]) {
    const path = join(artifactRoot, name);
    try {
      readFileSync(path);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      throw new Error(`missing required review artifact: ${name}`);
    }
  }
}

function assertEvidenceOnlyChanges() {
  const paths = new Set([
    ...gitPaths(["diff", "--name-only", "-z"]),
    ...gitPaths(["diff", "--cached", "--name-only", "-z"]),
    ...gitPaths(["ls-files", "--others", "--exclude-standard", "-z"]),
  ]);
  const unexpected = [...paths].filter((path) => !isAllowedBindingPath(path));
  if (unexpected.length > 0) {
    throw new Error(`source commit is not cleanly bound; dirty source: ${unexpected.join(", ")}`);
  }
}

function isAllowedBindingPath(path) {
  const normalized = path.replaceAll("\\", "/");
  return normalized.startsWith("artifacts/verification/m4/") ||
    normalized === "docs/superpowers/plans/2026-07-23-m4-context-deliberation.md" ||
    normalized === ".superpowers/sdd/progress.md";
}

function gitPaths(arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: root,
    encoding: "buffer",
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`unable to inspect worktree: git ${arguments_.join(" ")}`);
  }
  return result.stdout.toString("utf8").split("\0").filter(Boolean);
}

function currentToolVersions() {
  return {
    node: process.version,
    pnpm: commandOutput("pnpm --version"),
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
  const text = output.toString("utf8").replace(/\r\n|\r/gu, "\n");
  return Buffer.from(text.length === 0 ? "" : `${text.replace(/\n+$/u, "")}\n`, "utf8");
}

function collectFiles(directory) {
  const files = [];
  const pending = [resolve(directory)];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`evidence contains symlink: ${path}`);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile()) files.push(path);
      else throw new Error(`unsupported evidence entry: ${path}`);
    }
  }
  return files;
}

function canonicalToolchain(toolVersions) {
  return Object.entries(toolVersions).map(([name, version]) => `${name}=${version}\n`).join("");
}

function hasSkippedTests(output) {
  return /(?:# skipped |\b)(?:[1-9]\d*)\s+(?:skipped|ignored)\b/iu.test(output) ||
    /# skipped (?:[1-9]\d*)\b/iu.test(output);
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}
