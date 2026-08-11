import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  commands,
  credentialCanary,
  designBaseline,
  verificationMatrices,
} from "./m4-evidence-spec.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const historical = process.argv.includes("--historical");
const requireApproved = process.argv.includes("--require-approved");
const manifestIndex = process.argv.indexOf("--manifest");
const manifestPath = manifestIndex === -1
  ? join(root, "artifacts", "verification", "m4", "manifest.json")
  : resolve(root, requiredArgument(manifestIndex + 1, "--manifest"));
const artifactRoot = dirname(manifestPath);
let activeArtifactRoot;

try {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  verifyManifest(manifest);
  process.stdout.write("M4 evidence: ok\n");
} catch (error) {
  process.stderr.write(`M4 evidence: ${error.message}\n`);
  process.exitCode = 1;
}

function verifyManifest(manifest) {
  check(isPlainObject(manifest), "manifest must be an object");
  check(manifest.schemaVersion === 1, "unsupported manifest schema");
  check(manifest.finalized === true, "manifest is not finalized");
  check(
    /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/u.test(manifest.sourceCommit),
    "invalid source commit",
  );
  activeArtifactRoot = resolveActiveArtifactRoot(manifest.evidenceRoot);
  verifySourceBinding(manifest.sourceCommit);
  verifyToolchain(manifest);
  verifyCommands(manifest);
  verifyMatrices(manifest);
  verifyCredentialCanary(manifest);
  verifyArtifacts(manifest);
  verifyReview(manifest);
  rejectCredentialCanaryLeaks();
  verifyEvidenceTreeShape(manifest);
}

function resolveActiveArtifactRoot(evidenceRoot) {
  check(
    typeof evidenceRoot === "string" &&
      /^\.generations\/\d{13}-[0-9a-f]{24}$/u.test(evidenceRoot),
    "unsafe active evidence generation",
  );
  const candidate = resolve(artifactRoot, evidenceRoot);
  check(isContained(artifactRoot, candidate), "active evidence generation escapes root");
  check(realDirectory(candidate), "active evidence generation is not a real directory");
  return candidate;
}

function verifyToolchain(manifest) {
  check(manifest.platform === `${process.platform}-${process.arch}`, "platform mismatch");
  check(isPlainObject(manifest.toolVersions), "tool versions must be an object");
  check(
    Object.keys(manifest.toolVersions).join(",") === "node,pnpm,rustc,cargo",
    "tool versions must be pinned exactly",
  );
  for (const [name, version] of Object.entries(manifest.toolVersions)) {
    check(typeof version === "string" && version.length > 0, `missing ${name} version`);
  }
  if (!historical) {
    assert.deepEqual(manifest.toolVersions, currentToolVersions(), "toolchain mismatch");
  }
  check(
    manifest.outputCapture === "combined stdout/stderr bytes normalized to LF",
    "unsupported output capture",
  );
}

function verifyCommands(manifest) {
  check(Array.isArray(manifest.commands), "commands must be an array");
  check(manifest.commands.length === commands.length, "command count mismatch");
  const generatedAt = timestamp(manifest.generatedAtUtc, "manifest timestamp");
  const expectedOutputs = new Set();

  for (const [index, entry] of manifest.commands.entries()) {
    const [expectedName, expectedCommand] = commands[index];
    check(isPlainObject(entry), `invalid command entry ${index}`);
    check(entry.name === expectedName, `command order mismatch at ${expectedName}`);
    check(entry.command === expectedCommand, `command text mismatch: ${expectedName}`);
    check(entry.approvalCritical === true, `command is not approval-critical: ${expectedName}`);
    check(entry.exitCode === 0, `failed command: ${expectedName}`);
    check(entry.skipped === 0, `skipped approval-critical tests: ${expectedName}`);
    check(
      entry.outputFile === `outputs/${expectedName}.log`,
      `invalid output path: ${expectedName}`,
    );
    check(/^[0-9a-f]{64}$/u.test(entry.outputSha256), `invalid output hash: ${expectedName}`);
    check(Number.isSafeInteger(entry.durationMs) && entry.durationMs >= 0, `invalid duration: ${expectedName}`);
    const startedAt = timestamp(entry.startedAtUtc, `command timestamp: ${expectedName}`);
    check(startedAt <= generatedAt + 1_000, `manifest predates command: ${expectedName}`);
    const outputPath = activePath(entry.outputFile);
    check(realFile(outputPath), `missing retained output: ${expectedName}`);
    const bytes = readFileSync(outputPath);
    check(!bytes.includes(13), `retained output is not LF-normalized: ${expectedName}`);
    check(hash(bytes) === entry.outputSha256, `output hash mismatch: ${expectedName}`);
    check(!hasSkippedTests(bytes.toString("utf8")), `skipped tests in output: ${expectedName}`);
    expectedOutputs.add(resolve(outputPath));
  }

  const actualOutputs = collectFiles(join(activeArtifactRoot, "outputs"));
  assert.deepEqual(new Set(actualOutputs), expectedOutputs, "retained output set mismatch");
}

function verifyMatrices(manifest) {
  assert.deepEqual(
    manifest.verificationMatrices,
    verificationMatrices,
    "verification matrices mismatch",
  );
  const commandEntries = new Map(manifest.commands.map((entry) => [entry.name, entry]));
  for (const matrix of verificationMatrices) {
    check(matrix.evidence.length > 0, `empty verification matrix: ${matrix.name}`);
    for (const evidence of matrix.evidence) {
      const command = commandEntries.get(evidence.command);
      check(command, `matrix references unknown command: ${evidence.command}`);
      const output = readFileSync(activePath(command.outputFile), "utf8");
      check(
        output.includes(evidence.needle),
        `matrix evidence missing for ${matrix.name}: ${evidence.needle}`,
      );
    }
  }
}

function verifyCredentialCanary(manifest) {
  const canary = manifest.credentialCanary;
  check(isPlainObject(canary), "missing credential canary proof");
  check(canary.markerPrefix === credentialCanary.markerPrefix, "credential canary prefix mismatch");
  check(/^[0-9a-f]{64}$/u.test(canary.sha256), "invalid credential canary hash");
  check(canary.absentFromCapturedEvidence === true, "credential canary absence is unproven");
}

function verifyArtifacts(manifest) {
  const expected = ["review.md", "known-limitations.md", "toolchain.txt"];
  check(isPlainObject(manifest.artifactSha256), "missing retained artifact hashes");
  assert.deepEqual(Object.keys(manifest.artifactSha256).sort(), expected.slice().sort(), "artifact hash set mismatch");
  for (const name of expected) {
    const path = name === "toolchain.txt" ? activePath(name) : rootArtifactPath(name);
    check(realFile(path), `missing retained artifact: ${name}`);
    const bytes = readFileSync(path);
    check(!bytes.includes(13), `retained artifact is not LF-normalized: ${name}`);
    check(hash(bytes) === manifest.artifactSha256[name], `artifact hash mismatch: ${name}`);
  }
  check(
    readFileSync(activePath("toolchain.txt"), "utf8") === canonicalToolchain(manifest.toolVersions),
    "noncanonical toolchain serialization",
  );
}

function verifyReview(manifest) {
  const review = readFileSync(rootArtifactPath("review.md"), "utf8");
  check(review.startsWith("# M4 independent review\n\n"), "invalid review heading");
  const reviewedSource = reviewValue(review, "Reviewed source commit", /^(?:PENDING|[0-9a-f]{40}(?:[0-9a-f]{24})?)$/u);
  const verdicts = ["Independent approval", "Spec compliance", "Code quality"]
    .map((heading) => reviewValue(review, heading, /^(?:PENDING|PASS)$/u));
  check(/^## Critical findings$/mu.test(review), "missing Critical findings heading");
  check(/^## Important findings$/mu.test(review), "missing Important findings heading");
  if (requireApproved) {
    check(reviewedSource === manifest.sourceCommit, "reviewed source commit mismatch");
    check(verdicts.every((verdict) => verdict === "PASS"), "independent approval is PENDING");
    check(emptyFindingSection(review, "Critical findings"), "unresolved Critical findings");
    check(emptyFindingSection(review, "Important findings"), "unresolved Important findings");
  }
}

function rejectCredentialCanaryLeaks() {
  const marker = new RegExp(`${escapeRegExp(credentialCanary.markerPrefix)}[A-Za-z0-9_-]+`, "u");
  for (const path of collectFiles(artifactRoot)) {
    if (marker.test(readFileSync(path, "utf8"))) {
      throw new Error(`credential canary leaked in ${relative(artifactRoot, path)}`);
    }
  }
}

function verifyEvidenceTreeShape(manifest) {
  const allowedRootFiles = new Set(["manifest.json", "review.md", "known-limitations.md"]);
  for (const entry of readdirSync(artifactRoot, { withFileTypes: true })) {
    if (entry.name === ".generations") continue;
    check(entry.isFile() && allowedRootFiles.has(entry.name), `unexpected retained M4 artifact: ${entry.name}`);
  }
  const generationFiles = new Set(collectFiles(activeArtifactRoot).map((path) => relative(activeArtifactRoot, path).replaceAll("\\", "/")));
  const expected = new Set([
    "toolchain.txt",
    ...manifest.commands.map((entry) => entry.outputFile),
  ]);
  assert.deepEqual(generationFiles, expected, "active generation file set mismatch");
}

function verifySourceBinding(sourceCommit) {
  if (historical) return;
  commandMustPass("git", ["cat-file", "-e", `${sourceCommit}^{commit}`], "source commit is unavailable");
  commandMustPass("git", ["merge-base", "--is-ancestor", sourceCommit, "HEAD"], "source commit is not an ancestor of HEAD");
  commandMustPass(
    "git",
    ["diff", "--exit-code", designBaseline, "--", "docs/multi-agent-terminal-design"],
    "immutable design proof failed",
  );
  const dirty = gitPaths(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    .filter((path) => !isAllowedBindingPath(path));
  check(dirty.length === 0, `dirty tracked source: ${dirty.join(", ")}`);
}

function activePath(relativePath) {
  check(typeof relativePath === "string" && !isAbsolute(relativePath), "unsafe active artifact path");
  const candidate = resolve(activeArtifactRoot, relativePath);
  check(isContained(activeArtifactRoot, candidate), "active artifact path escapes generation");
  return candidate;
}

function rootArtifactPath(name) {
  const candidate = resolve(artifactRoot, name);
  check(isContained(artifactRoot, candidate), "root artifact path escapes evidence root");
  return candidate;
}

function collectFiles(directory) {
  check(realDirectory(directory), `evidence directory is not real: ${directory}`);
  const files = [];
  const pending = [directory];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      const metadata = lstatSync(path);
      check(!metadata.isSymbolicLink(), `evidence contains symlink or reparse point: ${path}`);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile()) files.push(resolve(path));
      else throw new Error(`unsupported evidence entry: ${path}`);
    }
  }
  return files;
}

function realDirectory(path) {
  try {
    return !lstatSync(path).isSymbolicLink() && statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function realFile(path) {
  try {
    return !lstatSync(path).isSymbolicLink() && statSync(path).isFile();
  } catch {
    return false;
  }
}

function reviewValue(review, heading, pattern) {
  const matches = [...review.matchAll(new RegExp(`^## ${escapeRegExp(heading)}: (.+)$`, "gmu"))];
  check(matches.length === 1 && pattern.test(matches[0][1]), `invalid ${heading}`);
  return matches[0][1];
}

function emptyFindingSection(review, heading) {
  const lines = review.split("\n");
  const headingIndex = lines.indexOf(`## ${heading}`);
  if (headingIndex === -1) return false;
  const nextHeading = lines.findIndex(
    (line, index) => index > headingIndex && line.startsWith("## "),
  );
  const end = nextHeading === -1 ? lines.length : nextHeading;
  return lines.slice(headingIndex + 1, end).join("\n").trim() === "None.";
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
  check(result.status === 0, `unable to read ${command} version`);
  return result.stdout.trim();
}

function commandMustPass(command, arguments_, message) {
  const result = spawnSync(command, arguments_, { cwd: root, encoding: "utf8", windowsHide: true });
  check(result.status === 0, `${message}: ${result.stdout}${result.stderr}`);
}

function gitPaths(arguments_) {
  const result = spawnSync("git", arguments_, { cwd: root, encoding: "buffer", windowsHide: true });
  check(result.status === 0, `git status failed: ${result.stderr.toString("utf8")}`);
  const records = result.stdout.toString("utf8").split("\0").filter(Boolean);
  return records.map((record) => record.slice(3).replaceAll("\\", "/"));
}

function isAllowedBindingPath(path) {
  return path.startsWith("artifacts/verification/m4/") ||
    path === "docs/superpowers/plans/2026-07-23-m4-context-deliberation.md" ||
    path === ".superpowers/sdd/progress.md";
}

function canonicalToolchain(toolVersions) {
  return Object.entries(toolVersions).map(([name, version]) => `${name}=${version}\n`).join("");
}

function hasSkippedTests(output) {
  return /(?:# skipped |\b)(?:[1-9]\d*)\s+(?:skipped|ignored)\b/iu.test(output) ||
    /# skipped (?:[1-9]\d*)\b/iu.test(output);
}

function timestamp(value, description) {
  const parsed = Date.parse(value);
  check(Number.isFinite(parsed), `invalid ${description}`);
  return parsed;
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isContained(parent, candidate) {
  const path = relative(resolve(parent), resolve(candidate));
  return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function requiredArgument(index, option) {
  const value = process.argv[index];
  check(typeof value === "string" && !value.startsWith("--"), `${option} requires a path`);
  return value;
}

function check(condition, message) {
  if (!condition) throw new Error(message);
}
