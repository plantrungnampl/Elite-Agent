import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import os from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  commands as requiredCommandEntries,
  credentialCanary,
  verificationMatrices,
} from "./m3-evidence-spec.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const historical = process.argv.includes("--historical");
const requireApproved = process.argv.includes("--require-approved");
const manifestArgument = process.argv.indexOf("--manifest");
const manifestPath =
  manifestArgument === -1
    ? join(root, "artifacts", "verification", "m3", "manifest.json")
    : resolve(root, process.argv[manifestArgument + 1]);
const artifactRoot = dirname(manifestPath);
let activeArtifactRoot = artifactRoot;
const allowedGeneratedPath =
  /^artifacts\/verification\/m3(?:\/|$)/u;
const allowedPlanPath =
  "docs/superpowers/plans/2026-07-23-m3-protocol-adapter.md";

try {
  assert(
    !(historical && requireApproved),
    "--historical cannot be combined with --require-approved",
  );
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  verifyManifest(manifest);
  console.log("M3 evidence: ok");
} catch (error) {
  console.error(`M3 evidence: ${error.message}`);
  process.exitCode = 1;
}

function verifyManifest(manifest) {
  assert(manifest && typeof manifest === "object" && !Array.isArray(manifest), "manifest must be an object");
  assert(manifest.schemaVersion === 1, "unsupported manifest schema");
  assert(manifest.finalized === true, "manifest is not finalized");
  activeArtifactRoot = resolveActiveArtifactRoot(manifest);
  assert(/^([0-9a-f]{40}|[0-9a-f]{64})$/u.test(manifest.sourceCommit), "invalid source commit");
  verifyCommitBinding(manifest.sourceCommit);
  assert(manifest.platform === `${process.platform}-${process.arch}`, "platform mismatch");
  assertDeepEqual(manifest.toolVersions, currentToolVersions(), "toolchain mismatch");
  assert(
    manifest.outputCapture === "combined stdout/stderr bytes normalized to LF",
    "output capture mismatch",
  );

  verifyCommands(manifest);
  verifyMatrices(manifest);
  verifyCredentialCanary(manifest);
  verifyArtifacts(manifest);
  verifyReview(manifest);
  rejectCredentialCanaryLeaks(manifest);
}

function resolveActiveArtifactRoot(manifest) {
  if (manifest.evidenceRoot === undefined) return artifactRoot;
  assert(
    typeof manifest.evidenceRoot === "string" && manifest.evidenceRoot.length > 0,
    "invalid active evidence root",
  );
  const candidate = resolve(artifactRoot, manifest.evidenceRoot);
  assert(
    isContainedPath(artifactRoot, candidate),
    "active evidence root escapes artifact root",
  );
  assert(statSync(candidate).isDirectory(), "active evidence root is not a directory");
  return candidate;
}

function verifyCommands(manifest) {
  assert(Array.isArray(manifest.commands), "commands must be an array");
  assert(
    manifest.commands.length === requiredCommandEntries.length,
    "unexpected command evidence count",
  );

  const commandNames = new Set();
  const outputFiles = new Set();
  const generatedAt = parseTimestamp(manifest.generatedAtUtc, "manifest timestamp");

  manifest.commands.forEach((entry, index) => {
    assert(entry && typeof entry === "object" && !Array.isArray(entry), "invalid command evidence");
    const [expectedName, expectedCommand] = requiredCommandEntries[index];
    assert(!commandNames.has(entry.name), `duplicate command evidence: ${entry.name}`);
    assert(entry.name === expectedName, `command order mismatch: expected ${expectedName}`);
    commandNames.add(entry.name);
    assert(entry.command === expectedCommand, `command mismatch: ${entry.name}`);
    assert(
      !/(?:run|verify)-m3-evidence\.mjs/u.test(entry.command),
      "verifier may not attest itself",
    );
    assert(entry.exitCode === 0, `command did not pass: ${entry.name}`);
    assert(Number.isInteger(entry.durationMs) && entry.durationMs >= 0, `invalid duration: ${entry.name}`);
    const startedAt = parseTimestamp(entry.startedAtUtc, `command timestamp: ${entry.name}`);
    assert(startedAt <= generatedAt, `command starts after manifest: ${entry.name}`);
    assert(startedAt + entry.durationMs <= generatedAt + 1_000, `manifest predates command: ${entry.name}`);
    const expectedOutputFile = `outputs/${entry.name}.log`;
    assert(entry.outputFile === expectedOutputFile, `output path mismatch: ${entry.name}`);
    assert(!outputFiles.has(entry.outputFile), `duplicate output path: ${entry.outputFile}`);
    outputFiles.add(entry.outputFile);

    const outputPath = resolveArtifactPath(entry.outputFile);
    const output = readFileSync(outputPath);
    assert(!output.includes(13), `output is not normalized to LF: ${entry.name}`);
    assert(entry.outputSha256 === hash(output), `output hash mismatch: ${entry.name}`);
    assert(!hasSkippedTests(output.toString("utf8")), `command skipped a case: ${entry.name}`);
  });

  const expectedOutputs = manifest.commands
    .map((entry) => entry.outputFile)
    .sort();
  const outputDirectory = resolveArtifactPath("outputs");
  assert(statSync(outputDirectory).isDirectory(), "active output root is not a directory");
  const actualOutputs = collectFiles(outputDirectory)
    .map((path) => relativeArtifactPath(path))
    .sort();
  assertDeepEqual(
    actualOutputs,
    expectedOutputs,
    "unexpected retained output set",
  );
}

function verifyMatrices(manifest) {
  assert(Array.isArray(manifest.verificationMatrices), "verification matrices must be an array");
  assertDeepEqual(
    manifest.verificationMatrices,
    verificationMatrices,
    "verification matrix mismatch: matrix evidence definition",
  );

  const commands = new Map(manifest.commands.map((entry) => [entry.name, entry]));
  for (const matrix of verificationMatrices) {
    assert(Array.isArray(matrix.evidence) && matrix.evidence.length > 0, `matrix has no evidence: ${matrix.name}`);
    for (const evidence of matrix.evidence) {
      const command = commands.get(evidence.command);
      assert(command, `matrix command missing: ${matrix.name} -> ${evidence.command}`);
      const output = readFileSync(resolveArtifactPath(command.outputFile), "utf8");
      assert(
        output.includes(evidence.needle),
        `matrix evidence not observed: ${matrix.name} -> ${evidence.needle}`,
      );
    }
  }
}

function verifyCredentialCanary(manifest) {
  const canary = manifest.credentialCanary;
  assert(canary && typeof canary === "object" && !Array.isArray(canary), "credential canary metadata is missing");
  assert(canary.markerPrefix === credentialCanary.markerPrefix, "credential canary marker mismatch");
  assert(/^sha256:[0-9a-f]{64}$/u.test(canary.sha256), "credential canary digest mismatch");
  assert(canary.absentFromCapturedEvidence === true, "credential canary absence was not attested");
}

function verifyArtifacts(manifest) {
  const artifactHashes = manifest.artifactSha256;
  assert(artifactHashes && typeof artifactHashes === "object" && !Array.isArray(artifactHashes), "artifact hashes are missing");
  assertDeepEqual(
    Object.keys(artifactHashes).sort(),
    ["known-limitations.md", "review.md", "toolchain.txt"],
    "unexpected artifact hash set",
  );

  for (const file of ["review.md", "known-limitations.md", "toolchain.txt"]) {
    const path = resolveArtifactPath(file);
    const contents = readFileSync(path);
    assert(artifactHashes[file] === hash(contents), `artifact hash mismatch: ${file}`);
  }

  assert(
    readFileSync(resolveArtifactPath("toolchain.txt"), "utf8") ===
      canonicalToolchain(manifest.toolVersions),
    "toolchain serialization is not canonical",
  );

  const limitations = readFileSync(resolveArtifactPath("known-limitations.md"), "utf8");
  assert(limitations.trim().length > 0, "known limitations are absent");
  assert(readFileSync(resolveArtifactPath("toolchain.txt"), "utf8").trim().length > 0, "toolchain artifact is absent");
}

function verifyReview(manifest) {
  const review = readFileSync(resolveArtifactPath("review.md"), "utf8");
  assert(review.startsWith("# M3 independent review\n\n"), "invalid review heading");
  const reviewedSource = reviewHeading(
    review,
    "Reviewed source commit",
    /^(?:PENDING|[0-9a-f]{40}|[0-9a-f]{64})$/u,
  );
  const independentVerdict = reviewHeading(review, "Independent approval", /^(?:PENDING|PASS)$/u);
  const specVerdict = reviewHeading(review, "Spec compliance", /^(?:PENDING|PASS)$/u);
  const codeVerdict = reviewHeading(review, "Code quality", /^(?:PENDING|PASS)$/u);
  assert(/^## Critical findings$/mu.test(review), "missing Critical findings heading");
  assert(/^## Important findings$/mu.test(review), "missing Important findings heading");

  if (requireApproved) {
    assert(independentVerdict === "PASS", "independent approval is pending");
    assert(specVerdict === "PASS", "spec compliance is pending");
    assert(codeVerdict === "PASS", "code quality is pending");
    assert(reviewedSource === manifest.sourceCommit, "reviewed source commit mismatch");
    assertReviewSectionIsEmpty(review, "Critical findings");
    assertReviewSectionIsEmpty(review, "Important findings");
  }
}

function assertReviewSectionIsEmpty(review, heading) {
  const lines = review.split(/\r?\n/u);
  const headingLine = `## ${heading}`;
  const start = lines.indexOf(headingLine);
  assert(start !== -1, `missing ${heading.toLowerCase()} heading`);
  const end = lines.findIndex((line, index) => index > start && line.startsWith("## "));
  const body = lines.slice(start + 1, end === -1 ? lines.length : end).join("\n").trim();
  assert(/^None\.?$/u.test(body), `${heading} must be None for approval`);
}

function reviewHeading(review, heading, valuePattern) {
  const matches = [...review.matchAll(new RegExp(`^## ${heading}: (.+)$`, "gmu"))];
  assert(matches.length === 1, `invalid ${heading.toLowerCase()} heading`);
  const value = matches[0][1];
  assert(valuePattern.test(value), `invalid ${heading.toLowerCase()} verdict`);
  return value;
}

function rejectCredentialCanaryLeaks(manifest) {
  const markerPattern = new RegExp(`${escapeRegExp(credentialCanary.markerPrefix)}[A-Za-z0-9][A-Za-z0-9_-]*`, "u");
  const files = collectFiles(activeArtifactRoot);
  for (const file of files) {
    const contents = readFileSync(file, "utf8");
    assert(!markerPattern.test(contents), `credential canary leaked in ${relativeArtifactPath(file)}`);
  }

  const serializedManifest = JSON.stringify(manifest);
  assert(!markerPattern.test(serializedManifest), "credential canary leaked in manifest fields");
}

function verifyCommitBinding(sourceCommit) {
  const head = commandOutput("git rev-parse HEAD");
  const ancestor = spawnSync("git", ["merge-base", "--is-ancestor", sourceCommit, head], {
    cwd: root,
    windowsHide: true,
  });
  assert(ancestor.status === 0, "evidence source commit is not an ancestor of HEAD");
  if (historical) return;

  if (head !== sourceCommit) {
    const changed = commandOutput(`git diff --name-only ${sourceCommit}..${head}`)
      .split(/\r?\n/u)
      .filter(Boolean)
      .map((path) => path.replaceAll("\\", "/"));
    assert(
      changed.length > 0 && changed.every(isAllowedCurrentBindingPath),
      "evidence source commit is stale for the current code",
    );
  }

  assertEvidenceOnlyChanges();
}

function assertEvidenceOnlyChanges() {
  const paths = new Set([
    ...gitPaths(["diff", "--name-only", "-z"]),
    ...gitPaths(["diff", "--cached", "--name-only", "-z"]),
    ...gitPaths(["ls-files", "--others", "--exclude-standard", "-z"]),
  ]);
  const sourceChanges = [...paths]
    .map((path) => path.replaceAll("\\", "/"))
    .filter((path) => path.length > 0 && !isAllowedCurrentBindingPath(path));
  assert(sourceChanges.length === 0, `dirty tracked source: ${sourceChanges.sort().join(", ")}`);
}

function isAllowedCurrentBindingPath(path) {
  return allowedGeneratedPath.test(path) || path === allowedPlanPath;
}

function gitPaths(arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
  });
  assert(result.status === 0, `unable to inspect worktree: git ${arguments_.join(" ")}`);
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
  assert(result.status === 0, `unable to run ${command}`);
  return result.stdout.trim();
}

function parseTimestamp(value, description) {
  assert(typeof value === "string", `invalid ${description}`);
  const parsed = Date.parse(value);
  assert(!Number.isNaN(parsed), `invalid ${description}`);
  return parsed;
}

function resolveArtifactPath(relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  const path = resolve(activeArtifactRoot, normalized);
  assert(
    isContainedPath(activeArtifactRoot, path),
    `invalid artifact path: ${relativePath}`,
  );
  return path;
}

function collectFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) files.push(...collectFiles(path));
    else if (statSync(path).isFile()) files.push(path);
  }
  return files;
}

function relativeArtifactPath(path) {
  return relative(activeArtifactRoot, path).replaceAll("\\", "/");
}

function isContainedPath(parent, candidate) {
  const relation = relative(parent, candidate);
  return relation.length === 0 || (!relation.startsWith("..") && !isAbsolute(relation));
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

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalToolchain(toolVersions) {
  return `${Object.entries(toolVersions)
    .map(([name, value]) => `${name}=${value}`)
    .join("\n")}\n`;
}

function assertDeepEqual(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), message);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
