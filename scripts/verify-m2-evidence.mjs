import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertEvidenceOnlyChanges } from "./m2-evidence-worktree.mjs";
import { commands as requiredCommandEntries, containmentCases } from "./m2-evidence-spec.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifestArgument = process.argv.indexOf("--manifest");
const manifestPath =
  manifestArgument === -1
    ? join(root, "artifacts", "verification", "m2", "manifest.json")
    : resolve(root, process.argv[manifestArgument + 1]);
const artifactRoot = dirname(manifestPath);
const requiredCommands = new Map(requiredCommandEntries);
const requireApproved = process.argv.includes("--require-approved");

try {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  assert(manifest.schemaVersion === 1, "unsupported manifest schema");
  assert(manifest.finalized === true, "manifest is not finalized");
  assert(/^([0-9a-f]{40}|[0-9a-f]{64})$/u.test(manifest.sourceCommit), "invalid source commit");
  verifyCommitBinding(manifest.sourceCommit);
  assert(manifest.platform === `${process.platform}-${process.arch}`, "platform mismatch");
  assertDeepEqual(manifest.toolVersions, currentToolVersions(), "toolchain mismatch");

  assert(Array.isArray(manifest.commands), "commands must be an array");
  assert(manifest.commands.length === requiredCommands.size, "unexpected command evidence count");
  const commands = new Map();
  for (const entry of manifest.commands) {
    assert(!commands.has(entry.name), `duplicate command evidence: ${entry.name}`);
    commands.set(entry.name, entry);
  }
  const generatedAt = Date.parse(manifest.generatedAtUtc);
  assert(!Number.isNaN(generatedAt), "invalid manifest timestamp");
  for (const [name, command] of requiredCommands) {
    const entry = commands.get(name);
    assert(entry, `missing command evidence: ${name}`);
    assert(entry.command === command, `command mismatch: ${name}`);
    assert(entry.exitCode === 0, `command did not pass: ${command}`);
    assert(
      Number.isInteger(entry.durationMs) && entry.durationMs >= 0,
      `invalid duration: ${command}`,
    );
    const started = Date.parse(entry.startedAtUtc);
    assert(!Number.isNaN(started), `invalid timestamp: ${command}`);
    assert(
      started + entry.durationMs <= generatedAt + 1_000,
      `manifest predates command: ${command}`,
    );
    assert(
      /^outputs\/[a-z0-9-]+\.log$/u.test(entry.outputFile),
      `invalid output path: ${command}`,
    );
    const output = readFileSync(join(artifactRoot, entry.outputFile));
    assert(entry.outputSha256 === hash(output), `output hash mismatch: ${command}`);
    assert(!hasSkippedTests(output.toString("utf8")), `command skipped a case: ${command}`);
  }

  assertDeepEqual(
    manifest.containmentCases,
    containmentCases,
    "containment case mismatch",
  );
  for (const containmentCase of containmentCases) {
    for (const item of containmentCase.evidence) {
      const command = commands.get(item.command);
      const output = readFileSync(join(artifactRoot, command.outputFile), "utf8");
      assert(
        output.includes(item.needle),
        `containment evidence not observed: ${containmentCase.case} -> ${item.needle}`,
      );
    }
  }

  for (const file of ["review.md", "known-limitations.md", "toolchain.txt"]) {
    assert(
      manifest.artifactSha256[file] === hash(readFileSync(join(artifactRoot, file))),
      `artifact hash mismatch: ${file}`,
    );
  }
  const review = readFileSync(join(artifactRoot, "review.md"), "utf8");
  const independentVerdict = reviewVerdict(review, "Independent approval");
  const specVerdict = reviewVerdict(review, "Spec compliance");
  const codeVerdict = reviewVerdict(review, "Code quality");
  if (requireApproved) {
    assert(independentVerdict === "PASS", "independent approval is pending");
    assert(specVerdict === "PASS", "spec compliance is pending");
    assert(codeVerdict === "PASS", "code quality is pending");
    const reviewedSource = review.match(
      /^## Reviewed source commit: ([0-9a-f]{40}|[0-9a-f]{64})$/mu,
    )?.[1];
    assert(reviewedSource === manifest.sourceCommit, "reviewed source commit mismatch");
  }
  assert(
    readFileSync(join(artifactRoot, "known-limitations.md"), "utf8").trim().length > 0,
    "known limitations are absent",
  );
  console.log("M2 evidence: ok");
} catch (error) {
  console.error(`M2 evidence: ${error.message}`);
  process.exitCode = 1;
}

function verifyCommitBinding(sourceCommit) {
  assertEvidenceOnlyChanges(root);
  const head = commandOutput("git rev-parse HEAD");
  if (head === sourceCommit) return;
  const ancestor = spawnSync("git", ["merge-base", "--is-ancestor", sourceCommit, head], {
    cwd: root,
    windowsHide: true,
  });
  assert(ancestor.status === 0, "evidence source commit is not an ancestor of HEAD");
  const changed = commandOutput(`git diff --name-only ${sourceCommit}..${head}`)
    .split(/\r?\n/u)
    .filter(Boolean);
  assert(
    changed.length > 0 &&
      changed.every((path) => path.startsWith("artifacts/verification/m2/")),
    "evidence source commit is stale for the current code",
  );
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

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function hasSkippedTests(output) {
  return (
    output.includes("# SKIP") ||
    /\b[1-9]\d*\s+(?:ignored|skipped)\b/u.test(output) ||
    /\bskipped\s+[1-9]\d*\b/u.test(output)
  );
}

function reviewVerdict(review, heading) {
  const verdict = review.match(
    new RegExp(`^## ${heading}: (PENDING|PASS)$`, "mu"),
  )?.[1];
  assert(verdict !== undefined, `invalid ${heading.toLowerCase()} verdict`);
  return verdict;
}

function assertDeepEqual(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), message);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
