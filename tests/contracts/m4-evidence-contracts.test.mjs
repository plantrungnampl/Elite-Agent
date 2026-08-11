import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  commands,
  credentialCanary,
  designBaseline,
  verificationMatrices,
} from "../../scripts/m4-evidence-spec.mjs";

const requiredMatrices = [
  "m0-m3-regressions",
  "context-security",
  "retrieval-freshness",
  "two-provider-conformance",
  "deliberation-recovery",
  "ui-browser-accessibility",
  "exact-plan-approval",
  "repository-no-mutation",
];

test("M4 evidence spec covers every approval-critical gate", () => {
  assert.equal(designBaseline, "9b182a3");
  assert.deepEqual(
    verificationMatrices.map(({ name }) => name),
    requiredMatrices,
  );
  assert.equal(new Set(commands.map(([name]) => name)).size, commands.length);
  assert.deepEqual(
    commands.find(([name]) => name === "design-docs-unchanged"),
    [
      "design-docs-unchanged",
      `git diff --exit-code ${designBaseline} -- docs/multi-agent-terminal-design`,
    ],
  );
  for (const name of [
    "source-contracts",
    "architecture",
    "rust-format",
    "rust-check",
    "rust-clippy",
    "rust-tests-all-targets",
    "rust-tests-all-features",
    "rust-doc",
    "frontend-tests",
    "frontend-build",
    "browser-accessibility",
    "desktop-debug-build",
  ]) {
    assert.ok(commands.some(([commandName]) => commandName === name), name);
  }
});

test("M4 runner publishes a source-bound generation that the verifier accepts", () => {
  const directory = mkdtempSync(join(tmpdir(), "m4-runner-"));
  try {
    createRunnerFixture(directory);
    const generated = spawnSync(process.execPath, [join(directory, "scripts", "run-m4-evidence.mjs")], {
      cwd: directory,
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(generated.status, 0, `${generated.stdout}${generated.stderr}`);
    const manifestPath = join(directory, "artifacts", "verification", "m4", "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.sourceCommit, gitOutput(directory, "rev-parse", "HEAD"));
    const verified = spawnSync(
      process.execPath,
      [
        join(directory, "scripts", "verify-m4-evidence.mjs"),
        "--historical",
        "--manifest",
        manifestPath,
      ],
      { cwd: directory, encoding: "utf8", windowsHide: true },
    );
    assert.equal(verified.status, 0, `${verified.stdout}${verified.stderr}`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("M4 verifier accepts complete hashed historical evidence", () => {
  withEvidenceFixture((directory) => {
    const result = runVerifier(directory, "--historical");
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(`${result.stdout}${result.stderr}`, /M4 evidence: ok/u);
  });
});

test("M4 verifier rejects invalid source binding and retained-output tampering", () => {
  withEvidenceFixture((directory, manifest) => {
    manifest.sourceCommit = "not-a-commit";
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /source commit/u);
  });

  withEvidenceFixture((directory, manifest) => {
    const output = join(directory, manifest.evidenceRoot, manifest.commands[0].outputFile);
    writeFileSync(output, "tampered\n");
    assertVerifierFails(directory, /output hash/u);
  });
});

test("M4 verifier rejects failed or skipped approval-critical commands", () => {
  withEvidenceFixture((directory, manifest) => {
    manifest.commands[0].exitCode = 1;
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /failed command/u);
  });

  withEvidenceFixture((directory, manifest) => {
    const entry = manifest.commands[0];
    const output = join(directory, manifest.evidenceRoot, entry.outputFile);
    writeFileSync(output, "# skipped 1\n");
    entry.outputSha256 = hash(readFileSync(output));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /skipped/u);
  });
});

test("M4 verifier rejects incomplete matrices and credential canary leakage", () => {
  withEvidenceFixture((directory, manifest) => {
    manifest.verificationMatrices.pop();
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /verification matrices/u);
  });

  withEvidenceFixture((directory, manifest) => {
    const entry = manifest.commands[0];
    const output = join(directory, manifest.evidenceRoot, entry.outputFile);
    writeFileSync(output, `${credentialCanary.markerPrefix}LEAK\n`);
    entry.outputSha256 = hash(readFileSync(output));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /credential canary/u);
  });
});

test("final M4 approval binds review to source and requires no important findings", () => {
  withEvidenceFixture((directory) => {
    const pending = runVerifier(directory, "--historical", "--require-approved");
    assert.notEqual(pending.status, 0);
    assert.match(`${pending.stdout}${pending.stderr}`, /approval|PENDING|reviewed source/u);
  });

  withEvidenceFixture((directory, manifest) => {
    const reviewPath = join(directory, "review.md");
    writeFileSync(reviewPath, approvedReview(manifest.sourceCommit));
    manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
    writeManifest(directory, manifest);
    const approved = runVerifier(directory, "--historical", "--require-approved");
    assert.equal(approved.status, 0, `${approved.stdout}${approved.stderr}`);
  });

  withEvidenceFixture((directory, manifest) => {
    const reviewPath = join(directory, "review.md");
    writeFileSync(
      reviewPath,
      approvedReview(manifest.sourceCommit).replace(
        "## Important findings\n\nNone.",
        "## Important findings\n\n- Evidence gap.",
      ),
    );
    manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
    writeManifest(directory, manifest);
    const result = runVerifier(directory, "--historical", "--require-approved");
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /Important findings/u);
  });
});

function withEvidenceFixture(callback) {
  const directory = mkdtempSync(join(tmpdir(), "m4-evidence-"));
  try {
    callback(directory, createEvidenceFixture(directory));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function createRunnerFixture(directory) {
  const scripts = join(directory, "scripts");
  const evidence = join(directory, "artifacts", "verification", "m4");
  mkdirSync(scripts, { recursive: true });
  mkdirSync(evidence, { recursive: true });
  copyFileSync("scripts/run-m4-evidence.mjs", join(scripts, "run-m4-evidence.mjs"));
  copyFileSync("scripts/verify-m4-evidence.mjs", join(scripts, "verify-m4-evidence.mjs"));
  writeFileSync(
    join(scripts, "m4-evidence-spec.mjs"),
    `export const designBaseline = "HEAD";\nexport const commands = [["probe", "node -e \\"process.stdout.write('runner-probe\\\\n')\\""]];\nexport const verificationMatrices = [{ name: "probe", evidence: [{ command: "probe", needle: "runner-probe" }] }];\nexport const credentialCanary = { markerPrefix: "M4_CREDENTIAL_CANARY_" };\n`,
  );
  writeFileSync(join(evidence, "review.md"), pendingReview());
  writeFileSync(join(evidence, "known-limitations.md"), "Fixture runner limitations.\n");
  runGit(directory, "init");
  runGit(directory, "config", "user.email", "m4-fixture@example.invalid");
  runGit(directory, "config", "user.name", "M4 fixture");
  runGit(directory, "add", ".");
  runGit(directory, "commit", "-m", "fixture");
}

function createEvidenceFixture(directory) {
  const evidenceRoot = ".generations/1700000000000-0123456789abcdef01234567";
  const generation = join(directory, evidenceRoot);
  const outputs = join(generation, "outputs");
  mkdirSync(outputs, { recursive: true });
  const generatedAtUtc = new Date().toISOString();
  const sourceCommit = "0123456789abcdef0123456789abcdef01234567";
  const toolVersions = currentToolVersions();
  const outputText = new Map(commands.map(([name]) => [name, `${name} passed\n`]));
  for (const matrix of verificationMatrices) {
    for (const evidence of matrix.evidence) {
      outputText.set(
        evidence.command,
        `${outputText.get(evidence.command)}${evidence.needle}\n`,
      );
    }
  }
  const commandEvidence = commands.map(([name, command]) => {
    const outputFile = `outputs/${name}.log`;
    const outputPath = join(generation, outputFile);
    writeFileSync(outputPath, outputText.get(name));
    return {
      name,
      command,
      approvalCritical: true,
      exitCode: 0,
      skipped: 0,
      startedAtUtc: generatedAtUtc,
      durationMs: 0,
      outputFile,
      outputSha256: hash(readFileSync(outputPath)),
    };
  });

  writeFileSync(join(directory, "review.md"), pendingReview());
  writeFileSync(
    join(directory, "known-limitations.md"),
    "Fixture-only M4 evidence for verifier mutation tests.\n",
  );
  writeFileSync(join(generation, "toolchain.txt"), canonicalToolchain(toolVersions));

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
    verificationMatrices: structuredClone(verificationMatrices),
    credentialCanary: {
      markerPrefix: credentialCanary.markerPrefix,
      sha256: hash(Buffer.from("fixture-canary-value")),
      absentFromCapturedEvidence: true,
    },
    artifactSha256: {
      "review.md": hash(readFileSync(join(directory, "review.md"))),
      "known-limitations.md": hash(readFileSync(join(directory, "known-limitations.md"))),
      "toolchain.txt": hash(readFileSync(join(generation, "toolchain.txt"))),
    },
  };
  writeManifest(directory, manifest);
  return manifest;
}

function pendingReview() {
  return "# M4 independent review\n\n## Reviewed source commit: PENDING\n\n## Independent approval: PENDING\n\n## Spec compliance: PENDING\n\n## Code quality: PENDING\n\n## Critical findings\n\nNone.\n\n## Important findings\n\nNone.\n";
}

function approvedReview(sourceCommit) {
  return pendingReview()
    .replace("Reviewed source commit: PENDING", `Reviewed source commit: ${sourceCommit}`)
    .replaceAll(": PENDING", ": PASS");
}

function writeManifest(directory, manifest) {
  writeFileSync(join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function runVerifier(directory, ...arguments_) {
  return spawnSync(
    process.execPath,
    ["scripts/verify-m4-evidence.mjs", ...arguments_, "--manifest", join(directory, "manifest.json")],
    { cwd: process.cwd(), encoding: "utf8", windowsHide: true },
  );
}

function assertVerifierFails(directory, pattern) {
  const result = runVerifier(directory, "--historical");
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, pattern);
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
    cwd: process.cwd(),
    encoding: "utf8",
    windowsHide: true,
    shell: true,
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  return result.stdout.trim();
}

function runGit(directory, ...arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: directory,
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
}

function gitOutput(directory, ...arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: directory,
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  return result.stdout.trim();
}

function canonicalToolchain(toolVersions) {
  return Object.entries(toolVersions)
    .map(([name, version]) => `${name}=${version}\n`)
    .join("");
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}
