import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os, { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  commands,
  credentialCanary,
  verificationMatrices,
} from "../../scripts/m3-evidence-spec.mjs";

const requiredMatrices = [
  "protocol-schema-conformance",
  "hostile-protocol",
  "fake-agent-runtime",
  "openai-loopback",
  "persistence-recovery",
  "provider-neutral-credentials",
];

test("M3 evidence is complete and internally consistent", () => {
  const result = runVerifier();
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(`${result.stdout}${result.stderr}`, /M3 evidence: ok/u);
});

test("M3 verifier rejects an absent manifest", () => {
  const directory = mkdtempSync(join(tmpdir(), "m3-missing-manifest-"));
  try {
    assertVerifierFailsAt(
      join(directory, "manifest.json"),
      /manifest|ENOENT|MODULE_NOT_FOUND|unable to read/u,
      [],
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("M3 verifier rejects unsupported or non-finalized manifests", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.schemaVersion = 999;
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /unsupported manifest schema|schema/u);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.finalized = false;
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /manifest is not finalized|finalized/u);
  });
});

test("M3 verifier rejects historical final approval mode", () => {
  withEvidenceCopy((directory) => {
    assertVerifierFails(
      directory,
      /historical.*require-approved|require-approved.*historical|cannot be combined/u,
      ["--historical", "--require-approved"],
    );
  });
});

test("M3 verifier rejects modified captured output and retained artifacts", () => {
  withEvidenceCopy((directory, manifest) => {
    appendFileSync(activeEvidencePath(directory, manifest, manifest.commands[0].outputFile), "tampered\n");
    assertVerifierFails(directory, /output hash mismatch/u);
  });
  for (const file of ["review.md", "known-limitations.md", "toolchain.txt"]) {
    withEvidenceCopy((directory, manifest) => {
      appendFileSync(
        file === "toolchain.txt"
          ? activeEvidencePath(directory, manifest, file)
          : join(directory, file),
        "tampered\n",
      );
      assertVerifierFails(directory, /artifact hash mismatch/u);
    });
  }
});

test("M3 verifier rejects retained outputs outside the active command set", () => {
  withEvidenceCopy((directory, manifest) => {
    writeFileSync(
      activeEvidencePath(directory, manifest, "outputs/unexpected.log"),
      "unattested output\n",
    );
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /unexpected retained output|output set|unexpected output/u);
  });
});

test("M3 verifier rejects noncanonical toolchain serialization", () => {
  withEvidenceCopy((directory, manifest) => {
    const toolchainPath = activeEvidencePath(directory, manifest, "toolchain.txt");
    writeFileSync(toolchainPath, `${JSON.stringify(manifest.toolVersions)}\n`);
    manifest.artifactSha256["toolchain.txt"] = hash(readFileSync(toolchainPath));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /canonical toolchain|toolchain serialization|toolchain artifact/u);
  });
});

test("M3 verifier requires a safe active generation and exact generation files", () => {
  for (const evidenceRoot of [
    undefined,
    ".generations/fixture",
    "generations/not-active",
    ".generations/active/extra",
    ".generations/../review.md",
  ]) {
    withEvidenceCopy((directory, manifest) => {
      if (evidenceRoot === undefined) delete manifest.evidenceRoot;
      else manifest.evidenceRoot = evidenceRoot;
      writeManifest(directory, manifest);
      assertVerifierFails(directory, /active evidence root|evidenceRoot|generation/u);
    });
  }
  withEvidenceCopy((directory, manifest) => {
    writeFileSync(join(directory, manifest.evidenceRoot, "review.md"), "override\n");
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /active generation file set|unexpected retained output|generation/u);
  });
});

test("M3 verifier scans inactive evidence and rejects evidence-tree symlinks", () => {
  withEvidenceCopy((directory, manifest) => {
    const inactiveOutput = join(directory, ".generations", "inactive", "outputs");
    mkdirSync(inactiveOutput, { recursive: true });
    writeFileSync(
      join(inactiveOutput, "leak.log"),
      `${credentialCanary.markerPrefix}INACTIVE_LEAK\n`,
    );
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /credential canary leaked|canary/u);
  });
  withEvidenceCopy((directory, manifest) => {
    const outside = mkdtempSync(join(tmpdir(), "m3-symlink-target-"));
    try {
      const link = join(directory, ".generations", "inactive-link");
      symlinkSync(outside, link, "junction");
      writeManifest(directory, manifest);
      assertVerifierFails(directory, /symlink|junction|reparse|evidence tree/u);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
  withEvidenceCopy((directory, manifest) => {
    const outside = mkdtempSync(join(tmpdir(), "m3-nested-symlink-target-"));
    try {
      const activeRoot = join(directory, manifest.evidenceRoot);
      const link = join(activeRoot, "nested-link");
      symlinkSync(outside, link, "junction");
      writeManifest(directory, manifest);
      assertVerifierFails(directory, /symlink|junction|reparse|evidence tree/u);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
});

test("M3 verifier rejects missing, duplicate, failed, and reordered commands", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.commands.pop();
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /unexpected command evidence count|missing command/u);
  });
  withEvidenceCopy((directory, manifest) => {
    assert.ok(manifest.commands.length > 1, "M3 evidence must retain multiple commands");
    manifest.commands[1].name = manifest.commands[0].name;
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /duplicate command evidence/u);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.commands[0].exitCode = 1;
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /command did not pass/u);
  });
  withEvidenceCopy((directory, manifest) => {
    const first = manifest.commands[0];
    const second = manifest.commands[1];
    manifest.commands[0] = second;
    manifest.commands[1] = first;
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /command order|unexpected command|command mismatch/u);
  });
});

test("M3 verifier rejects native skipped-test summaries", () => {
  for (const summary of [
    "test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured\n",
    "  1 skipped\n",
    "      Tests  1 skipped (1)\n",
  ]) {
    withEvidenceCopy((directory, manifest) => {
      const entry = manifest.commands[0];
      const outputPath = activeEvidencePath(directory, manifest, entry.outputFile);
      appendFileSync(outputPath, summary);
      entry.outputSha256 = hash(readFileSync(outputPath));
      writeManifest(directory, manifest);
      assertVerifierFails(directory, /command skipped a case|skipped/u);
    });
  }
});

test("M3 verifier rejects platform and toolchain drift", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.platform = "other-platform";
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /platform mismatch/u);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.toolVersions.node = "node changed";
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /toolchain mismatch/u);
  });
});

test("M3 verifier rejects missing and altered verification matrices", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.verificationMatrices.pop();
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /verification matrix|matrix count|missing matrix/u);
  });
  for (const name of requiredMatrices) {
    withEvidenceCopy((directory, manifest) => {
      const matrix = manifest.verificationMatrices.find((entry) => entry.name === name);
      assert.ok(matrix, `missing required test fixture matrix: ${name}`);
      assert.ok(matrix.evidence?.length > 0, `matrix has no evidence: ${name}`);
      matrix.evidence[0].needle = "unobserved_m3_matrix_test";
      writeManifest(directory, manifest);
      assertVerifierFails(directory, /matrix evidence|evidence not observed|needle/u);
    });
  }
});

test("M3 verifier rejects a captured credential-canary marker", () => {
  withEvidenceCopy((directory, manifest) => {
    const markerPrefix = manifest.credentialCanary?.markerPrefix;
    assert.equal(markerPrefix, "M3_CREDENTIAL_CANARY_");
    const entry = manifest.commands[0];
    const outputPath = activeEvidencePath(directory, manifest, entry.outputFile);
    appendFileSync(outputPath, `${markerPrefix}LEAK_TEST\n`);
    entry.outputSha256 = hash(readFileSync(outputPath));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /credential canary leaked|canary/u);
  });
  withEvidenceCopy((directory, manifest) => {
    const markerPrefix = manifest.credentialCanary?.markerPrefix;
    assert.equal(markerPrefix, "M3_CREDENTIAL_CANARY_");
    const reviewPath = join(directory, "review.md");
    appendFileSync(reviewPath, `${markerPrefix}LEAK_TEST\n`);
    manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /credential canary leaked|canary/u);
  });
});

test("final M3 verification rejects pending independent, spec, and code verdicts", () => {
  for (const heading of ["Independent approval", "Spec compliance", "Code quality"]) {
    withApprovedRunnerEvidence((directory, manifest, activeRoot, manifestPath) => {
      const reviewPath = join(directory, "artifacts", "verification", "m3", "review.md");
      const review = readFileSync(reviewPath, "utf8").replace(
        new RegExp(`(^## ${heading}: )PASS$`, "mu"),
        "$1PENDING",
      );
      writeFileSync(reviewPath, review);
      manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
      writeManifest(join(directory, "artifacts", "verification", "m3"), manifest);
      runGit(directory, ["add", "artifacts/verification/m3"]);
      runGit(directory, ["commit", "-m", `pending ${heading}`]);
      assertTempVerifierFails(
        directory,
        manifestPath,
        new RegExp(`${heading}.*pending|pending`, "iu"),
        ["--require-approved"],
      );
    });
  }
});

test("final M3 verification binds every verdict to the reviewed source", () => {
  withApprovedRunnerEvidence((directory, manifest, activeRoot, manifestPath) => {
    const reviewPath = join(directory, "artifacts", "verification", "m3", "review.md");
    const review = readFileSync(reviewPath, "utf8").replace(
      /^## Reviewed source commit: .+$/mu,
      `## Reviewed source commit: ${"0".repeat(40)}`,
    );
    writeFileSync(reviewPath, review);
    manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
    writeManifest(join(directory, "artifacts", "verification", "m3"), manifest);
    runGit(directory, ["add", "artifacts/verification/m3"]);
    runGit(directory, ["commit", "-m", "mismatched reviewed source"]);
    assertTempVerifierFails(directory, manifestPath, /reviewed source commit mismatch/u, [
      "--require-approved",
    ]);
  });
});

test("final M3 verification requires empty Critical and Important findings", () => {
  for (const heading of ["Critical findings", "Important findings"]) {
    withApprovedRunnerEvidence((directory, manifest, activeRoot, manifestPath) => {
      const reviewPath = join(directory, "artifacts", "verification", "m3", "review.md");
      const review = readFileSync(reviewPath, "utf8").replace(
        new RegExp(`(^## ${heading}\\n\\n)None\\.$`, "mu"),
        "$1Finding remains.",
      );
      writeFileSync(reviewPath, review);
      manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
      writeManifest(join(directory, "artifacts", "verification", "m3"), manifest);
      runGit(directory, ["add", "artifacts/verification/m3"]);
      runGit(directory, ["commit", "-m", `mutate ${heading}`]);
      assertTempVerifierFails(
        directory,
        manifestPath,
        new RegExp(`${heading}.*None|findings|approval`, "iu"),
        ["--require-approved"],
      );
    });
  }
});

test("root review artifacts are authoritative over generation contents", () => {
  withApprovedRunnerEvidence((directory, manifest, activeRoot, manifestPath) => {
    const rootReviewPath = join(directory, "artifacts", "verification", "m3", "review.md");
    const approvedRootReview = readFileSync(rootReviewPath, "utf8")
      .replace("Reviewed source commit: PENDING", `Reviewed source commit: ${manifest.sourceCommit}`)
      .replace("Independent approval: PENDING", "Independent approval: PASS")
      .replace("Spec compliance: PENDING", "Spec compliance: PASS")
      .replace("Code quality: PENDING", "Code quality: PASS");
    writeFileSync(rootReviewPath, approvedRootReview);
    manifest.artifactSha256["review.md"] = hash(readFileSync(rootReviewPath));
    writeManifest(join(directory, "artifacts", "verification", "m3"), manifest);
    runGit(directory, ["add", "artifacts/verification/m3"]);
    runGit(directory, ["commit", "-m", "approve root review"]);
    assertTempVerifierPasses(directory, manifestPath, ["--require-approved"]);

    writeFileSync(join(activeRoot, "review.md"), approvedRootReview);
    const pendingRootReview = approvedRootReview.replace(
      "Independent approval: PASS",
      "Independent approval: PENDING",
    );
    writeFileSync(rootReviewPath, pendingRootReview);
    manifest.artifactSha256["review.md"] = hash(readFileSync(rootReviewPath));
    writeManifest(join(directory, "artifacts", "verification", "m3"), manifest);
    runGit(directory, ["add", "artifacts/verification/m3"]);
    runGit(directory, ["commit", "-m", "contradict root review"]);
    assertTempVerifierFails(
      directory,
      manifestPath,
      /active generation file set|independent approval.*pending|pending/u,
      ["--require-approved"],
    );
  });
});

test("runner keeps the active evidence generation when publication fails", () => {
  const directory = mkdtempSync(join(tmpdir(), "m3-runner-transaction-"));
  try {
    createRunnerFixture(directory);
    const before = readActiveRunnerEvidence(directory);
    const result = spawnSync(process.execPath, [join(directory, "scripts", "run-m3-evidence.mjs")], {
      cwd: directory,
      encoding: "utf8",
      env: { ...process.env, M3_EVIDENCE_INJECT_PUBLISH_FAILURE: "after-generation" },
    });
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.deepEqual(readActiveRunnerEvidence(directory), before);
    assert.deepEqual(
      readdirSync(join(directory, "artifacts", "verification", "m3", ".generations"), {
        withFileTypes: true,
      }).map((entry) => entry.name),
      ["old"],
      "failed publication must remove the uncommitted generation",
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runner scans all retained evidence before publication", () => {
  const directory = mkdtempSync(join(tmpdir(), "m3-runner-canary-"));
  try {
    createRunnerFixture(directory);
    const inactiveOutput = join(
      directory,
      "artifacts",
      "verification",
      "m3",
      ".generations",
      "inactive",
      "outputs",
    );
    mkdirSync(inactiveOutput, { recursive: true });
    writeFileSync(
      join(inactiveOutput, "leak.log"),
      `${credentialCanary.markerPrefix}RUNNER_INACTIVE_LEAK\n`,
    );
    const result = spawnSync(process.execPath, [join(directory, "scripts", "run-m3-evidence.mjs")], {
      cwd: directory,
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(`${result.stdout}${result.stderr}`, /credential canary|canary/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("M3 verifier rejects stale and non-ancestor source commits in strict mode", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.sourceCommit = gitOutput("rev-parse", "HEAD~2");
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /stale for the current code|stale/u, []);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.sourceCommit = "0".repeat(40);
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /not an ancestor|ancestor/u, []);
  });
});

test("M3 verifier rejects dirty source and immutable design changes in strict mode", () => {
  for (const path of [
    "tests/contracts/fixtures/m3/agent-protocol-outward-metadata.json",
    "docs/multi-agent-terminal-design/schemas/README.md",
  ]) {
    withEvidenceCopy((directory) => {
      withDirtyFile(path, () => {
        assertVerifierFails(directory, /dirty tracked source/u, []);
      });
    });
  }
});

function runVerifier(...arguments_) {
  return spawnSync(process.execPath, ["scripts/verify-m3-evidence.mjs", ...arguments_], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}

function withEvidenceCopy(callback) {
  const directory = mkdtempSync(join(tmpdir(), "m3-evidence-"));
  try {
    const manifest = createEvidenceFixture(directory);
    callback(directory, manifest);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function createEvidenceFixture(directory) {
  const evidenceRoot = ".generations/1700000000000-0123456789abcdef01234567";
  const generationDirectory = join(directory, evidenceRoot);
  const outputDirectory = join(generationDirectory, "outputs");
  mkdirSync(outputDirectory, { recursive: true });
  const generatedAtUtc = new Date().toISOString();
  const sourceCommit = gitOutput("rev-parse", "HEAD");
  const toolVersions = currentToolVersions();
  const outputText = new Map(commands.map(([name]) => [name, `M3 command ${name} passed\n`]));
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
    const outputPath = join(generationDirectory, outputFile);
    writeFileSync(outputPath, outputText.get(name));
    return {
      name,
      command,
      exitCode: 0,
      startedAtUtc: generatedAtUtc,
      durationMs: 0,
      outputFile,
      outputSha256: hash(readFileSync(outputPath)),
    };
  });

  writeFileSync(
    join(directory, "review.md"),
    `# M3 independent review\n\n## Reviewed source commit: ${sourceCommit}\n\n## Independent approval: PASS\n\n## Spec compliance: PASS\n\n## Code quality: PASS\n\n## Critical findings\n\nNone.\n\n## Important findings\n\nNone.\n`,
  );
  writeFileSync(
    join(directory, "known-limitations.md"),
    "Fixture-only M3 evidence for verifier contract mutation tests.\n",
  );
  writeFileSync(join(generationDirectory, "toolchain.txt"), canonicalToolchain(toolVersions));

  const canaryDigest = hash(Buffer.from("fixture-only-canary-digest"));
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
    verificationMatrices: JSON.parse(JSON.stringify(verificationMatrices)),
    credentialCanary: {
      markerPrefix: credentialCanary.markerPrefix,
      sha256: canaryDigest,
      absentFromCapturedEvidence: true,
    },
    artifactSha256: {
      "review.md": hash(readFileSync(join(directory, "review.md"))),
      "known-limitations.md": hash(readFileSync(join(directory, "known-limitations.md"))),
      "toolchain.txt": hash(readFileSync(join(generationDirectory, "toolchain.txt"))),
    },
  };
  writeManifest(directory, manifest);
  return manifest;
}

function writeManifest(directory, manifest) {
  writeFileSync(join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function activeEvidencePath(directory, manifest, relativePath) {
  return join(directory, manifest.evidenceRoot, relativePath);
}

function createRunnerFixture(directory) {
  mkdirSync(join(directory, "scripts"), { recursive: true });
  mkdirSync(join(directory, "docs", "superpowers", "plans"), { recursive: true });
  mkdirSync(
    join(directory, "artifacts", "verification", "m3", ".generations", "old", "outputs"),
    { recursive: true },
  );
  copyFileSync("scripts/run-m3-evidence.mjs", join(directory, "scripts", "run-m3-evidence.mjs"));
  writeFileSync(
    join(directory, "scripts", "m3-evidence-spec.mjs"),
    `export const commands = [["probe", "node -e \\\"process.stdout.write('runner-probe\\\\n')\\\""]];\nexport const verificationMatrices = [{ name: "probe", evidence: [{ command: "probe", needle: "runner-probe" }] }];\nexport const credentialCanary = { markerPrefix: "M3_CREDENTIAL_CANARY_" };\n`,
  );
  writeFileSync(
    join(directory, "docs", "superpowers", "plans", "2026-07-23-m3-protocol-adapter.md"),
    "fixture plan\n",
  );
  writeFileSync(
    join(directory, "artifacts", "verification", "m3", "review.md"),
    "# M3 independent review\n\n## Reviewed source commit: PENDING\n\n## Independent approval: PENDING\n\n## Spec compliance: PENDING\n\n## Code quality: PENDING\n\n## Critical findings\n\nNone.\n\n## Important findings\n\nNone.\n",
  );
  writeFileSync(
    join(directory, "artifacts", "verification", "m3", "known-limitations.md"),
    "Fixture runner limitations.\n",
  );
  writeFileSync(
    join(directory, "artifacts", "verification", "m3", "manifest.json"),
    "active-old-manifest\n",
  );
  writeFileSync(
    join(
      directory,
      "artifacts",
      "verification",
      "m3",
      ".generations",
      "old",
      "outputs",
      "old.log",
    ),
    "active-old-output\n",
  );
  writeFileSync(
    join(directory, "artifacts", "verification", "m3", ".generations", "old", "toolchain.txt"),
    "active-old-toolchain\n",
  );

  runGit(directory, ["init"]);
  runGit(directory, ["config", "user.email", "m3-fixture@example.invalid"]);
  runGit(directory, ["config", "user.name", "M3 fixture"]);
  runGit(directory, ["add", "scripts", "docs", "artifacts/verification/m3"]);
  runGit(directory, ["commit", "-m", "fixture"]);
}

function withApprovedRunnerEvidence(callback) {
  const directory = mkdtempSync(join(tmpdir(), "m3-approved-runner-"));
  try {
    createRunnerFixture(directory);
    copyFileSync("scripts/verify-m3-evidence.mjs", join(directory, "scripts", "verify-m3-evidence.mjs"));
    runGit(directory, ["add", "scripts/verify-m3-evidence.mjs"]);
    runGit(directory, ["commit", "-m", "fixture verifier"]);
    const generated = spawnSync(
      process.execPath,
      [join(directory, "scripts", "run-m3-evidence.mjs")],
      { cwd: directory, encoding: "utf8", env: process.env },
    );
    assert.equal(generated.status, 0, `${generated.stdout}${generated.stderr}`);
    const manifestPath = join(directory, "artifacts", "verification", "m3", "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    const activeRoot = join(directory, "artifacts", "verification", "m3", manifest.evidenceRoot);
    const reviewPath = join(directory, "artifacts", "verification", "m3", "review.md");
    const approvedReview = readFileSync(reviewPath, "utf8")
      .replace("Reviewed source commit: PENDING", `Reviewed source commit: ${manifest.sourceCommit}`)
      .replace("Independent approval: PENDING", "Independent approval: PASS")
      .replace("Spec compliance: PENDING", "Spec compliance: PASS")
      .replace("Code quality: PENDING", "Code quality: PASS");
    writeFileSync(reviewPath, approvedReview);
    manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
    writeManifest(join(directory, "artifacts", "verification", "m3"), manifest);
    callback(directory, manifest, activeRoot, manifestPath);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function readActiveRunnerEvidence(directory) {
  const evidenceRoot = join(directory, "artifacts", "verification", "m3", ".generations", "old");
  const files = [
    "toolchain.txt",
    join("outputs", "old.log"),
  ];
  return [
    ["manifest.json", readFileSync(join(directory, "artifacts", "verification", "m3", "manifest.json"))],
    ...files.map((file) => {
      const path = join(evidenceRoot, file);
      assert.equal(statSync(path).isFile(), true, `fixture evidence file missing: ${file}`);
      return [file, readFileSync(path)];
    }),
  ];
}

function runGit(directory, arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: directory,
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
}

function assertVerifierFails(directory, pattern, extraArguments = ["--historical"]) {
  assertVerifierFailsAt(join(directory, "manifest.json"), pattern, extraArguments);
}

function assertVerifierFailsAt(manifestPath, pattern, extraArguments) {
  const result = runVerifier(...extraArguments, "--manifest", manifestPath);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, pattern);
}

function assertTempVerifierFails(directory, manifestPath, pattern, extraArguments = []) {
  const result = spawnSync(
    process.execPath,
    ["scripts/verify-m3-evidence.mjs", ...extraArguments, "--manifest", manifestPath],
    { cwd: directory, encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, pattern);
}

function assertTempVerifierPasses(directory, manifestPath, extraArguments = []) {
  const result = spawnSync(
    process.execPath,
    ["scripts/verify-m3-evidence.mjs", ...extraArguments, "--manifest", manifestPath],
    { cwd: directory, encoding: "utf8" },
  );
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(`${result.stdout}${result.stderr}`, /M3 evidence: ok/u);
}

function withDirtyFile(path, callback) {
  const original = readFileSync(path);
  try {
    appendFileSync(path, "\nm3-dirty-source-sentinel\n");
    callback();
  } finally {
    writeFileSync(path, original);
  }
}

function gitOutput(...arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: process.cwd(),
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  return result.stdout.trim();
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalToolchain(toolVersions) {
  return `${Object.entries(toolVersions)
    .map(([name, value]) => `${name}=${value}`)
    .join("\n")}\n`;
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
    cwd: process.cwd(),
    encoding: "utf8",
    shell: true,
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  return result.stdout.trim();
}
