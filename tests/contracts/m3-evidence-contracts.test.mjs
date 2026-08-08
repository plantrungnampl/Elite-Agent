import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
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

test("M3 verifier rejects modified captured output and retained artifacts", () => {
  withEvidenceCopy((directory, manifest) => {
    appendFileSync(join(directory, manifest.commands[0].outputFile), "tampered\n");
    assertVerifierFails(directory, /output hash mismatch/u);
  });
  for (const file of ["review.md", "known-limitations.md", "toolchain.txt"]) {
    withEvidenceCopy((directory) => {
      appendFileSync(join(directory, file), "tampered\n");
      assertVerifierFails(directory, /artifact hash mismatch/u);
    });
  }
});

test(
  "M3 verifier rejects missing, duplicate, failed, and reordered commands; runner preserves prior evidence on failure",
  () => {
    const runner = readFileSync("scripts/run-m3-evidence.mjs", "utf8");
    const failurePath = runner.match(/\}\s*catch \(error\) \{([\s\S]*?)\n\}\s*finally/u)?.[1];
    assert.ok(failurePath, "runner failure path is missing");
    assert.doesNotMatch(
      failurePath,
      /artifactRoot|outputRoot|copyFileSync|renameSync|writeFileSync/u,
      "failed evidence runs must not replace finalized artifacts",
    );

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
  },
);

test("M3 verifier rejects native skipped-test summaries", () => {
  for (const summary of [
    "test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured\n",
    "  1 skipped\n",
    "      Tests  1 skipped (1)\n",
  ]) {
    withEvidenceCopy((directory, manifest) => {
      const entry = manifest.commands[0];
      const outputPath = join(directory, entry.outputFile);
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
    const outputPath = join(directory, entry.outputFile);
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
    withEvidenceCopy((directory, manifest) => {
      const reviewPath = join(directory, "review.md");
      const review = readFileSync(reviewPath, "utf8").replace(
        new RegExp(`(^## ${heading}: )PASS$`, "mu"),
        "$1PENDING",
      );
      writeFileSync(reviewPath, review);
      manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
      writeManifest(directory, manifest);
      assertVerifierFails(
        directory,
        new RegExp(`${heading}.*pending|pending`, "iu"),
        ["--historical", "--require-approved"],
      );
    });
  }
});

test("final M3 verification binds every verdict to the reviewed source", () => {
  withEvidenceCopy((directory, manifest) => {
    const reviewPath = join(directory, "review.md");
    const review = readFileSync(reviewPath, "utf8").replace(
      /^## Reviewed source commit: .+$/mu,
      `## Reviewed source commit: ${"0".repeat(40)}`,
    );
    writeFileSync(reviewPath, review);
    manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /reviewed source commit mismatch/u, [
      "--historical",
      "--require-approved",
    ]);
  });
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
  const outputDirectory = join(directory, "outputs");
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
    const outputPath = join(directory, outputFile);
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
  writeFileSync(join(directory, "toolchain.txt"), `${JSON.stringify(toolVersions, null, 2)}\n`);

  const canaryDigest = hash(Buffer.from("fixture-only-canary-digest"));
  const manifest = {
    schemaVersion: 1,
    finalized: true,
    generatedAtUtc,
    sourceCommit,
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
      "toolchain.txt": hash(readFileSync(join(directory, "toolchain.txt"))),
    },
  };
  writeManifest(directory, manifest);
  return manifest;
}

function writeManifest(directory, manifest) {
  writeFileSync(join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function assertVerifierFails(directory, pattern, extraArguments = ["--historical"]) {
  assertVerifierFailsAt(join(directory, "manifest.json"), pattern, extraArguments);
}

function assertVerifierFailsAt(manifestPath, pattern, extraArguments) {
  const result = runVerifier(...extraArguments, "--manifest", manifestPath);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, pattern);
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
