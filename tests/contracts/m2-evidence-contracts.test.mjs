import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import {
  appendFileSync,
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { isEvidenceOnlyPath } from "../../scripts/m2-evidence-worktree.mjs";

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });

test("M2 evidence is complete and internally consistent", () => {
  assert.match(run("scripts/verify-m2-evidence.mjs", "--historical"), /M2 evidence: ok/u);
});

test("Windows CI runs containment before fresh M2 evidence verification", () => {
  const workflow = readFileSync(".github/workflows/ci.yml", "utf8");
  const containment = workflow.indexOf(
    "cargo test -p local-agent-terminal-platform-windows --features test-seams --test filesystem_matrix --test process_matrix",
  );
  const generate = workflow.indexOf("node scripts/run-m2-evidence.mjs");
  const verify = workflow.indexOf(
    "node scripts/verify-m2-evidence.mjs --require-approved",
  );
  const postFinal = workflow.indexOf("node scripts/run-m2-post-final-contracts.mjs");
  const verifyPostFinal = workflow.indexOf("node scripts/verify-m2-post-final-log.mjs");
  const upload = workflow.indexOf("actions/upload-artifact@v4");
  assert.ok(
    containment >= 0 &&
      generate > containment &&
      verify > generate &&
      postFinal > verify &&
      verifyPostFinal > postFinal &&
      upload > verifyPostFinal,
  );
  assert.match(workflow, /artifacts\/verification\/m2/u);
});

test("M2 evidence-only path predicate allows exact M2/M3 evidence and the execution plan", () => {
  for (const path of [
    "artifacts/verification/m2/manifest.json",
    "artifacts/verification/m2/review.md",
    "artifacts/verification/m2/known-limitations.md",
    "artifacts/verification/m2/toolchain.txt",
    "artifacts/verification/m2/post-final-contracts.log",
    "artifacts/verification/m2/outputs/source-contracts.log",
    "artifacts/verification/m3/manifest.json",
    "artifacts/verification/m3/review.md",
    "artifacts/verification/m3/known-limitations.md",
    "artifacts/verification/m3/.generations/1786215905484-1cd0d36850022258537b24f3/toolchain.txt",
    "artifacts/verification/m3/.generations/1786215905484-1cd0d36850022258537b24f3/outputs/protocol-schema-conformance.log",
    "docs/superpowers/plans/2026-07-23-m3-protocol-adapter.md",
  ]) {
    assert.equal(isEvidenceOnlyPath(path), true, path);
  }
  assert.equal(
    isEvidenceOnlyPath("artifacts\\verification\\m3\\manifest.json"),
    true,
  );
});

test("M2 evidence-only path predicate rejects broad artifacts, unsafe generations, and source paths", () => {
  for (const path of [
    "artifacts/verification/m3/task9a4-runner-report.log",
    "artifacts/verification/m3/known-limitations.txt",
    "artifacts/verification/m3/.generations/178621590548-1cd0d36850022258537b24f3/toolchain.txt",
    "artifacts/verification/m3/.generations/1786215905484-1cd0d36850022258537b24f/outputs/protocol-schema-conformance.log",
    "artifacts/verification/m3/.generations/1786215905484-1cd0d36850022258537b24f3/manifest.json",
    "artifacts/verification/m3/.generations/1786215905484-1cd0d36850022258537b24f3/outputs/Protocol.log",
    "artifacts/verification/m3/.generations/1786215905484-1cd0d36850022258537b24f3/outputs/../toolchain.txt",
    "artifacts/verification/m3/../m2/manifest.json",
    "artifacts/verification/m3/raw/manifest.json",
    "docs/superpowers/plans/2026-07-23-m3-protocol-adapter-copy.md",
    "docs/multi-agent-terminal-design/03-agent-protocol.md",
    "scripts/verify-m2-evidence.mjs",
    "tests/contracts/m2-evidence-contracts.test.mjs",
  ]) {
    assert.equal(isEvidenceOnlyPath(path), false, path);
  }
});

test("M2 verifier rejects modified captured output", () => {
  withEvidenceCopy((directory, manifest) => {
    appendFileSync(join(directory, manifest.commands[0].outputFile), "tampered\n");
    assertVerifierFails(directory, /output hash mismatch/u);
  });
});

test("M2 verifier rejects stale and non-ancestor source commits", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.sourceCommit = gitOutput("rev-parse", "HEAD^");
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /stale for the current code/u, []);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.sourceCommit = "0".repeat(40);
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /not an ancestor|unable to run/u, []);
  });
});

test("M2 historical mode still requires ancestry and allows later source commits", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.sourceCommit = "0".repeat(40);
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /not an ancestor|unable to run/u);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.sourceCommit = gitOutput("rev-parse", "HEAD^");
    writeManifest(directory, manifest);
    const result = spawnSync(
      process.execPath,
      [
        "scripts/verify-m2-evidence.mjs",
        "--historical",
        "--manifest",
        join(directory, "manifest.json"),
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(`${result.stdout}${result.stderr}`, /M2 evidence: ok/u);
  });
});

test("M2 verifier rejects missing, failed, and skipped commands", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.commands.pop();
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /unexpected command evidence count/u);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.commands[0].exitCode = 1;
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /command did not pass/u);
  });
  withEvidenceCopy((directory, manifest) => {
    const entry = manifest.commands[0];
    const outputPath = join(directory, entry.outputFile);
    appendFileSync(outputPath, "# SKIP containment\n");
    entry.outputSha256 = hash(readFileSync(outputPath));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /command skipped a case/u);
  });
});

test("M2 verifier rejects omitted containment cases", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.containmentCases.pop();
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /containment case mismatch/u);
  });
});

test("M2 verifier rejects platform and toolchain drift", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.platform = "other-platform";
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /platform mismatch/u);
  });
  withEvidenceCopy((directory, manifest) => {
    manifest.toolVersions.rustc = "rustc changed";
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /toolchain mismatch/u);
  });
});

test("M2 verifier rejects tampered review and limitations artifacts", () => {
  for (const file of ["review.md", "known-limitations.md"]) {
    withEvidenceCopy((directory) => {
      appendFileSync(join(directory, file), "tampered\n");
      assertVerifierFails(directory, /artifact hash mismatch/u);
    });
  }
});

test("final M2 verification rejects a pending independent review", () => {
  withEvidenceCopy((directory, manifest) => {
    const reviewPath = join(directory, "review.md");
    const review = readFileSync(reviewPath, "utf8").replace(
      "Independent approval: PASS",
      "Independent approval: PENDING",
    );
    writeFileSync(reviewPath, review);
    manifest.artifactSha256["review.md"] = hash(readFileSync(reviewPath));
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /independent approval is pending/u, [
      "--historical",
      "--require-approved",
    ]);
  });
});

test("final M2 verification binds every verdict to the reviewed source", () => {
  withEvidenceCopy((directory, manifest) => {
    writeReview(
      directory,
      manifest,
      reviewFixture(manifest.sourceCommit, "PASS", "PENDING", "PASS"),
    );
    assertVerifierFails(directory, /spec compliance is pending/u, [
      "--historical",
      "--require-approved",
    ]);
  });
  withEvidenceCopy((directory, manifest) => {
    writeReview(
      directory,
      manifest,
      reviewFixture("0".repeat(40), "PASS", "PASS", "PASS"),
    );
    assertVerifierFails(directory, /reviewed source commit mismatch/u, [
      "--historical",
      "--require-approved",
    ]);
  });
});

test("M2 verifier rejects native skipped-test summaries", () => {
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
      assertVerifierFails(directory, /command skipped a case/u);
    });
  }
});

test("M2 verifier rejects dirty source and immutable design changes", () => {
  for (const path of [
    "tests/contracts/fixtures/m2/raw-shell-request.json",
    "docs/multi-agent-terminal-design/schemas/README.md",
  ]) {
    withDirtyFile(path, () => {
      const result = spawnSync(process.execPath, ["scripts/verify-m2-evidence.mjs"], {
        cwd: process.cwd(),
        encoding: "utf8",
      });
      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}${result.stderr}`, /dirty tracked source/u);
    });
  }
});

test("M2 evidence generation preflight rejects dirty source", () => {
  withDirtyFile("tests/contracts/fixtures/m2/raw-shell-request.json", () => {
    const result = spawnSync(
      process.execPath,
      ["scripts/check-m2-evidence-worktree.mjs"],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /dirty tracked source/u);
  });
});

test("M2 post-final verifier rejects an absent log", () => {
  const missing = join(tmpdir(), `missing-m2-post-final-${process.pid}.log`);
  const result = spawnSync(
    process.execPath,
    ["scripts/verify-m2-post-final-log.mjs", "--log", missing],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /M2 post-final contracts/u);
});

test("M2 post-final verifier requires every approval-critical contract", () => {
  const names = [
    "M2 evidence is complete and internally consistent",
    "Windows CI runs containment before fresh M2 evidence verification",
    "M2 verifier rejects modified captured output",
    "M2 verifier rejects stale and non-ancestor source commits",
    "M2 verifier rejects missing, failed, and skipped commands",
    "M2 verifier rejects omitted containment cases",
    "M2 verifier rejects platform and toolchain drift",
    "M2 verifier rejects tampered review and limitations artifacts",
    "final M2 verification rejects a pending independent review",
    "M2 verifier rejects dirty source and immutable design changes",
    "M2 evidence generation preflight rejects dirty source",
    "M2 post-final verifier rejects an absent log",
  ];
  for (const name of [
    "Windows CI runs containment before fresh M2 evidence verification",
    "final M2 verification rejects a pending independent review",
  ]) {
    const path = join(tmpdir(), `m2-post-final-${process.pid}.log`);
    try {
      writeFileSync(
        path,
        names
          .filter((candidate) => candidate !== name)
          .map((candidate) => `✔ ${candidate}`)
          .join("\n"),
      );
      const result = spawnSync(
        process.execPath,
        ["scripts/verify-m2-post-final-log.mjs", "--log", path],
        { cwd: process.cwd(), encoding: "utf8" },
      );
      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}${result.stderr}`, /missing passing contract/u);
    } finally {
      rmSync(path, { force: true });
    }
  }
});

function withEvidenceCopy(callback) {
  const directory = mkdtempSync(join(tmpdir(), "m2-evidence-"));
  try {
    cpSync("artifacts/verification/m2", directory, { recursive: true });
    const manifest = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8"));
    callback(directory, manifest);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function writeManifest(directory, manifest) {
  writeFileSync(join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function writeReview(directory, manifest, review) {
  const path = join(directory, "review.md");
  writeFileSync(path, review);
  manifest.artifactSha256["review.md"] = hash(readFileSync(path));
  writeManifest(directory, manifest);
}

function reviewFixture(sourceCommit, independent, spec, code) {
  return `# M2 independent review

## Reviewed source commit: ${sourceCommit}

## Independent approval: ${independent}

## Spec compliance: ${spec}

## Code quality: ${code}
`;
}

function assertVerifierFails(directory, pattern, extraArguments = ["--historical"]) {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/verify-m2-evidence.mjs",
      ...extraArguments,
      "--manifest",
      join(directory, "manifest.json"),
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, pattern);
}

function withDirtyFile(path, callback) {
  const original = readFileSync(path);
  try {
    appendFileSync(path, "\nm2-dirty-source-sentinel\n");
    callback();
  } finally {
    writeFileSync(path, original);
  }
}

function gitOutput(...arguments_) {
  return execFileSync("git", arguments_, {
    cwd: process.cwd(),
    encoding: "utf8",
  }).trim();
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
