import assert from "node:assert/strict";
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

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });

test("immutable design checks still pass", () => {
  assert.match(run("scripts/verify-design-contracts.mjs"), /design contracts: ok/);
});

test("repository adapter cannot depend on an outer desktop adapter", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--metadata",
        "tests/contracts/fixtures/m1/repository-git-outward-metadata.json",
      ),
    /local-agent-terminal-repository-git has an outward internal dependency/,
  );
});

test("generic Tauri execution commands are rejected", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--tauri-fixture",
        "tests/contracts/fixtures/architecture/tauri-generic-command/src",
      ),
    /generic Tauri command is forbidden: run_command/,
  );
});

test("repository adapter rejects process execution", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--repository-fixture",
        "tests/contracts/fixtures/m1/repository-process-adapter/src",
      ),
    /repository adapter may not spawn a process/,
  );
});

test("repository adapter rejects PATH lookup", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--repository-fixture",
        "tests/contracts/fixtures/m1/repository-path-adapter/src",
      ),
    /repository adapter may not inspect PATH/,
  );
});

test("M1 evidence is complete and internally consistent", () => {
  assert.match(run("scripts/verify-m1-evidence.mjs"), /M1 evidence: ok/);
});

test("Windows CI generates, verifies, and uploads fresh M1 evidence", () => {
  const workflow = readFileSync(".github/workflows/ci.yml", "utf8");
  const runner = readFileSync("scripts/run-m1-evidence.mjs", "utf8");
  for (const command of [
    "pnpm install --frozen-lockfile",
    "node scripts/verify-design-contracts.mjs",
    "node --test tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs",
    "node scripts/check-architecture.mjs",
    "cargo test -p local-agent-terminal-repository-git --test windows_matrix --features test-seams",
    "cargo test -p local-agent-terminal-bootstrap --test recovery_matrix",
    "cargo fmt --all -- --check",
    "cargo clippy --workspace --all-targets -- -D warnings",
    "cargo test --workspace --all-targets",
    "pnpm --dir apps/desktop test --run",
    "pnpm --dir apps/desktop test:browser",
    "pnpm --dir apps/desktop build",
    "cargo build -p local-agent-terminal-desktop",
    "git diff --check",
    "git diff --exit-code 321734f -- docs/multi-agent-terminal-design",
  ]) {
    assert.match(runner, new RegExp(escapeRegExp(command)), command);
  }
  const generate = workflow.indexOf("node scripts/run-m1-evidence.mjs");
  const verify = workflow.indexOf("node scripts/verify-m1-evidence.mjs");
  const postFinal = workflow.indexOf("node scripts/run-m1-post-final-contracts.mjs");
  const verifyPostFinal = workflow.indexOf("node scripts/verify-m1-post-final-log.mjs");
  const upload = workflow.indexOf("actions/upload-artifact@v4");
  assert.ok(
    generate >= 0
      && verify > generate
      && postFinal > verify
      && verifyPostFinal > postFinal
      && upload > verifyPostFinal,
  );
  assert.match(workflow, /artifacts\/verification\/m1/);
});

test("M1 verifier rejects modified captured output", () => {
  withEvidenceCopy((directory, manifest) => {
    appendFileSync(join(directory, manifest.commands[0].outputFile), "tampered\n");
    assertVerifierFails(directory, /output hash mismatch/);
  });
});

test("M1 verifier rejects a stale source commit", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.sourceCommit = "0".repeat(40);
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /source commit|ancestor/);
  });
});

test("M1 verifier rejects self-asserted fixture classifications", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.fixtureClassifications.find(
      (entry) => entry.case === "long paths",
    ).classification = "supported";
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /fixture classification mismatch/);
  });
});

test("M1 verifier rejects fixture evidence absent from captured output", () => {
  withEvidenceCopy((directory, manifest) => {
    manifest.fixtureClassifications.find(
      (entry) => entry.case === "spaces\/metacharacters",
    ).evidence[0].needle = "unobserved_test_name";
    writeManifest(directory, manifest);
    assertVerifierFails(directory, /fixture evidence mismatch|test evidence not observed/);
  });
});

test("M1 verifier rejects dirty tracked source even when HEAD matches sourceCommit", () => {
  withDirtyTrackedSource(() => {
    const result = spawnSync(process.execPath, ["scripts/verify-m1-evidence.mjs"], {
      cwd: process.cwd(),
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /dirty tracked source/);
  });
});

test("M1 evidence generation preflight rejects dirty tracked source", () => {
  withDirtyTrackedSource(() => {
    const result = spawnSync(
      process.execPath,
      ["scripts/check-m1-evidence-worktree.mjs"],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /dirty tracked source/);
  });
});

test("unknown non-repeatable operations are indeterminate and non-replayable", () => {
  const fixture = JSON.parse(
    readFileSync("tests/contracts/fixtures/m1/unknown-operation.json", "utf8"),
  );

  assert.equal(fixture.status, "started");
  assert.equal(fixture.idempotencyClass, "non_repeatable");
  assert.equal(fixture.recovery.classification, "indeterminate");
  assert.ok(!fixture.recovery.actions.includes("retry"));
  assert.ok(!("command" in fixture) && !("argv" in fixture) && !("executable" in fixture));
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function withEvidenceCopy(callback) {
  const directory = mkdtempSync(join(tmpdir(), "m1-evidence-"));
  try {
    cpSync("artifacts/verification/m1", directory, { recursive: true });
    const manifest = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8"));
    callback(directory, manifest);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function writeManifest(directory, manifest) {
  writeFileSync(join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function assertVerifierFails(directory, pattern) {
  const result = spawnSync(
    process.execPath,
    ["scripts/verify-m1-evidence.mjs", "--manifest", join(directory, "manifest.json")],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, pattern);
}

function withDirtyTrackedSource(callback) {
  const path = "tests/contracts/fixtures/m1/unknown-operation.json";
  const original = readFileSync(path);
  try {
    appendFileSync(path, "\nround-2-dirty-source-sentinel\n");
    callback();
  } finally {
    writeFileSync(path, original);
  }
}
