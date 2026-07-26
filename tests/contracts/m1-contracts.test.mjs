import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
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

test("Windows CI runs every M1 acceptance gate", () => {
  const workflow = readFileSync(".github/workflows/ci.yml", "utf8");
  for (const command of [
    "node scripts/verify-design-contracts.mjs",
    "node --test tests/contracts/*.test.mjs",
    "node scripts/verify-m1-evidence.mjs",
    "node scripts/check-architecture.mjs",
    "cargo test -p local-agent-terminal-repository-git --test windows_matrix",
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
    assert.match(workflow, new RegExp(escapeRegExp(command)), command);
  }
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
