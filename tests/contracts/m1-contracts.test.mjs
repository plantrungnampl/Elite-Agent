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
