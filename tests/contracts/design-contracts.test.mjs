import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });

test("design verifier accepts the checked-in immutable design artifacts", () => {
  assert.match(run("scripts/verify-design-contracts.mjs"), /design contracts: ok/);
});

test("design verifier rejects incomplete checksum manifests", () => {
  assert.throws(
    () =>
      run(
        "scripts/verify-design-contracts.mjs",
        "--manifest",
        "tests/contracts/fixtures/incomplete-sha256sums.txt",
      ),
    /checksum manifest is not exact/,
  );
});
