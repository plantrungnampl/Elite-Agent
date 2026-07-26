import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });

test("architecture checker accepts the production workspace", () => {
  assert.match(run("scripts/check-architecture.mjs"), /architecture contracts: ok/);
});

test("architecture checker rejects a frontend Tauri invoke outside its API boundary", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--fixture",
        "tests/contracts/fixtures/architecture/frontend-invoke-outside-api",
      ),
    /Tauri invoke is allowed only in src\/api/,
  );
});

test("architecture checker rejects an outward application dependency", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--metadata",
        "tests/contracts/fixtures/architecture/application-outward-metadata.json",
      ),
    /application may depend only on domain or general-purpose libraries/,
  );
});

test("architecture checker rejects even dev-only domain dependencies on adapters", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--metadata",
        "tests/contracts/fixtures/architecture/domain-adapter-dev-metadata.json",
      ),
    /domain may not depend on workspace packages/,
  );
});
