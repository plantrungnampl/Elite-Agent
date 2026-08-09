import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });

test("architecture checker accepts the production workspace", () => {
  assert.match(run("scripts/check-architecture.mjs"), /architecture contracts: ok/);
});

test("architecture checker permits staged M3 crate introduction", () => {
  const directory = mkdtempSync(join(tmpdir(), "m3-staged-workspace-"));
  try {
    const metadata = join(directory, "metadata.json");
    writeFileSync(
      metadata,
      JSON.stringify({
        packages: [
          { name: "local-agent-terminal-domain", dependencies: [] },
          {
            name: "local-agent-terminal-application",
            dependencies: [{ name: "local-agent-terminal-domain" }],
          },
          { name: "local-agent-terminal-agent-protocol", dependencies: [] },
        ],
        workspace_members: [
          "local-agent-terminal-domain",
          "local-agent-terminal-application",
          "local-agent-terminal-agent-protocol",
        ],
      }),
      "utf8",
    );
    assert.match(
      run("scripts/check-architecture.mjs", "--metadata", metadata),
      /architecture contracts: ok/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("architecture checker permits staged M4 crate introduction", () => {
  const directory = mkdtempSync(join(tmpdir(), "m4-staged-workspace-"));
  try {
    const metadata = join(directory, "metadata.json");
    writeFileSync(
      metadata,
      JSON.stringify({
        packages: [
          { name: "local-agent-terminal-domain", dependencies: [] },
          {
            name: "local-agent-terminal-application",
            dependencies: [{ name: "local-agent-terminal-domain" }],
          },
          {
            name: "local-agent-terminal-context-engine",
            dependencies: [
              { name: "local-agent-terminal-application" },
              { name: "local-agent-terminal-domain" },
            ],
          },
        ],
        workspace_members: [
          "local-agent-terminal-domain",
          "local-agent-terminal-application",
          "local-agent-terminal-context-engine",
        ],
      }),
      "utf8",
    );
    assert.match(
      run("scripts/check-architecture.mjs", "--metadata", metadata),
      /architecture contracts: ok/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
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
    /local-agent-terminal-application has an outward internal dependency/,
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

test("architecture checker allows external domain test dependencies", () => {
  assert.match(
    run(
      "scripts/check-architecture.mjs",
      "--metadata",
      "tests/contracts/fixtures/architecture/domain-proptest-dev-metadata.json",
    ),
    /architecture contracts: ok/,
  );
});

test("architecture checker rejects a generic Tauri execution command", () => {
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

test("architecture checker rejects M5 commit and finalization command variants", () => {
  for (const name of ["commit", "create_commit", "finalize_commit"]) {
    const directory = mkdtempSync(join(tmpdir(), "m2-commit-command-"));
    try {
      const source = join(directory, "apps", "desktop", "src-tauri", "src", "lib.rs");
      mkdirSync(dirname(source), { recursive: true });
      writeFileSync(source, `#[tauri::command]\nfn ${name}() {}\n`, "utf8");
      assert.throws(
        () => run("scripts/check-architecture.mjs", "--m2-source-fixture", directory),
        new RegExp(`generic Tauri command is forbidden: ${name}`),
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("architecture checker rejects grouped and aliased process imports", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--repository-fixture",
        "tests/contracts/fixtures/architecture/repository-process-alias",
      ),
    /repository adapter may not spawn a process/,
  );
});

test("architecture checker rejects grouped and aliased PATH access", () => {
  assert.throws(
    () =>
      run(
        "scripts/check-architecture.mjs",
        "--repository-fixture",
        "tests/contracts/fixtures/architecture/repository-path-alias",
      ),
    /repository adapter may not inspect PATH/,
  );
});
