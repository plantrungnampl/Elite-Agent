import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });
const runGit = (...args) => execFileSync("git", args, { cwd: process.cwd(), encoding: "utf8" });
const fixture = (name) => `tests/contracts/fixtures/m2/${name}`;
const digest = /^sha256:[0-9a-f]{64}$/;

test("architecture checker accepts the workspace while M2 packages are absent", () => {
  assert.match(run("scripts/check-architecture.mjs"), /architecture contracts: ok/);
});

test("architecture checker rejects outward M2 adapter dependencies", () => {
  for (const [name, pattern] of [
    ["policy-engine-outward-metadata.json", /policy-engine has an outward internal dependency/],
    ["tool-runtime-outward-metadata.json", /tool-runtime has an outward internal dependency/],
  ]) {
    assert.throws(() => run("scripts/check-architecture.mjs", "--metadata", fixture(name)), pattern);
  }
});

test("architecture checker rejects tool-runtime process construction", () => {
  withM2Source({
    "crates/tool-runtime/src/lib.rs": "use std::process::Command;\n",
  }, (directory) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m2-source-fixture", directory),
      /tool-runtime may not construct or discover processes/,
    );
  });
});

test("architecture checker requires tool-runtime to receive application ports", () => {
  withM2Source({
    "crates/tool-runtime/src/lib.rs": "use local_agent_terminal_application::{CapabilityFilesystem, ProcessLauncher, StructuredGit};\n",
  }, (directory) => {
    assert.match(
      run("scripts/check-architecture.mjs", "--m2-source-fixture", directory),
      /architecture contracts: ok/,
    );
  });
});

test("architecture checker reserves Windows process and filesystem APIs for platform-windows", () => {
  withM2Source({
    "crates/platform-core/src/lib.rs": "use windows_sys::Win32::System::Threading::CreateJobObjectW;\n",
  }, (directory) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m2-source-fixture", directory),
      /Windows process and filesystem APIs are allowed only in platform-windows/,
    );
  });
});

test("architecture checker reserves concrete M2 adapter construction for bootstrap", () => {
  withM2Source({
    "crates/application/src/lib.rs": "let _runtime = ToolRuntime::new();\n",
  }, (directory) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m2-source-fixture", directory),
      /concrete M2 adapters must be constructed only in bootstrap/,
    );
  });
});

test("architecture checker rejects raw frontend paths", () => {
  withM2Source({
    "apps/desktop/src/api/tool.ts": "export interface Request { rawPath: string; }\n",
  }, (directory) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m2-source-fixture", directory),
      /raw path-bearing frontend DTOs are forbidden/,
    );
  });
});

test("the approval fixture satisfies the loaded normative tool schema", () => {
  const schema = JSON.parse(
    readFileSync("docs/multi-agent-terminal-design/schemas/approval-digest.v1.schema.json", "utf8"),
  );
  assert.equal(validateToolApproval(JSON.parse(readFileSync(fixture("tool-approval-valid.json"), "utf8")), schema), null);
  assert.match(
    validateToolApproval(JSON.parse(readFileSync(fixture("tool-approval-unknown-field.json"), "utf8")), schema),
    /operation contains an unknown field/,
  );
  for (const [field, value, pattern] of [
    ["approvalType", "raw_shell", /approvalType is invalid/],
    ["nonce", "bad nonce", /nonce is invalid/],
    ["workspaceVersion", "four", /workspaceVersion is invalid/],
  ]) {
    const invalid = JSON.parse(readFileSync(fixture("tool-approval-valid.json"), "utf8"));
    invalid[field] = value;
    assert.match(validateToolApproval(invalid, schema), pattern);
  }
});

test("default structured tool requests deny raw shell and command strings", () => {
  const rawShell = JSON.parse(readFileSync(fixture("raw-shell-request.json"), "utf8"));
  assert.match(validateDefaultToolRequest(rawShell), /shell\.raw is denied/);
  assert.match(
    validateDefaultToolRequest({
      tool: "process.exec",
      executable: "toolchain:cargo",
      argv: "test --workspace",
      cwd: "worktree:task-1",
      executorFencingToken: 19,
    }),
    /argv must be an array/,
  );
});

test("architecture checker rejects M3 protocol and provider packages", () => {
  withM2Source({
    "crates/agent-protocol/src/lib.rs": "pub struct Protocol;\n",
  }, (directory) => {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--m2-source-fixture", directory),
      /M3 protocol or provider packages are out of scope/,
    );
  });
});

test("the normative design directory remains unchanged", () => {
  runGit("diff", "--exit-code", "321734f", "--", "docs/multi-agent-terminal-design");
});

function validateToolApproval(value, schema) {
  const required = schema.required;
  if (!isObject(value)) return "approval must be an object";
  if (
    schema.additionalProperties === false
    && Object.keys(value).some((key) => !schema.properties[key])
  ) {
    return "approval contains an unknown field";
  }
  if (required.some((key) => !(key in value))) return "approval omits a required field";
  if (value.schema !== schema.properties.schema.const) return "schema must be approval-digest.v1";
  if (!schema.properties.approvalType.enum.includes(value.approvalType)) return "approvalType is invalid";
  if (typeof value.taskId !== "string" || value.taskId.length === 0) return "taskId must be a string";
  if (!new RegExp(schema.$defs.sha256.pattern).test(value.policySnapshotDigest)) return "policySnapshotDigest is invalid";
  if (!Number.isInteger(value.workspaceVersion) || value.workspaceVersion < 0) return "workspaceVersion is invalid";
  if (![value.requestedAt, value.expiresAt].every((time) => typeof time === "string" && !Number.isNaN(Date.parse(time)))) return "timestamps are invalid";
  if (typeof value.nonce !== "string" || !new RegExp(schema.properties.nonce.pattern).test(value.nonce)) return "nonce is invalid";
  if (value.approvalType !== "tool") return "fixture must be a tool approval";

  const operation = schema.$defs.toolOperation;
  if (!isObject(value.operation)) return "operation must be an object";
  if (
    operation.additionalProperties === false
    && Object.keys(value.operation).some((key) => !operation.properties[key])
  ) {
    return "operation contains an unknown field";
  }
  if (operation.required.some((key) => !(key in value.operation))) return "operation omits a required field";
  if (!["runId", "planStepId", "tool", "cwdCapability"].every((key) => typeof value.operation[key] === "string" && value.operation[key].length > 0)) return "operation identifiers are invalid";
  if (!["argumentsDigest", "environmentProfileDigest"].every((key) => digest.test(value.operation[key]))) return "operation digest is invalid";
  if (!(value.operation.executableDigest === undefined || digest.test(value.operation.executableDigest))) return "executableDigest is invalid";
  if (!operation.properties.networkProfile.enum.includes(value.operation.networkProfile)) return "networkProfile is invalid";
  if (!Array.isArray(value.operation.expectedWrites) || value.operation.expectedWrites.some((path) => typeof path !== "string" || path.length === 0)) return "expectedWrites is invalid";
  if (!(value.operation.executorFencingToken === null || (Number.isInteger(value.operation.executorFencingToken) && value.operation.executorFencingToken >= 1))) return "executorFencingToken is invalid";
  return null;
}

function validateDefaultToolRequest(request) {
  if (!isObject(request)) return "tool request must be an object";
  if (request.tool === "shell.raw") return "shell.raw is denied by the default profile";
  if (request.tool !== "process.exec") return "unknown tool";
  if (typeof request.executable !== "string" || request.executable.length === 0) return "executable must be a string";
  if (!Array.isArray(request.argv) || request.argv.some((argument) => typeof argument !== "string")) return "argv must be an array of strings";
  if (typeof request.cwd !== "string" || !request.cwd.startsWith("worktree:")) return "cwd must be a capability";
  if (!Number.isInteger(request.executorFencingToken) || request.executorFencingToken < 1) return "executorFencingToken is invalid";
  return null;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function withM2Source(files, callback) {
  const directory = mkdtempSync(join(tmpdir(), "m2-contracts-"));
  try {
    for (const [path, source] of Object.entries(files)) {
      const target = join(directory, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, source, "utf8");
    }
    callback(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
