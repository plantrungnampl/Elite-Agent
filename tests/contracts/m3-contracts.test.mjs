import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const run = (...args) =>
  execFileSync(process.execPath, args, { cwd: process.cwd(), encoding: "utf8" });
const fixture = (name) => `tests/contracts/fixtures/m3/${name}`;
const defaultMaxFrameBytes = 8 * 1024 * 1024;

test("architecture checker accepts the complete M3 inward dependency graph", () => {
  assert.match(
    run("scripts/check-architecture.mjs", "--metadata", fixture("m3-valid-metadata.json")),
    /architecture contracts: ok/,
  );
});

test("architecture checker rejects outward M3 crate dependencies", () => {
  for (const [name, pattern] of [
    ["agent-protocol-outward-metadata.json", /agent-protocol has an outward internal dependency/],
    ["agent-runtime-outward-metadata.json", /agent-runtime has an outward internal dependency/],
    ["provider-openai-outward-metadata.json", /provider-openai has an outward internal dependency/],
  ]) {
    assert.throws(
      () => run("scripts/check-architecture.mjs", "--metadata", fixture(name)),
      pattern,
    );
  }
});

test("architecture checker confines M3 provider and runtime boundaries", () => {
  for (const [path, source, pattern] of [
    [
      "crates/application/src/lib.rs",
      "let _runtime = ProtocolAgentRuntime::new();\n",
      /concrete M3 adapters must be constructed only in bootstrap/,
    ],
    [
      "crates/policy-engine/src/lib.rs",
      "const PROVIDER: &str = \"OpenAI\";\n",
      /provider names are forbidden in domain, application, and orchestration policy/,
    ],
    [
      "crates/provider-openai/src/lib.rs",
      "let _api_key = std::env::var(\"OPENAI_API_KEY\");\n",
      /M3 crates may not read credentials from std::env/,
    ],
    [
      "crates/provider-openai/src/lib.rs",
      "tracing::info!(\"Authorization: {}\", \"canary\");\n",
      /Authorization values may not be logged/,
    ],
    [
      "crates/agent-runtime/src/lib.rs",
      "use std::net::TcpStream;\n",
      /provider HTTP and raw TCP\/TLS are allowed only in provider-openai/,
    ],
    [
      "crates/bootstrap/src/lib.rs",
      "use reqwest::blocking::Client;\n",
      /provider HTTP and raw TCP\/TLS are allowed only in provider-openai/,
    ],
    [
      "crates/agent-protocol/src/lib.rs",
      "use std::process::Command;\n",
      /process construction is allowed only in platform-windows/,
    ],
  ]) {
    withM3Source({ [path]: source }, (directory) => {
      assert.throws(
        () => run("scripts/check-architecture.mjs", "--m3-source-fixture", directory),
        pattern,
      );
    });
  }
});

test("architecture checker allows bootstrap composition and provider HTTP", () => {
  withM3Source({
    "crates/bootstrap/src/lib.rs": "let _runtime = ProtocolAgentRuntime::new();\nlet _provider = OpenAiResponsesAdapter::new();\n",
    "crates/provider-openai/src/lib.rs": "use reqwest::blocking::Client;\nlet _client = Client::new();\n",
  }, (directory) => {
    assert.match(
      run("scripts/check-architecture.mjs", "--m3-source-fixture", directory),
      /architecture contracts: ok/,
    );
  });
});

test("normative M3 schema pins frame variants, IDs, strict frames, and the 8 MiB default", () => {
  const schema = JSON.parse(
    readFileSync("docs/multi-agent-terminal-design/schemas/agent-protocol.v1.schema.json", "utf8"),
  );
  const expectedFrames = [
    "initializeRequest",
    "initializedNotification",
    "runStartRequest",
    "runCancelRequest",
    "runCompleteRequest",
    "streamDeltaNotification",
    "contextQueryRequest",
    "toolRequest",
    "specialistRequest",
    "heartbeatNotification",
    "shutdownRequest",
    "exitNotification",
    "successResponse",
    "errorResponse",
  ];
  assert.deepEqual(
    schema.oneOf.map((variant) => variant.$ref.replace("#/$defs/", "")),
    expectedFrames,
  );
  assert.deepEqual(schema.$defs.requestId, {
    type: "string",
    minLength: 1,
    maxLength: 128,
    pattern: "^(core|agent):[A-Za-z0-9._:-]+$",
  });
  for (const name of expectedFrames) {
    const definition = schema.$defs[name];
    const frame = definition.allOf?.[definition.allOf.length - 1] ?? definition;
    assert.equal(frame.additionalProperties, false, `${name} must reject unknown top-level fields`);
  }
  assert.match(
    readFileSync("docs/multi-agent-terminal-design/03-agent-protocol.md", "utf8"),
    /the default maximum frame is 8 MiB/,
  );
  const initialize = JSON.parse(
    readFileSync(
      "docs/multi-agent-terminal-design/schemas/examples/protocol-initialize.request.json",
      "utf8",
    ),
  );
  assert.equal(initialize.params.transport.maxFrameBytes, defaultMaxFrameBytes);
});

test("M3 hostile fixtures encode rejection cases for the future conformance binary", () => {
  const duplicateFrames = readFileSync(fixture("duplicate-request-id.ndjson"), "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(
    duplicateFrames.map((frame) => frame.id),
    ["core:duplicate-request", "core:duplicate-request"],
  );
  assert.ok(duplicateFrames.every((frame) => frame.jsonrpc === "2.0"));

  const oversizeFrame = readFileSync(fixture("oversize-frame.ndjson"), "utf8").trimEnd();
  assert.equal(Buffer.byteLength(oversizeFrame), defaultMaxFrameBytes + 1);
  assert.equal(JSON.parse(oversizeFrame).method, "tool.request");
});

function withM3Source(files, callback) {
  const directory = mkdtempSync(join(tmpdir(), "m3-contracts-"));
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
