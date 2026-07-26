import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const designRoot = join(root, "docs", "multi-agent-terminal-design");
const argument = process.argv.indexOf("--manifest");
const workflowArgument = process.argv.indexOf("--workflow");
const manifestPath = resolve(
  root,
  argument === -1
    ? "docs/multi-agent-terminal-design/SHA256SUMS.txt"
    : process.argv[argument + 1],
);

try {
  verifyManifest(manifestPath);
  verifyJsonArtifacts();
  verifyWorkflow(
    workflowArgument === -1
      ? join(designRoot, "schemas", "workflow-transitions.v1.json")
      : resolve(root, process.argv[workflowArgument + 1]),
  );
  verifySqliteDdl();
  console.log("design contracts: ok");
} catch (error) {
  console.error(`design contracts: ${error.message}`);
  process.exitCode = 1;
}

function verifyManifest(path) {
  const entries = new Map();
  for (const line of readFileSync(path, "utf8").trim().split(/\r?\n/)) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    if (!match || entries.has(match?.[2])) throw new Error("checksum manifest is malformed");
    entries.set(match[2], match[1]);
  }
  const actual = filesUnder(designRoot)
    .filter((path) => path !== "SHA256SUMS.txt")
    .map((path) => path.replaceAll(sep, "/"));
  if (
    entries.size !== actual.length ||
    actual.some((path) => !entries.has(path)) ||
    [...entries].some(([path]) => !actual.includes(path))
  ) {
    throw new Error("checksum manifest is not exact");
  }
  for (const [path, expected] of entries) {
    const content = readFileSync(join(designRoot, path));
    const found = createHash("sha256").update(content).digest("hex");
    if (found !== expected) throw new Error(`checksum mismatch: ${path}`);
  }
}

function filesUnder(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return filesUnder(path).map((child) => join(entry.name, child));
    return [relative(directory, path)];
  });
}

function verifyJsonArtifacts() {
  for (const path of filesUnder(designRoot)) {
    if (path.endsWith(".json")) JSON.parse(readFileSync(join(designRoot, path), "utf8"));
  }
}

function verifyWorkflow(path) {
  const workflow = JSON.parse(readFileSync(path, "utf8"));
  const phases = new Set(workflow.phases);
  const conditions = new Set(workflow.conditions);
  const operations = new Set(workflow.operationStates);
  assertUnique(workflow.phaseTransitions, "phase transition", (entry) =>
    [entry.from, entry.event].join("\0"),
  );
  assertUnique(workflow.conditionTransitions, "condition transition", (entry) =>
    [entry.from, entry.event].join("\0"),
  );
  assertUnique(workflow.operationTransitions, "operation transition", (entry) =>
    [entry.from, entry.event].join("\0"),
  );
  for (const entry of workflow.phaseTransitions) {
    if (!phases.has(entry.from) || !phases.has(entry.to)) {
      throw new Error("workflow phase transition is not closed");
    }
  }
  for (const entry of workflow.conditionTransitions) {
    if (!conditions.has(entry.from) || !conditions.has(entry.to)) {
      throw new Error("workflow condition transition is not closed");
    }
  }
  for (const entry of workflow.operationTransitions) {
    if (!operations.has(entry.from) || !operations.has(entry.to)) {
      throw new Error("workflow operation transition is not closed");
    }
  }
  for (const phase of workflow.workspaceDirtySources) {
    if (!phases.has(phase)) throw new Error("workspace dirty source is not a phase");
  }
  if (!phases.has(workflow.workspaceDirtyTransition.to)) {
    throw new Error("workspace dirty target is not a phase");
  }
  const globalSources = new Set([
    ...phases,
    "any_nonterminal_phase",
    "any_nonterminal_phase_after_resolution",
  ]);
  for (const event of Object.values(workflow.globalEvents)) {
    if (event.to && !phases.has(event.to)) {
      throw new Error("workflow global event target is not a phase");
    }
    if (event.allowedFrom && !globalSources.has(event.allowedFrom)) {
      throw new Error("workflow global event source is not closed");
    }
  }
}

function assertUnique(entries, label, selector) {
  const selectors = new Set();
  for (const entry of entries) {
    const value = selector(entry);
    if (selectors.has(value)) throw new Error(`duplicate ${label} selector`);
    selectors.add(value);
  }
}

function verifySqliteDdl() {
  const database = new DatabaseSync(":memory:");
  database.exec("PRAGMA foreign_keys = ON");
  database.exec(readFileSync(join(designRoot, "schemas", "sqlite-v1.sql"), "utf8"));
  if (database.prepare("PRAGMA foreign_keys").get().foreign_keys !== 1) {
    throw new Error("normative SQLite DDL did not enable foreign keys");
  }
  database.close();
}
