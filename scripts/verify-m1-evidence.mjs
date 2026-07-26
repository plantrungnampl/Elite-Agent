import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifestPath = resolve(root, "artifacts/verification/m1/manifest.json");

try {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  assert(manifest.finalized === true, "manifest is not finalized");

  const requiredCommands = [
    "pnpm install --frozen-lockfile",
    "node scripts/verify-design-contracts.mjs",
    "node --test tests/contracts/*.test.mjs",
    "node scripts/verify-m1-evidence.mjs",
    "node scripts/check-architecture.mjs",
    "cargo fmt --all -- --check",
    "cargo clippy --workspace --all-targets -- -D warnings",
    "cargo test --workspace --all-targets",
    "pnpm --dir apps/desktop test --run",
    "pnpm --dir apps/desktop test:browser",
    "pnpm --dir apps/desktop build",
    "cargo build -p local-agent-terminal-desktop",
    "git diff --check",
    "git diff --exit-code 321734f -- docs/multi-agent-terminal-design",
  ];
  const commands = new Map(manifest.commands.map((entry) => [entry.command, entry]));
  for (const command of requiredCommands) {
    const entry = commands.get(command);
    assert(entry, `missing command evidence: ${command}`);
    assert(entry.exitCode === 0, `command did not pass: ${command}`);
    assert(Number.isInteger(entry.durationMs) && entry.durationMs >= 0, `invalid duration: ${command}`);
    assert(!Number.isNaN(Date.parse(entry.startedAtUtc)), `invalid timestamp: ${command}`);
    assert(/^sha256:[0-9a-f]{64}$/.test(entry.outputSha256), `invalid output hash: ${command}`);
  }

  const requiredCases = [
    "clean/dirty/original-index preservation",
    "spaces/metacharacters",
    "Unicode",
    "long paths",
    "locks",
    "static and swap-race junctions/symlinks",
    "UNC/device/ADS rejection",
    "nested/common-dir/artifact-root target rejection",
    "branch/path/CAS conflicts",
    "crash boundaries and pending/started intent recovery",
    "stale lease replacement",
    "projection-only replay",
    "approval/candidate invalidation rollback",
    "unknown intent handling",
    "SHA-1/SHA-256 exact IDs",
    "submodule/LFS/custom filter/hook/fsmonitor/include/credential/SSH/remote-helper fail-closed behavior",
    "shallow/sparse/detached/unborn repositories",
    "CRLF configuration with checkout filters disabled",
    "no child process spawned and sentinel executables untouched",
  ];
  const cases = new Map(
    manifest.fixtureClassifications.map((entry) => [entry.case, entry]),
  );
  for (const requiredCase of requiredCases) {
    const entry = cases.get(requiredCase);
    assert(entry, `missing fixture classification: ${requiredCase}`);
    assert(
      ["supported", "fail-closed", "recovered", "preserved"].includes(entry.classification),
      `unverified fixture classification: ${requiredCase}`,
    );
    assert(Array.isArray(entry.evidence) && entry.evidence.length > 0, `missing fixture evidence: ${requiredCase}`);
    for (const evidence of entry.evidence) {
      const file = evidence.split(/::|#/u, 1)[0];
      assert(existsSync(resolve(root, file)), `missing evidence file: ${file}`);
    }
  }

  for (const blocker of [
    "filterDisabling",
    "pathContainment",
    "sha256ExactOids",
    "noForceConditionalRefs",
    "worktrees",
    "lfsSubmoduleEvidence",
  ]) {
    assert(manifest.approvalBlockers[blocker] === "verified", `M1 approval blocked: ${blocker}`);
  }

  for (const file of ["review.md", "known-limitations.md", "toolchain.txt"]) {
    const expected = manifest.artifactSha256[file];
    const actual = `sha256:${createHash("sha256")
      .update(readFileSync(resolve(root, "artifacts/verification/m1", file)))
      .digest("hex")}`;
    assert(expected === actual, `artifact hash mismatch: ${file}`);
  }
  console.log("M1 evidence: ok");
} catch (error) {
  console.error(`M1 evidence: ${error.message}`);
  process.exitCode = 1;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
