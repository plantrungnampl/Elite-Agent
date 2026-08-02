import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertEvidenceOnlyChanges } from "./m1-evidence-worktree.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const historical = process.argv.includes("--historical");
const manifestArgument = process.argv.indexOf("--manifest");
const manifestPath =
  manifestArgument === -1
    ? join(root, "artifacts", "verification", "m1", "manifest.json")
    : resolve(root, process.argv[manifestArgument + 1]);
const artifactRoot = dirname(manifestPath);

const requiredCommands = new Map([
  ["frozen-install", "pnpm install --frozen-lockfile"],
  ["design-contracts", "node scripts/verify-design-contracts.mjs"],
  ["architecture", "node scripts/check-architecture.mjs"],
  ["repository-windows", "cargo test -p local-agent-terminal-repository-git --test windows_matrix --features test-seams"],
  ["recovery-matrix", "cargo test -p local-agent-terminal-bootstrap --test recovery_matrix"],
  ["contract-tests", "node --test tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs"],
  ["rust-format", "cargo fmt --all -- --check"],
  ["rust-clippy", "cargo clippy --workspace --all-targets -- -D warnings"],
  ["rust-tests", "cargo test --workspace --all-targets"],
  ["frontend-tests", "pnpm --dir apps/desktop test --run"],
  ["playwright-install", "pnpm --dir apps/desktop exec playwright install chromium"],
  ["browser-tests", "pnpm --dir apps/desktop test:browser"],
  ["frontend-build", "pnpm --dir apps/desktop build"],
  ["desktop-debug-build", "cargo build -p local-agent-terminal-desktop"],
  ["diff-check", "git diff --check"],
  ["committed-diff-check", "git diff --check 321734f..HEAD"],
  ["design-docs-unchanged", "git diff --exit-code 321734f -- docs/multi-agent-terminal-design"],
]);

const requiredFixtures = new Map([
  ["clean/dirty/original-index preservation", expected("preserved", [["repository-windows", "successful_unicode_worktree_preserves_original_head_index_and_checkout_bytes"], ["repository-windows", "worktree_creation_rejects_a_dirty_original_checkout"]])],
  ["spaces/metacharacters", expected("supported", [["repository-windows", "valid_windows_shell_metacharacters_are_supported_in_managed_paths"]])],
  ["Unicode", expected("supported", [["repository-windows", "successful_unicode_worktree_preserves_original_head_index_and_checkout_bytes"]])],
  ["long paths", expected("fail-closed", [["repository-windows", "long_path_checkout_fails_closed_without_mutating_original_state"]])],
  ["locks", expected("fail-closed", [["repository-windows", "ref_lock_and_base_cas_conflicts_leave_branch_target_and_index_absent"]])],
  ["static and swap-race junctions/symlinks", expected("fail-closed", [["repository-windows", "static_symlink_target_is_rejected_without_touching_its_destination"], ["repository-windows", "parent_swap_race_is_blocked_while_checkout_is_in_progress"]])],
  ["UNC/device/ADS rejection", expected("fail-closed", [["repository-windows", "invalid_windows_target_forms_are_rejected_without_git_side_effects"]])],
  ["nested/common-dir/artifact-root target rejection", expected("fail-closed", [["repository-windows", "target_inside_original_checkout_and_case_collisions_fail_closed"], ["repository-windows", "excluded_artifact_root_and_git_common_dir_targets_are_rejected"]])],
  ["branch/path/CAS conflicts", expected("fail-closed", [["repository-windows", "branch_conflict_is_preserved_without_creating_target"], ["repository-windows", "failed_create_preserves_replacements_after_ownership_observation"]])],
  ["all post-add rollback boundaries", expected("preserved", [["repository-windows", "every_post_add_failure_preserves_owned_state_as_a_conflict"]])],
  ["crash boundaries and pending/started intent recovery", expected("recovered", [["rust-tests", "crash_boundaries_reconcile_to_deterministic_states"], ["recovery-matrix", "startup_leaves_pending_intent_for_exact_command_retry_without_git_effects"], ["recovery-matrix", "startup_adopts_only_the_exact_durable_worktree"], ["recovery-matrix", "startup_inspects_preserved_indeterminate_create_without_adopting_or_discarding_it"]])],
  ["stale lease replacement", expected("recovered", [["rust-tests", "stale_monitor_claim_is_rejected_before_evidence_or_repository_bytes_change"], ["rust-tests", "lease_replacement_increments_token_and_stale_claim_cannot_write"]])],
  ["projection-only replay", expected("preserved", [["recovery-matrix", "repeated_startup_replays_recovery_projection_without_duplicate_side_effects"]])],
  ["approval/candidate invalidation rollback", expected("preserved", [["rust-tests", "workspace_mutation_is_atomic_and_invalidates_candidate_approvals"], ["rust-tests", "mutation_rolls_back_event_projection_approvals_candidate_and_lease_together"]])],
  ["unknown intent handling", expected("recovered", [["recovery-matrix", "startup_marks_unknown_operations_indeterminate_without_touching_git"]])],
  ["SHA-1/SHA-256 exact IDs", expected("supported", [["repository-windows", "sha256_repository_keeps_exact_object_ids"]])],
  ["submodule/LFS and execution-capable Git configuration", expected("fail-closed", [["repository-windows", "repository_hazards_are_classified_before_worktree_side_effects"], ["repository-windows", "hazard_scan_fails_closed_when_head_object_is_missing"], ["repository-windows", "hazard_scan_fails_closed_when_attributes_path_is_not_a_blob"], ["repository-windows", "hazard_scan_fails_closed_when_attributes_blob_is_missing"], ["repository-windows", "hazard_scan_fails_closed_for_non_utf8_attributes"], ["repository-windows", "hazard_scan_fails_closed_for_malformed_attributes"], ["repository-windows", "every_execution_capable_git_configuration_fails_closed_and_stays_inert"]])],
  ["shallow/sparse/detached/unborn repositories", expected("fail-closed", [["repository-windows", "shallow_and_sparse_repositories_fail_closed"], ["repository-windows", "dirty_detached_and_unborn_states_are_explicit"]])],
  ["CRLF configuration with checkout filters disabled", expected("supported", [["repository-windows", "checkout_disables_crlf_filters_and_preserves_blob_bytes"]])],
  ["no child process spawned and executable sentinels untouched", expected("preserved", [["contract-tests", "architecture checker rejects grouped and aliased process imports"], ["contract-tests", "architecture checker rejects grouped and aliased PATH access"], ["repository-windows", "every_execution_capable_git_configuration_fails_closed_and_stays_inert"]])],
  ["browser recovery and accessibility", expected("supported", [["browser-tests", "renders authoritative workspace state and guards recovery actions"], ["browser-tests", "supports keyboard flow, reduced motion, narrow reflow, and contrast"]])],
]);

const approvalBlockers = new Map([
  ["filterDisabling", ["CRLF configuration with checkout filters disabled"]],
  ["pathContainment", ["static and swap-race junctions/symlinks", "UNC/device/ADS rejection", "nested/common-dir/artifact-root target rejection"]],
  ["sha256ExactOids", ["SHA-1/SHA-256 exact IDs"]],
  ["noForceConditionalRefs", ["branch/path/CAS conflicts"]],
  ["worktrees", ["all post-add rollback boundaries", "clean/dirty/original-index preservation"]],
  ["lfsSubmoduleEvidence", ["submodule/LFS and execution-capable Git configuration"]],
]);

try {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  assert(manifest.schemaVersion === 2, "unsupported manifest schema");
  assert(manifest.finalized === true, "manifest is not finalized");
  assert(/^([0-9a-f]{40}|[0-9a-f]{64})$/.test(manifest.sourceCommit), "invalid source commit");
  verifyCommitBinding(manifest.sourceCommit, historical);
  assert(manifest.platform === `${process.platform}-${process.arch}`, "platform mismatch");
  assertDeepEqual(manifest.toolVersions, currentToolVersions(), "toolchain mismatch");

  assert(Array.isArray(manifest.commands), "commands must be an array");
  assert(manifest.commands.length === requiredCommands.size, "unexpected command evidence count");
  const commands = new Map();
  for (const entry of manifest.commands) {
    assert(!commands.has(entry.name), `duplicate command evidence: ${entry.name}`);
    commands.set(entry.name, entry);
  }
  const generatedAt = Date.parse(manifest.generatedAtUtc);
  assert(!Number.isNaN(generatedAt), "invalid manifest timestamp");
  for (const [name, command] of requiredCommands) {
    const entry = commands.get(name);
    assert(entry, `missing command evidence: ${name}`);
    assert(entry.command === command, `command mismatch: ${name}`);
    assert(entry.command !== "node scripts/verify-m1-evidence.mjs", "verifier may not attest itself");
    assert(entry.exitCode === 0, `command did not pass: ${command}`);
    assert(Number.isInteger(entry.durationMs) && entry.durationMs >= 0, `invalid duration: ${command}`);
    const started = Date.parse(entry.startedAtUtc);
    assert(!Number.isNaN(started), `invalid timestamp: ${command}`);
    assert(started + entry.durationMs <= generatedAt + 1_000, `manifest predates command: ${command}`);
    assert(/^outputs\/[a-z0-9-]+\.log$/.test(entry.outputFile), `invalid output path: ${command}`);
    const output = readFileSync(join(artifactRoot, entry.outputFile));
    assert(entry.outputSha256 === hash(output), `output hash mismatch: ${command}`);
    if (name === "contract-tests") {
      assert(!output.toString("utf8").includes("# SKIP"), "generation contract was skipped");
    }
  }

  assert(Array.isArray(manifest.fixtureClassifications), "fixtures must be an array");
  assert(manifest.fixtureClassifications.length === requiredFixtures.size, "unexpected fixture count");
  const actualFixtures = new Map(
    manifest.fixtureClassifications.map((entry) => [entry.case, entry]),
  );
  for (const [caseName, expectedFixture] of requiredFixtures) {
    const actual = actualFixtures.get(caseName);
    assert(actual, `missing fixture classification: ${caseName}`);
    assert(actual.classification === expectedFixture.classification, `fixture classification mismatch: ${caseName}`);
    assertDeepEqual(actual.evidence, expectedFixture.evidence, `fixture evidence mismatch: ${caseName}`);
    for (const item of expectedFixture.evidence) {
      const command = commands.get(item.command);
      const output = readFileSync(join(artifactRoot, command.outputFile), "utf8");
      assert(output.includes(item.needle), `test evidence not observed: ${caseName} -> ${item.needle}`);
    }
  }
  for (const [blocker, cases] of approvalBlockers) {
    assert(cases.every((caseName) => actualFixtures.has(caseName)), `M1 approval blocked: ${blocker}`);
  }

  for (const file of ["review.md", "known-limitations.md", "toolchain.txt"]) {
    assert(
      manifest.artifactSha256[file] === hash(readFileSync(join(artifactRoot, file))),
      `artifact hash mismatch: ${file}`,
    );
  }
  console.log("M1 evidence: ok");
} catch (error) {
  console.error(`M1 evidence: ${error.message}`);
  process.exitCode = 1;
}

function verifyCommitBinding(sourceCommit, allowHistorical) {
  if (!allowHistorical) assertEvidenceOnlyChanges(root);
  const head = commandOutput("git rev-parse HEAD");
  if (head !== sourceCommit) {
    const ancestor = spawnSync("git", ["merge-base", "--is-ancestor", sourceCommit, head], {
      cwd: root,
      windowsHide: true,
    });
    assert(ancestor.status === 0, "evidence source commit is not an ancestor of HEAD");
    if (allowHistorical) return;
    const changed = commandOutput(`git diff --name-only ${sourceCommit}..${head}`)
      .split(/\r?\n/u)
      .filter(Boolean);
    assert(
      changed.length > 0
        && changed.every((path) => path.startsWith("artifacts/verification/m1/")),
      "evidence source commit is stale for the current code",
    );
  }
}

function currentToolVersions() {
  return {
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    node: process.version,
    pnpm: commandOutput("pnpm --version"),
    git: commandOutput("git --version"),
    rustup: commandOutput("rustup --version").split("\n")[0],
    rustToolchain: commandOutput("rustup show active-toolchain"),
    rustc: commandOutput("rustc --version"),
    cargo: commandOutput("cargo --version"),
  };
}

function commandOutput(command) {
  const result = spawnSync(command, {
    cwd: root,
    encoding: "utf8",
    shell: true,
    windowsHide: true,
  });
  assert(result.status === 0, `unable to run ${command}`);
  return result.stdout.trim();
}

function expected(classification, evidenceItems) {
  return {
    classification,
    evidence: evidenceItems.map(([command, needle]) => ({ command, needle })),
  };
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function assertDeepEqual(actual, expectedValue, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expectedValue), message);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
