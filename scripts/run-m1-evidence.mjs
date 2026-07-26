import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const artifactRoot = join(root, "artifacts", "verification", "m1");
const outputRoot = join(artifactRoot, "outputs");
const manifestPath = join(artifactRoot, "manifest.json");
const temporaryManifestPath = `${manifestPath}.tmp`;

const commands = [
  ["frozen-install", "pnpm install --frozen-lockfile"],
  ["design-contracts", "node scripts/verify-design-contracts.mjs"],
  ["architecture", "node scripts/check-architecture.mjs"],
  [
    "repository-windows",
    "cargo test -p local-agent-terminal-repository-git --test windows_matrix --features test-seams",
  ],
  [
    "recovery-matrix",
    "cargo test -p local-agent-terminal-bootstrap --test recovery_matrix",
  ],
  ["contract-tests", "node --test tests/contracts/*.test.mjs"],
  ["rust-format", "cargo fmt --all -- --check"],
  ["rust-clippy", "cargo clippy --workspace --all-targets -- -D warnings"],
  ["rust-tests", "cargo test --workspace --all-targets"],
  ["frontend-tests", "pnpm --dir apps/desktop test --run"],
  [
    "playwright-install",
    "pnpm --dir apps/desktop exec playwright install chromium",
  ],
  ["browser-tests", "pnpm --dir apps/desktop test:browser"],
  ["frontend-build", "pnpm --dir apps/desktop build"],
  ["desktop-debug-build", "cargo build -p local-agent-terminal-desktop"],
  ["diff-check", "git diff --check"],
  ["committed-diff-check", "git diff --check 321734f..HEAD"],
  [
    "design-docs-unchanged",
    "git diff --exit-code 321734f -- docs/multi-agent-terminal-design",
  ],
];

const fixtureClassifications = [
  fixture("clean/dirty/original-index preservation", "preserved", [
    evidence("repository-windows", "successful_unicode_worktree_preserves_original_head_index_and_checkout_bytes"),
    evidence("repository-windows", "worktree_creation_rejects_a_dirty_original_checkout"),
  ]),
  fixture("spaces/metacharacters", "supported", [
    evidence("repository-windows", "valid_windows_shell_metacharacters_are_supported_in_managed_paths"),
  ]),
  fixture("Unicode", "supported", [
    evidence("repository-windows", "successful_unicode_worktree_preserves_original_head_index_and_checkout_bytes"),
  ]),
  fixture("long paths", "fail-closed", [
    evidence("repository-windows", "long_path_checkout_fails_closed_without_mutating_original_state"),
  ]),
  fixture("locks", "fail-closed", [
    evidence("repository-windows", "ref_lock_and_base_cas_conflicts_leave_branch_target_and_index_absent"),
  ]),
  fixture("static and swap-race junctions/symlinks", "fail-closed", [
    evidence("repository-windows", "static_symlink_target_is_rejected_without_touching_its_destination"),
    evidence("repository-windows", "parent_swap_race_is_blocked_while_checkout_is_in_progress"),
  ]),
  fixture("UNC/device/ADS rejection", "fail-closed", [
    evidence("repository-windows", "invalid_windows_target_forms_are_rejected_without_git_side_effects"),
  ]),
  fixture("nested/common-dir/artifact-root target rejection", "fail-closed", [
    evidence("repository-windows", "target_inside_original_checkout_and_case_collisions_fail_closed"),
    evidence("repository-windows", "excluded_artifact_root_and_git_common_dir_targets_are_rejected"),
  ]),
  fixture("branch/path/CAS conflicts", "fail-closed", [
    evidence("repository-windows", "branch_conflict_is_preserved_without_creating_target"),
    evidence("repository-windows", "rollback_preserves_a_concurrently_replaced_branch"),
    evidence("repository-windows", "rollback_preserves_a_concurrently_replaced_target"),
  ]),
  fixture("all post-add rollback boundaries", "recovered", [
    evidence("repository-windows", "every_post_add_failure_rolls_back_owned_state"),
  ]),
  fixture("crash boundaries and pending/started intent recovery", "recovered", [
    evidence("rust-tests", "crash_boundaries_reconcile_to_deterministic_states"),
    evidence("recovery-matrix", "startup_leaves_pending_intent_for_exact_command_retry_without_git_effects"),
    evidence("recovery-matrix", "startup_adopts_only_the_exact_durable_worktree"),
  ]),
  fixture("stale lease replacement", "recovered", [
    evidence("rust-tests", "stale_monitor_claim_is_rejected_before_evidence_or_repository_bytes_change"),
    evidence("rust-tests", "lease_replacement_increments_token_and_stale_claim_cannot_write"),
  ]),
  fixture("projection-only replay", "preserved", [
    evidence("recovery-matrix", "repeated_startup_replays_recovery_projection_without_duplicate_side_effects"),
  ]),
  fixture("approval/candidate invalidation rollback", "preserved", [
    evidence("rust-tests", "workspace_mutation_is_atomic_and_invalidates_candidate_approvals"),
    evidence("rust-tests", "mutation_rolls_back_event_projection_approvals_candidate_and_lease_together"),
  ]),
  fixture("unknown intent handling", "recovered", [
    evidence("recovery-matrix", "startup_marks_unknown_operations_indeterminate_without_touching_git"),
  ]),
  fixture("SHA-1/SHA-256 exact IDs", "supported", [
    evidence("repository-windows", "sha256_repository_keeps_exact_object_ids"),
  ]),
  fixture("submodule/LFS and execution-capable Git configuration", "fail-closed", [
    evidence("repository-windows", "repository_hazards_are_classified_before_worktree_side_effects"),
    evidence("repository-windows", "every_execution_capable_git_configuration_fails_closed_and_stays_inert"),
  ]),
  fixture("shallow/sparse/detached/unborn repositories", "fail-closed", [
    evidence("repository-windows", "shallow_and_sparse_repositories_fail_closed"),
    evidence("repository-windows", "dirty_detached_and_unborn_states_are_explicit"),
  ]),
  fixture("CRLF configuration with checkout filters disabled", "supported", [
    evidence("repository-windows", "checkout_disables_crlf_filters_and_preserves_blob_bytes"),
  ]),
  fixture("no child process spawned and executable sentinels untouched", "preserved", [
    evidence("contract-tests", "repository adapter rejects process execution"),
    evidence("contract-tests", "architecture checker rejects grouped and aliased process imports"),
    evidence("repository-windows", "every_execution_capable_git_configuration_fails_closed_and_stays_inert"),
  ]),
  fixture("browser recovery and accessibility", "supported", [
    evidence("browser-tests", "renders authoritative workspace state and guards recovery actions"),
    evidence("browser-tests", "supports keyboard flow, reduced motion, narrow reflow, and contrast"),
  ]),
];

try {
  mkdirSync(artifactRoot, { recursive: true });
  rmSync(outputRoot, { recursive: true, force: true });
  mkdirSync(outputRoot, { recursive: true });
  rmSync(manifestPath, { force: true });
  rmSync(temporaryManifestPath, { force: true });

  const sourceCommit = commandOutput("git rev-parse HEAD");
  const toolVersions = currentToolVersions();
  writeFileSync(
    join(artifactRoot, "toolchain.txt"),
    Object.entries(toolVersions)
      .map(([name, value]) => `${name}=${value}`)
      .join("\n") + "\n",
  );

  const commandEvidence = [];
  for (const [name, command] of commands) {
    commandEvidence.push(await runCommand(name, command));
  }

  const manifest = {
    schemaVersion: 2,
    finalized: true,
    generatedAtUtc: new Date().toISOString(),
    sourceCommit,
    platform: `${process.platform}-${process.arch}`,
    outputCapture: "combined stdout/stderr bytes normalized to LF",
    toolVersions,
    commands: commandEvidence,
    fixtureClassifications,
    artifactSha256: Object.fromEntries(
      ["review.md", "known-limitations.md", "toolchain.txt"].map((name) => [
        name,
        hash(readFileSync(join(artifactRoot, name))),
      ]),
    ),
  };
  writeFileSync(temporaryManifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  renameSync(temporaryManifestPath, manifestPath);
  console.log(`M1 evidence generated for ${sourceCommit}`);
} catch (error) {
  rmSync(temporaryManifestPath, { force: true });
  console.error(`M1 evidence generation failed: ${error.message}`);
  process.exitCode = 1;
}

async function runCommand(name, command) {
  const startedAtUtc = new Date().toISOString();
  const started = process.hrtime.bigint();
  const chunks = [];
  const exitCode = await new Promise((resolveExit, reject) => {
    const child = spawn(command, {
      cwd: root,
      env: { ...process.env, M1_EVIDENCE_GENERATING: "1" },
      shell: true,
      windowsHide: true,
    });
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => {
        chunks.push(chunk);
        process.stdout.write(chunk);
      });
    }
    child.on("error", reject);
    child.on("close", (code) => resolveExit(code ?? 1));
  });
  const durationMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
  const output = normalizeOutput(Buffer.concat(chunks));
  const outputFile = `outputs/${name}.log`;
  writeFileSync(join(artifactRoot, outputFile), output);
  if (exitCode !== 0) throw new Error(`${command} exited with ${exitCode}`);
  return {
    name,
    command,
    exitCode,
    startedAtUtc,
    durationMs,
    outputFile,
    outputSha256: hash(output),
  };
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
  if (result.status !== 0) throw new Error(`unable to run ${command}`);
  return result.stdout.trim();
}

function normalizeOutput(output) {
  return Buffer.from(output.toString("utf8").replaceAll("\r\n", "\n"), "utf8");
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function fixture(caseName, classification, evidenceItems) {
  return { case: caseName, classification, evidence: evidenceItems };
}

function evidence(command, needle) {
  return { command, needle };
}
