export const commands = [
  ["frozen-install", "pnpm install --frozen-lockfile"],
  ["design-contracts", "node scripts/verify-design-contracts.mjs"],
  ["architecture", "node scripts/check-architecture.mjs"],
  [
    "source-contracts",
    "node --test tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs tests/contracts/m1-contracts.test.mjs tests/contracts/m2-contracts.test.mjs",
  ],
  ["rust-format", "cargo fmt --all -- --check"],
  [
    "rust-clippy",
    "cargo clippy --workspace --all-targets --all-features -- -D warnings",
  ],
  ["rust-tests", "cargo test --workspace --all-targets"],
  ["rust-all-features", "cargo test --workspace --all-features"],
  ["rust-doc", "cargo test --workspace --doc"],
  [
    "probe-format",
    "cargo fmt --manifest-path tests/fixtures/m2-containment-probe/Cargo.toml -- --check",
  ],
  [
    "probe-clippy",
    "cargo clippy --manifest-path tests/fixtures/m2-containment-probe/Cargo.toml --all-targets -- -D warnings",
  ],
  [
    "tool-security-matrix",
    "cargo test -p local-agent-terminal-tool-runtime --test security_matrix",
  ],
  [
    "platform-windows",
    "cargo test -p local-agent-terminal-platform-windows --test filesystem_matrix --test process_matrix",
  ],
  [
    "platform-windows-seams",
    "cargo test -p local-agent-terminal-platform-windows --features test-seams --test filesystem_matrix --test process_matrix",
  ],
  [
    "tool-broker-e2e",
    "cargo test -p local-agent-terminal-bootstrap --test tool_broker_e2e --test tool_recovery",
  ],
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

export const containmentCases = [
  containment("direct OS repository/original/sibling/profile/appdata/capability canaries", "fail-closed", [
    evidence("platform-windows", "real_lpac_denies_filesystem_path_environment_and_network_hostile_matrix"),
  ]),
  containment("loopback/LAN/internet denial", "fail-closed", [
    evidence("platform-windows", "real_lpac_denies_filesystem_path_environment_and_network_hostile_matrix"),
    evidence("platform-windows-seams", "lpac_network_denial_is_stronger_than_the_paired_ordinary_appcontainer_control"),
  ]),
  containment("empty-by-default environment and provider credentials", "preserved", [
    evidence("platform-windows", "real_lpac_denies_filesystem_path_environment_and_network_hostile_matrix"),
    evidence("platform-windows-seams", "child_environment_starts_empty_and_does_not_inherit_parent_canary"),
  ]),
  containment("registry, credential, and named-pipe isolation", "fail-closed", [
    evidence("platform-windows", "real_lpac_denies_filesystem_path_environment_and_network_hostile_matrix"),
  ]),
  containment("junction/symlink/UNC/device/ADS/case/Unicode/long/replacement paths", "fail-closed", [
    evidence("platform-windows", "real_lpac_denies_filesystem_path_environment_and_network_hostile_matrix"),
    evidence("platform-windows", "unicode_normalization_is_exact_and_non_disclosing"),
    evidence("platform-windows-seams", "replacement_races_are_contained_by_retained_and_exact_file_handles"),
  ]),
  containment("stale fencing and replacement", "fail-closed", [
    evidence("tool-security-matrix", "stale_write_has_zero_target_or_durable_effect"),
    evidence("tool-security-matrix", "runtime_initial_check_cannot_bypass_final_windows_resume_fence"),
  ]),
  containment("executable identity, digest, and PATH replacement", "fail-closed", [
    evidence("platform-windows", "executable_registry_rejects_path_lookup_version_drift_and_replacement"),
    evidence("tool-security-matrix", "old_approval_executable_identity_replacement_never_reaches_launcher"),
  ]),
  containment("argv metacharacters and response files", "preserved", [
    evidence("tool-security-matrix", "typed_process_exec_resolves_profiles_and_preserves_argv_boundaries"),
    evidence("tool-security-matrix", "response_file_arguments_are_denied_before_launch"),
  ]),
  containment("ordinary/detached/breakaway descendants", "fail-closed", [
    evidence("platform-windows", "real_lpac_denies_registered_descendant_creation_modes"),
    evidence("platform-windows-seams", "cancellation_terminates_descendants_and_breakaway_is_denied"),
  ]),
  containment("output/process/memory/CPU/wall budgets", "enforced", [
    evidence("platform-windows", "output_overflow_terminates_the_job_and_returns_only_the_bound"),
    evidence("platform-windows", "memory_job_limit_denies_additional_committed_memory"),
    evidence("platform-windows", "cpu_job_limit_terminates_busy_process_before_wall_timeout"),
    evidence("platform-windows", "bounded_inert_helper_outlives_a_short_real_lpac_timeout"),
  ]),
  containment("structured file-write size budget", "enforced", [
    evidence("platform-windows", "oversized_write_is_denied_before_target_or_temp_mutation"),
  ]),
  containment("unenforceable boundaries start no process", "fail-closed", [
    evidence("platform-windows", "missing_os_containment_denies_before_child_code_runs"),
    evidence("platform-windows", "lpac_rejects_non_denied_network_before_resume"),
    evidence("platform-windows-seams", "requested_disk_write_budget_fails_closed_before_child_creation"),
  ]),
  containment("structured read/write/status/diff paths", "policy-bound", [
    evidence("tool-security-matrix", "file_read_forces_resolved_digest_records_authoritative_decision_and_returns_only_effective_bytes"),
    evidence("tool-security-matrix", "write_holds_the_exact_durable_call_order"),
    evidence("tool-security-matrix", "git_status_is_policy_bound_before_bytes_cross_the_runtime_boundary"),
    evidence("tool-security-matrix", "git_diff_copies_only_validated_metadata_and_policy_bound_effective_bytes"),
  ]),
  containment("approval, intent, execution, artifact, and event reconstruction", "reconstructible", [
    evidence("tool-broker-e2e", "journaled_tool_publishers_persist_distinct_verified_artifacts_and_exact_relation"),
    evidence("tool-broker-e2e", "configured_runtime_projects_exact_approval_context_and_rejects_a_stale_digest"),
  ]),
  containment("cancellation, shutdown, and restart leave no survivor", "terminated", [
    evidence("tool-broker-e2e", "stop_all_cancels_and_joins_a_runtime_owned_execution"),
    evidence("tool-broker-e2e", "startup_recovery_terminates_exact_retained_job_and_never_relaunches"),
    evidence("platform-windows-seams", "explicit_cancellation_terminates_a_live_real_lpac_root"),
  ]),
  containment("stale approval UI and accessibility", "supported", [
    evidence("browser-tests", "invalidates a replaced approval without resolving the stale digest"),
    evidence("browser-tests", "confirms stop-all and passes reduced-motion, zoom, reflow, contrast, and axe"),
  ]),
];

function containment(caseName, classification, evidenceItems) {
  return { case: caseName, classification, evidence: evidenceItems };
}

function evidence(command, needle) {
  return { command, needle };
}
