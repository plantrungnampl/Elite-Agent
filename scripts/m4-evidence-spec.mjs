const contextPackage = "local-agent-terminal-context-engine";
const bootstrapPackage = "local-agent-terminal-bootstrap";
const orchestrationPackage = "local-agent-terminal-orchestration";
const storagePackage = "local-agent-terminal-storage-sqlite";
const openAiPackage = "local-agent-terminal-provider-openai";
const anthropicPackage = "local-agent-terminal-provider-anthropic";

export const designBaseline = "9b182a3";

export const commands = [
  ["source-contracts", "node --test tests/contracts/*.test.mjs"],
  ["design-contracts", "node scripts/verify-design-contracts.mjs"],
  ["architecture", "node scripts/check-architecture.mjs --require-m4"],
  ["rust-format", "cargo fmt --all -- --check"],
  ["rust-check", "cargo check --workspace --all-targets"],
  [
    "rust-clippy",
    "cargo clippy --workspace --all-targets --all-features -- -D warnings",
  ],
  ["rust-tests-all-targets", "cargo test --workspace --all-targets"],
  ["rust-tests-all-features", "cargo test --workspace --all-features"],
  ["rust-doc", "cargo test --workspace --doc"],
  [
    "m0-m3-regressions",
    "node --test tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs tests/contracts/m1-contracts.test.mjs tests/contracts/m2-contracts.test.mjs tests/contracts/m2-evidence-contracts.test.mjs tests/contracts/m3-contracts.test.mjs tests/contracts/m3-evidence-contracts.test.mjs",
  ],
  [
    "context-security",
    `cargo test -p ${contextPackage} --test pre_index_filter --test package_contract`,
  ],
  [
    "retrieval-freshness",
    `cargo test -p ${contextPackage} --test retrieval --test package_contract`,
  ],
  [
    "two-provider-conformance",
    `cargo test -p ${openAiPackage} -p ${anthropicPackage} --test conformance --test request_contract --test streaming_contract`,
  ],
  [
    "deliberation-recovery",
    `cargo test -p ${bootstrapPackage} --test deliberation_e2e --test deliberation_recovery`,
  ],
  [
    "exact-plan-approval",
    `cargo test -p ${storagePackage} --test plan_approval_store`,
  ],
  [
    "preapproval-no-mutation",
    `cargo test -p ${orchestrationPackage} --test zero_mutation`,
  ],
  ["frontend-tests", "pnpm --dir apps/desktop test --run --reporter=verbose"],
  ["frontend-build", "pnpm --dir apps/desktop build"],
  [
    "browser-accessibility",
    "pnpm --dir apps/desktop test:browser -- --reporter=line",
  ],
  ["desktop-debug-build", "cargo build -p local-agent-terminal-desktop"],
  ["diff-check", "git diff --check"],
  [
    "design-docs-unchanged",
    `git diff --exit-code ${designBaseline} -- docs/multi-agent-terminal-design`,
  ],
];

export const verificationMatrices = [
  {
    name: "m0-m3-regressions",
    evidence: [
      {
        command: "m0-m3-regressions",
        needle: "architecture checker accepts the production workspace",
      },
      {
        command: "m0-m3-regressions",
        needle: "M2 evidence is complete and internally consistent",
      },
      {
        command: "m0-m3-regressions",
        needle: "M3 evidence is complete and internally consistent",
      },
    ],
  },
  {
    name: "context-security",
    evidence: [
      {
        command: "context-security",
        needle: "redacted_names_and_denied_injection_canaries_never_reach_persistence",
      },
      {
        command: "context-security",
        needle: "rejects_final_disclosure_that_rewrites_the_canonical_package",
      },
      {
        command: "deliberation-recovery",
        needle: "real_source_policy_and_storage_block_secrets_before_index_and_bind_the_package",
      },
    ],
  },
  {
    name: "retrieval-freshness",
    evidence: [
      {
        command: "retrieval-freshness",
        needle: "ranks_exact_path_symbol_and_terms_before_stable_tie_order",
      },
      {
        command: "retrieval-freshness",
        needle: "excludes_noncurrent_cross_task_and_changed_sources_and_deduplicates_hashes",
      },
      {
        command: "retrieval-freshness",
        needle: "package_bytes_digest_relations_and_citations_are_stable_and_complete",
      },
    ],
  },
  {
    name: "two-provider-conformance",
    evidence: [
      {
        command: "two-provider-conformance",
        needle: "openai_adapter_passes_shared_conformance_against_loopback_sse_fixtures",
      },
      {
        command: "two-provider-conformance",
        needle: "anthropic_adapter_passes_shared_conformance_against_loopback_sse_fixtures",
      },
      {
        command: "two-provider-conformance",
        needle: "sanitizes_api_key_reflected_by_provider_response_ids",
      },
      {
        command: "deliberation-recovery",
        needle: "heterogeneous_loopback_proposals_remain_private_until_quorum_publication",
      },
    ],
  },
  {
    name: "deliberation-recovery",
    evidence: [
      {
        command: "deliberation-recovery",
        needle: "two_role_specific_packages_bind_exact_policy_redaction_and_provenance",
      },
      {
        command: "deliberation-recovery",
        needle: "provider_failure_isolated_and_restart_reconstructs_exact_parallel_run",
      },
    ],
  },
  {
    name: "ui-browser-accessibility",
    evidence: [
      {
        command: "frontend-tests",
        needle: "rejects replacement payloads before invoking a privileged command",
      },
      {
        command: "browser-accessibility",
        needle: "supports keyboard context inspection and a digest-bound plan decision",
      },
      {
        command: "browser-accessibility",
        needle: "invalidates stale approval authority and passes reflow, targets, motion, contrast, and axe",
      },
    ],
  },
  {
    name: "exact-plan-approval",
    evidence: [
      {
        command: "exact-plan-approval",
        needle: "pending_plan_request_reloads_and_resolves_exactly_once_across_reopen",
      },
      {
        command: "exact-plan-approval",
        needle: "live_repository_change_rejects_resolution_across_reopen_without_mutation",
      },
      {
        command: "exact-plan-approval",
        needle: "live_policy_change_rejects_resolution_across_reopen_without_mutation",
      },
    ],
  },
  {
    name: "repository-no-mutation",
    evidence: [
      {
        command: "preapproval-no-mutation",
        needle: "preapproval_path_queries_only_typed_read_catalog_and_never_calls_mutation_adapters",
      },
      {
        command: "deliberation-recovery",
        needle: "heterogeneous_loopback_proposals_remain_private_until_quorum_publication",
      },
    ],
  },
];

export const credentialCanary = {
  markerPrefix: "M4_CREDENTIAL_CANARY_",
};
