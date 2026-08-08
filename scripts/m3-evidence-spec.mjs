const protocolPackage = "local-agent-terminal-agent-protocol";
const runtimePackage = "local-agent-terminal-agent-runtime";
const providerPackage = "local-agent-terminal-provider-openai";
const bootstrapPackage = "local-agent-terminal-bootstrap";

export const commands = [
  [
    "source-contracts",
    "node --test tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs tests/contracts/m1-contracts.test.mjs tests/contracts/m2-contracts.test.mjs tests/contracts/m2-evidence-contracts.test.mjs tests/contracts/m3-contracts.test.mjs",
  ],
  ["design-contracts", "node scripts/verify-design-contracts.mjs"],
  ["architecture", "node scripts/check-architecture.mjs --require-m3"],
  ["rust-format", "cargo fmt --all -- --check"],
  ["rust-check", "cargo check --workspace --all-targets"],
  [
    "rust-clippy",
    "cargo clippy --workspace --all-targets --all-features -- -D warnings",
  ],
  ["rust-tests", "cargo test --workspace --all-targets"],
  ["rust-all-features", "cargo test --workspace --all-features"],
  ["rust-doc", "cargo test --workspace --doc"],
  [
    "protocol-schema-conformance",
    `cargo test -p ${protocolPackage} --test schema_types --test codec`,
  ],
  [
    "hostile-protocol",
    `cargo test -p ${protocolPackage} --test session_contract --test conformance`,
  ],
  [
    "fake-agent-runtime",
    `cargo test -p ${runtimePackage} --test runtime_contract --test fake_conformance`,
  ],
  [
    "openai-loopback",
    `cargo test -p ${providerPackage} --test conformance`,
  ],
  [
    "provider-neutral-credentials",
    `cargo test -p ${providerPackage} --test request_contract --test streaming_contract`,
  ],
  [
    "persistence-recovery",
    `cargo test -p ${bootstrapPackage} --test agent_runtime_e2e --test agent_recovery`,
  ],
  ["frontend-tests", "pnpm --dir apps/desktop test --run"],
  ["frontend-build", "pnpm --dir apps/desktop build"],
  ["desktop-debug-build", "cargo build -p local-agent-terminal-desktop"],
  ["diff-check", "git diff --check"],
  [
    "design-docs-unchanged",
    "git diff --exit-code 321734f -- docs/multi-agent-terminal-design",
  ],
];

export const verificationMatrices = [
  {
    name: "protocol-schema-conformance",
    evidence: [
      {
        command: "protocol-schema-conformance",
        needle: "every_protocol_example_round_trips_through_generated_types",
      },
      {
        command: "protocol-schema-conformance",
        needle: "consumes_hostile_ndjson_fixtures",
      },
    ],
  },
  {
    name: "hostile-protocol",
    evidence: [
      {
        command: "protocol-schema-conformance",
        needle: "enforces_configured_limits_before_deserialization",
      },
      {
        command: "hostile-protocol",
        needle: "enforces_connection_unique_request_ids_and_response_provenance",
      },
      {
        command: "hostile-protocol",
        needle: "enforces_method_ownership_and_never_responds_to_notifications",
      },
      {
        command: "hostile-protocol",
        needle: "rejects_foreign_runs_and_terminalizes_runs_after_stream_sequence_violations",
      },
      {
        command: "hostile-protocol",
        needle: "rejects_terminal_frames_before_start_and_after_the_one_terminal_result",
      },
    ],
  },
  {
    name: "fake-agent-runtime",
    evidence: [
      {
        command: "fake-agent-runtime",
        needle: "proposer_critic_and_verifier_outputs_are_stable_for_the_same_bound_input",
      },
      {
        command: "fake-agent-runtime",
        needle: "duplicate_and_conflicting_terminal_requests_commit_one_result",
      },
      {
        command: "fake-agent-runtime",
        needle: "heartbeat_timeout_and_crash_interrupt_active_runs",
      },
      {
        command: "fake-agent-runtime",
        needle: "cancellation_and_run_deadlines_are_classified_as_terminated",
      },
      {
        command: "fake-agent-runtime",
        needle: "every_hostile_peer_failure_terminates_the_run",
      },
      {
        command: "fake-agent-runtime",
        needle: "every_script_passes_the_shared_protocol_conformance_matrix",
      },
    ],
  },
  {
    name: "openai-loopback",
    evidence: [
      {
        command: "openai-loopback",
        needle: "openai_adapter_passes_shared_conformance_against_loopback_sse_fixtures",
      },
      {
        command: "provider-neutral-credentials",
        needle: "rejects_invalid_oversized_and_premature_sse_streams",
      },
      {
        command: "provider-neutral-credentials",
        needle: "rejects_oversized_prompt_and_hosted_tools_before_contacting_the_provider",
      },
      {
        command: "provider-neutral-credentials",
        needle: "classifies_http_failures_and_preserves_valid_retry_after_without_retrying",
      },
    ],
  },
  {
    name: "persistence-recovery",
    evidence: [
      {
        command: "persistence-recovery",
        needle: "loopback_sse_persists_a_terminal_run_and_reconstructs_its_bound_inputs_after_reopen",
      },
      {
        command: "persistence-recovery",
        needle: "accepted_cancellation_terminalizes_cleanly_without_changing_the_task_workflow",
      },
      {
        command: "persistence-recovery",
        needle: "openai_outage_terminalizes_the_agent_run_without_changing_the_task_workflow",
      },
      {
        command: "persistence-recovery",
        needle: "restart_interrupts_an_incomplete_openai_run_and_reconstructs_its_durable_inputs",
      },
      {
        command: "persistence-recovery",
        needle: "successful_runs_before_and_after_bootstrap_restart_persist_distinct_messages",
      },
    ],
  },
  {
    name: "provider-neutral-credentials",
    evidence: [
      {
        command: "provider-neutral-credentials",
        needle: "posts_bound_request_and_keeps_api_key_off_everything_except_wire",
      },
      {
        command: "provider-neutral-credentials",
        needle: "sanitizes_api_key_reflected_by_provider_response_ids",
      },
      {
        command: "provider-neutral-credentials",
        needle: "rejects_non_https_or_non_loopback_http_endpoints_without_leaking_the_key",
      },
      {
        command: "persistence-recovery",
        needle: "non_openai_provider_is_rejected_before_publication_or_loopback_dispatch",
      },
    ],
  },
];

export const credentialCanary = {
  markerPrefix: "M3_CREDENTIAL_CANARY_",
};
