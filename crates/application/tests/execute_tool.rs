use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_approval_payload, canonical_policy_binding_digest,
    canonical_tool_request, parse_tool_request, ApprovalDigestPayload, ApprovedExecutableIdentity,
    ApprovedProcessRequest, AuthorizedToolRequest, BoundToolApproval, BoundedOutput,
    CancellationReceipt, DurableToolExecutionArtifact, DurableToolExecutionArtifacts,
    DurableToolExecutionOutcome, DurableToolExecutionReceipt, ExecuteDurableTool, IdempotencyClass,
    IncompleteToolExecution, JobReceipt, NewToolExecution, NewToolIntent, OperationIntentSnapshot,
    PortError, ProcessReceipt, ProcessStatus, ResolvedExecutable, Retryability,
    SafeErrorClassification, SafeToolExecutionError, StructuredToolExecutor,
    ToolApprovalOperationV1, ToolApprovalPayloadV1, ToolExecutionClaim,
    ToolExecutionClaimAuthority, ToolExecutionId, ToolExecutionOutput,
    ToolExecutionRecoveryEvidence, ToolExecutionResolution, ToolExecutionResult,
    ToolExecutionStore, ToolExecutionTerminal, ToolExecutionTerminalKind, ToolPolicyContext,
    ToolRequest,
};
use sha2::{Digest, Sha256};

#[test]
fn immutable_tool_request_round_trips_without_approval_material() {
    let request = tool_request("test");
    let canonical = canonical_tool_request(&request).unwrap();

    assert_eq!(
        parse_tool_request(canonical.canonical_bytes()).unwrap(),
        canonical
    );
    assert_eq!(canonical.request(), &request);
    assert!(std::str::from_utf8(canonical.canonical_bytes())
        .unwrap()
        .contains(r#""schema":"tool-request.v1""#));
    let wire: serde_json::Value = serde_json::from_slice(canonical.canonical_bytes()).unwrap();
    assert!(wire.get("approval").is_none());
    for approval_field in [
        "approvalId",
        "summary",
        "requestedAt",
        "expiresAt",
        "nonce",
        "scopes",
    ] {
        assert!(wire.get(approval_field).is_none());
    }
    assert_ne!(
        canonical.binding_digest().as_sha256(),
        &canonical_approval_payload(&ApprovalDigestPayload::Tool(
            approved_tool_binding(request.process()).payload().clone()
        ))
        .unwrap()
        .operation_digest
    );
}

#[test]
fn tool_request_binding_covers_every_canonical_wire_leaf_and_list() {
    let canonical = canonical_tool_request(&rich_tool_request()).unwrap();
    let wire: serde_json::Value = serde_json::from_slice(canonical.canonical_bytes()).unwrap();
    let expected_paths = [
        "/executionId",
        "/policy/action",
        "/policy/actor/agentId",
        "/policy/actor/connectionId",
        "/policy/actor/locality",
        "/policy/actor/trustTier",
        "/policy/policySnapshotDigest",
        "/policy/purpose",
        "/policy/resource/capability/kind",
        "/policy/resource/capability/path",
        "/policy/resource/capability/taskId",
        "/policy/resource/contentDigest",
        "/policy/resource/resourceClass",
        "/policy/taskRisk",
        "/process/approvedExecutable/canonicalPath",
        "/process/approvedExecutable/fileIdentity",
        "/process/approvedExecutable/sha256",
        "/process/approvedExecutable/toolchainId",
        "/process/approvedExecutable/version",
        "/process/argv",
        "/process/argv/0",
        "/process/cpuTimeLimitMs",
        "/process/cwd/kind",
        "/process/cwd/path",
        "/process/cwd/taskId",
        "/process/environmentProfile/digest",
        "/process/environmentProfile/name",
        "/process/executable/kind",
        "/process/executable/name",
        "/process/executorFencingToken",
        "/process/expectedReads",
        "/process/expectedReads/0/kind",
        "/process/expectedReads/0/path",
        "/process/expectedReads/0/revision",
        "/process/expectedWrites",
        "/process/expectedWrites/0/kind",
        "/process/expectedWrites/0/path",
        "/process/expectedWrites/0/taskId",
        "/process/memoryLimitBytes",
        "/process/networkProfile",
        "/process/planStepId",
        "/process/runId",
        "/process/schema",
        "/process/taskId",
        "/process/timeoutMs",
        "/process/trustTier",
        "/process/workflowPhase",
        "/process/workspaceVersion",
        "/schema",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let actual_paths = canonical_wire_binding_paths(&wire);

    assert_eq!(actual_paths, expected_paths);
    assert_eq!(
        canonical.binding_digest().as_sha256(),
        &canonical_wire_digest(&wire)
    );

    for path in actual_paths {
        let mut mutated = wire.clone();
        mutate_binding_path(&mut mutated, &path);
        assert_ne!(
            canonical_wire_digest(&mutated),
            *canonical.binding_digest().as_sha256(),
            "{path} was not bound"
        );
    }
}

#[test]
fn immutable_tool_request_parser_rejects_unknown_fields_and_noncanonical_json() {
    let request = tool_request("test");
    let canonical = canonical_tool_request(&request).unwrap();
    let original =
        serde_json::from_slice::<serde_json::Value>(canonical.canonical_bytes()).unwrap();
    let mut unknown = original.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), serde_json::Value::Bool(true));
    assert!(parse_tool_request(serde_json::to_string(&unknown).unwrap().as_bytes()).is_err());

    let noncanonical = serde_json::to_string_pretty(&original).unwrap();
    assert!(parse_tool_request(noncanonical.as_bytes()).is_err());

    let raw = std::str::from_utf8(canonical.canonical_bytes()).unwrap();
    let duplicate = raw.replacen(
        r#""schema":"tool-request.v1""#,
        r#""schema":"tool-request.v1","schema":"tool-request.v1""#,
        1,
    );
    assert!(parse_tool_request(duplicate.as_bytes()).is_err());
}

#[test]
fn approved_executable_identity_accepts_only_canonical_resolver_path_shapes() {
    #[cfg(windows)]
    assert!(
        approved_executable_identity_at(r"C:\approved\cargo.exe").is_ok(),
        "ordinary disk path was rejected"
    );
    assert!(
        approved_executable_identity_at(resolver_canonical_executable_path()).is_ok(),
        "authoritative resolver path was rejected"
    );
    for (name, path) in rejected_canonical_executable_paths() {
        assert!(
            approved_executable_identity_at(path).is_err(),
            "{name} path was accepted"
        );
    }
}

#[test]
fn tool_request_parser_rejects_every_domain_invalid_process_shape() {
    let canonical = canonical_tool_request(&tool_request("test")).unwrap();
    let base: serde_json::Value = serde_json::from_slice(canonical.canonical_bytes()).unwrap();
    let write = serde_json::json!({"kind": "worktree", "taskId": "task-1", "path": "target/out"});
    let field_cases: [(&str, &[&str], serde_json::Value); 17] = [
        ("timeout zero", &["timeoutMs"], serde_json::json!(0)),
        ("argv empty", &["argv"], serde_json::json!([])),
        (
            "executable is not toolchain",
            &["executable"],
            serde_json::json!({"kind": "worktree", "taskId": "task-1", "path": "."}),
        ),
        (
            "cwd is not worktree",
            &["cwd"],
            serde_json::json!({"kind": "toolchain", "name": "cargo"}),
        ),
        (
            "cwd belongs to another task",
            &["cwd"],
            serde_json::json!({"kind": "worktree", "taskId": "task-2", "path": "."}),
        ),
        (
            "brokered process",
            &["trustTier"],
            serde_json::json!("brokered_process"),
        ),
        (
            "invalid expected write",
            &["expectedWrites"],
            serde_json::json!([{"kind": "toolchain", "name": "cargo"}]),
        ),
        (
            "duplicate expected writes",
            &["expectedWrites"],
            serde_json::json!([write.clone(), write.clone()]),
        ),
        (
            "too many expected writes",
            &["expectedWrites"],
            serde_json::Value::Array(vec![write.clone(); 1_025]),
        ),
        (
            "cross-task expected write",
            &["expectedWrites"],
            serde_json::json!([{"kind": "worktree", "taskId": "task-2", "path": "target/out"}]),
        ),
        (
            "zero fence",
            &["executorFencingToken"],
            serde_json::json!(0),
        ),
        (
            "zero memory limit",
            &["memoryLimitBytes"],
            serde_json::json!(0),
        ),
        ("zero cpu limit", &["cpuTimeLimitMs"], serde_json::json!(0)),
        (
            "absolute cwd path",
            &["cwd", "path"],
            serde_json::json!(r"C:\absolute"),
        ),
        (
            "traversing cwd path",
            &["cwd", "path"],
            serde_json::json!("../escape"),
        ),
        (
            "toolchain identity mismatch",
            &["approvedExecutable", "toolchainId"],
            serde_json::json!("rustc"),
        ),
        (
            "nul canonical path",
            &["approvedExecutable", "canonicalPath"],
            serde_json::json!("C:\\approved\\cargo\0.exe"),
        ),
    ];

    for (name, path, value) in field_cases {
        let wire = mutate_wire_field(&base, path, value);
        let bytes = serde_json_canonicalizer::to_vec(&wire).unwrap();
        assert!(parse_tool_request(&bytes).is_err(), "{name} was accepted");
    }
    for (name, path) in rejected_canonical_executable_paths() {
        let wire = mutate_wire_field(
            &base,
            &["approvedExecutable", "canonicalPath"],
            serde_json::json!(path),
        );
        let bytes = serde_json_canonicalizer::to_vec(&wire).unwrap();
        assert!(
            parse_tool_request(&bytes).is_err(),
            "{name} canonical path was accepted"
        );
    }

    let mut writes_without_fence = base;
    writes_without_fence["process"]["expectedWrites"] = serde_json::json!([write]);
    writes_without_fence["process"]["executorFencingToken"] = serde_json::Value::Null;
    let bytes = serde_json_canonicalizer::to_vec(&writes_without_fence).unwrap();
    assert!(
        parse_tool_request(&bytes).is_err(),
        "writes without fence was accepted"
    );
}

#[test]
fn policy_binding_excludes_evaluation_time_but_binds_stable_identity() {
    let request = tool_request("test");
    let binding = request.process().process().binding();
    let policy = request.policy();
    let policy_request = local_agent_terminal_domain::PolicyRequest {
        task_id: binding.task_id().clone(),
        actor: policy.actor().clone(),
        action: policy.action().clone(),
        resource: policy.resource().clone(),
        task_risk: policy.task_risk(),
        workflow_phase: binding.workflow_phase().as_str().to_owned(),
        purpose: policy.purpose().to_owned(),
        policy_snapshot_digest: policy.policy_snapshot_digest().clone(),
        evaluated_at: Timestamp::from_unix_seconds(1_753_272_000),
    };
    let expected = canonical_policy_binding_digest(&policy_request).unwrap();
    assert!(expected.as_sha256().as_str().starts_with("sha256:"));

    let mut later = policy_request.clone();
    later.evaluated_at = Timestamp::from_unix_seconds(1_753_272_060);
    assert_eq!(canonical_policy_binding_digest(&later).unwrap(), expected);

    let mut mutations = Vec::new();
    let mut changed = later.clone();
    changed.task_id = TaskId::new("task-2").unwrap();
    mutations.push(changed);
    let mut changed = later.clone();
    changed.actor.connection_id = "connection-2".to_owned();
    mutations.push(changed);
    let mut changed = later.clone();
    changed.actor.agent_id = "agent-2".to_owned();
    mutations.push(changed);
    let mut changed = later.clone();
    changed.actor.trust_tier = TrustTier::BrokeredProcess;
    mutations.push(changed);
    let mut changed = later.clone();
    changed.actor.locality = ActorLocality::Cloud;
    mutations.push(changed);
    let mut changed = later.clone();
    changed.action = PolicyAction::new("process.check").unwrap();
    mutations.push(changed);
    let mut changed = later.clone();
    changed.resource.capability =
        CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "src").unwrap();
    mutations.push(changed);
    let mut changed = later.clone();
    changed.resource.content_digest = digest('c');
    mutations.push(changed);
    let mut changed = later.clone();
    changed.resource.resource_class = ResourceClass::Restricted;
    mutations.push(changed);
    let mut changed = later.clone();
    changed.task_risk = TaskRisk::Critical;
    mutations.push(changed);
    let mut changed = later.clone();
    changed.workflow_phase = Phase::Verification.as_str().to_owned();
    mutations.push(changed);
    let mut changed = later.clone();
    changed.purpose = "different purpose".to_owned();
    mutations.push(changed);
    let mut changed = later;
    changed.policy_snapshot_digest = digest('c');
    mutations.push(changed);

    for mutation in mutations {
        assert_ne!(
            canonical_policy_binding_digest(&mutation).unwrap(),
            expected
        );
    }
}

use local_agent_terminal_domain::{
    ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile, ExpectedWrite, FencingToken,
    NetworkProfile, Phase, PlanStepId, PolicyAction, PolicyActor, PolicyResource, ProcessBinding,
    ProcessInvocation, ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest,
    TaskId, TaskRisk, Timestamp, TrustTier, WorkspaceVersion,
};

#[test]
fn claimed_execution_orders_begin_effect_resolve_and_preserves_claim_authority() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            fixture.request.execution_id.clone(),
            ProcessStatus::Exited,
            Some(0),
        ),
        sequence.clone(),
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
    assert_eq!(executor.calls(), 1);
    let writes = store.terminal_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].authority(), &authority);
    assert_eq!(
        writes[0].receipt().terminal(),
        &ToolExecutionTerminal::succeeded(ToolExecutionOutput {
            exit_code: Some(0),
            output_digest: digest('9'),
            duration_ms: 25,
            artifacts: unavailable_process_artifacts(),
        })
        .unwrap()
    );
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Completed(writes[0].receipt().clone())
    );
}

#[test]
fn operation_digest_is_revalidated_before_begin_and_distinguishes_duplicates() {
    let first = authorized_fixture("execution-a", "test");
    let second = authorized_fixture("execution-a", "check");
    assert_ne!(first.operation_digest, second.operation_digest);
    let sequence = recording_sequence();
    let completed = durable_receipt(
        claim_authority(
            ToolExecutionId::new("execution-a").unwrap(),
            first.operation_digest.clone(),
        ),
        ToolExecutionTerminal::interrupted(),
    );
    let store = RecordingStore::digest_checking(completed, sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence);
    let use_case = ExecuteDurableTool::new(&store, &executor);

    use_case.execute(first.request).unwrap();
    let error = use_case.execute(second.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        store
            .begin_requests()
            .iter()
            .map(|request| request.operation_digest.clone())
            .collect::<Vec<_>>(),
        vec![first.operation_digest, second.operation_digest]
    );
    assert_eq!(executor.calls(), 0);
}

#[test]
fn in_flight_claim_stops_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::InFlight(evidence.clone())),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(outcome, DurableToolExecutionOutcome::InFlight(evidence));
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn completed_claim_stops_after_begin_and_returns_exact_durable_receipt() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let receipt = durable_receipt(
        authority,
        ToolExecutionTerminal::failed(ToolExecutionOutput {
            exit_code: Some(3),
            output_digest: digest('7'),
            duration_ms: 91,
            artifacts: available_process_artifacts(),
        })
        .unwrap(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::Completed(receipt.clone())),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(outcome, DurableToolExecutionOutcome::Completed(receipt));
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn indeterminate_claim_stops_after_begin_without_retry_implication() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::Indeterminate(evidence.clone())),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Indeterminate(evidence)
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn mismatched_in_flight_response_fails_closed_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        ToolExecutionId::new("execution-b").unwrap(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store =
        RecordingStore::with_claim(Ok(ToolExecutionClaim::InFlight(evidence)), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn mismatched_completed_response_fails_closed_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let receipt = durable_receipt(
        claim_authority(
            ToolExecutionId::new("execution-b").unwrap(),
            fixture.operation_digest.clone(),
        ),
        ToolExecutionTerminal::interrupted(),
    );
    let sequence = recording_sequence();
    let store =
        RecordingStore::with_claim(Ok(ToolExecutionClaim::Completed(receipt)), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn mismatched_indeterminate_response_fails_closed_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let mut evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    evidence.task_id = TaskId::new("task-2").unwrap();
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::Indeterminate(evidence)),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn begin_failure_stops_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(Err(unavailable()), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(error, unavailable());
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn generic_executor_error_resolves_indeterminate_with_safe_metadata() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
    let writes = store.terminal_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].authority(), &authority);
    assert_eq!(
        writes[0].receipt().terminal(),
        &ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
            classification: SafeErrorClassification::Internal,
            retryability: Retryability::NonRetryable,
        })
    );
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Completed(writes[0].receipt().clone())
    );
}

#[test]
fn terminal_persistence_failure_returns_typed_unresolved_outcome() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone())
        .with_resolution_error(unavailable());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            fixture.request.execution_id.clone(),
            ProcessStatus::Exited,
            Some(0),
        ),
        sequence.clone(),
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    let attempted_resolution = store.terminal_writes()[0].clone();
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::TerminalPersistenceUnresolved {
            resolution: attempted_resolution,
            error: SafeToolExecutionError {
                classification: SafeErrorClassification::Unavailable,
                retryability: Retryability::Retryable,
            },
        }
    );
    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
}

#[test]
fn executor_receipt_for_b_resolves_a_as_indeterminate_and_never_writes_b() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            ToolExecutionId::new("execution-b").unwrap(),
            ProcessStatus::Exited,
            Some(0),
        ),
        sequence.clone(),
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    let writes = store.terminal_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].authority(), &authority);
    assert_eq!(
        writes[0].receipt(),
        &DurableToolExecutionReceipt::new(
            authority.clone(),
            ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
                classification: SafeErrorClassification::IntegrityFailure,
                retryability: Retryability::NonRetryable,
            }),
        )
    );
    assert!(writes
        .iter()
        .all(|write| write.authority().execution_id().as_str() != "execution-b"));
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Completed(writes[0].receipt().clone())
    );
    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
}

#[test]
fn nonzero_exit_is_failed_and_retains_safe_durable_evidence() {
    assert_failed_process_outcome(Some(23));
}

#[test]
fn absent_exit_code_is_failed_and_retains_safe_durable_evidence() {
    assert_failed_process_outcome(None);
}

#[test]
fn process_terminal_constructors_reject_contradictory_exit_states() {
    assert!(ToolExecutionTerminal::succeeded(process_output(Some(9))).is_err());
    assert!(ToolExecutionTerminal::succeeded(process_output(None)).is_err());
    assert!(ToolExecutionTerminal::failed(process_output(Some(0))).is_err());
    assert!(ToolExecutionTerminal::terminated(process_output(Some(0))).is_err());
}

#[test]
fn terminal_accessors_expose_only_kind_appropriate_evidence() {
    let failed = ToolExecutionTerminal::failed(process_output(Some(9))).unwrap();
    assert_eq!(failed.kind(), ToolExecutionTerminalKind::Failed);
    assert_eq!(failed.output().unwrap().exit_code, Some(9));
    assert_eq!(failed.error(), None);

    let error = SafeToolExecutionError {
        classification: SafeErrorClassification::Unavailable,
        retryability: Retryability::Retryable,
    };
    let indeterminate = ToolExecutionTerminal::indeterminate(error);
    assert_eq!(
        indeterminate.kind(),
        ToolExecutionTerminalKind::Indeterminate
    );
    assert_eq!(indeterminate.output(), None);
    assert_eq!(indeterminate.error(), Some(&error));
}

#[test]
fn artifact_evidence_has_fixed_stream_slots_and_ordered_observed_writes() {
    let artifacts = available_process_artifacts();

    assert_eq!(
        artifacts.stdout(),
        &DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stdout").unwrap())
    );
    assert_eq!(
        artifacts.stderr(),
        &DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stderr").unwrap())
    );
    assert_eq!(
        artifacts.observed_writes(),
        &[DurableToolExecutionArtifact::Available(
            ArtifactId::new("artifact-write-0").unwrap()
        )]
    );
}

#[test]
fn incomplete_listing_returns_authoritative_recovery_evidence_read_only() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let records = vec![IncompleteToolExecution::Indeterminate(evidence.clone())];
    let sequence = recording_sequence();
    let store = RecordingStore::with_incomplete(records.clone(), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let observed = use_case.incomplete().unwrap();

    assert_eq!(observed, records);
    assert_eq!(evidence.task_id, TaskId::new("task-1").unwrap());
    assert_eq!(
        evidence.authority.owner_run_id(),
        &RunId::new("run-1").unwrap()
    );
    assert_eq!(
        evidence.canonical_request_artifact_id,
        ArtifactId::new("artifact-request-a").unwrap()
    );
    assert_eq!(evidence.idempotency_class, IdempotencyClass::NonRepeatable);
    assert_eq!(evidence.authority.attempt(), 7);
    assert_eq!(
        evidence.authority.executor_fencing_token(),
        Some(FencingToken::new(19).unwrap())
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["incomplete"]);
    assert!(store.terminal_writes().is_empty());
    assert_eq!(executor.calls(), 0);
}

fn assert_failed_process_outcome(exit_code: Option<i32>) {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority, sequence.clone());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            fixture.request.execution_id.clone(),
            ProcessStatus::Exited,
            exit_code,
        ),
        sequence,
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    let DurableToolExecutionOutcome::Completed(receipt) = outcome else {
        panic!("expected a durably resolved process failure");
    };
    assert_eq!(
        receipt.terminal(),
        &ToolExecutionTerminal::failed(ToolExecutionOutput {
            exit_code,
            output_digest: digest('9'),
            duration_ms: 25,
            artifacts: unavailable_process_artifacts(),
        })
        .unwrap()
    );
}

type RecordingSequence = Arc<Mutex<Vec<&'static str>>>;

fn recording_sequence() -> RecordingSequence {
    Arc::new(Mutex::new(Vec::new()))
}

struct RecordingStore {
    claim: Result<ToolExecutionClaim, PortError>,
    incomplete: Vec<IncompleteToolExecution>,
    sequence: RecordingSequence,
    begin_requests: Mutex<Vec<NewToolExecution>>,
    terminal_writes: Mutex<Vec<ToolExecutionResolution>>,
    resolution_error: Option<PortError>,
    enforce_first_digest: bool,
}

impl RecordingStore {
    fn claiming(authority: ToolExecutionClaimAuthority, sequence: RecordingSequence) -> Self {
        Self::with_claim(Ok(ToolExecutionClaim::Claimed(authority)), sequence)
    }

    fn with_claim(
        claim: Result<ToolExecutionClaim, PortError>,
        sequence: RecordingSequence,
    ) -> Self {
        Self {
            claim,
            incomplete: Vec::new(),
            sequence,
            begin_requests: Mutex::new(Vec::new()),
            terminal_writes: Mutex::new(Vec::new()),
            resolution_error: None,
            enforce_first_digest: false,
        }
    }

    fn digest_checking(receipt: DurableToolExecutionReceipt, sequence: RecordingSequence) -> Self {
        Self {
            enforce_first_digest: true,
            ..Self::with_claim(Ok(ToolExecutionClaim::Completed(receipt)), sequence)
        }
    }

    fn with_incomplete(
        incomplete: Vec<IncompleteToolExecution>,
        sequence: RecordingSequence,
    ) -> Self {
        Self {
            incomplete,
            ..Self::with_claim(
                Ok(ToolExecutionClaim::Completed(durable_receipt(
                    claim_authority(ToolExecutionId::new("unused").unwrap(), digest('1')),
                    ToolExecutionTerminal::interrupted(),
                ))),
                sequence,
            )
        }
    }

    fn with_resolution_error(mut self, error: PortError) -> Self {
        self.resolution_error = Some(error);
        self
    }

    fn begin_requests(&self) -> Vec<NewToolExecution> {
        self.begin_requests.lock().unwrap().clone()
    }

    fn terminal_writes(&self) -> Vec<ToolExecutionResolution> {
        self.terminal_writes.lock().unwrap().clone()
    }
}

impl ToolExecutionStore for RecordingStore {
    fn reserve(&self, request: NewToolIntent) -> Result<OperationIntentSnapshot, PortError> {
        Ok(OperationIntentSnapshot {
            execution_id: request.execution_id,
            operation_digest: request.operation_digest,
        })
    }

    fn begin(&self, request: NewToolExecution) -> Result<ToolExecutionClaim, PortError> {
        self.sequence.lock().unwrap().push("begin");
        let mut requests = self.begin_requests.lock().unwrap();
        let digest_mismatch = self.enforce_first_digest
            && requests
                .first()
                .is_some_and(|first| first.operation_digest != request.operation_digest);
        requests.push(request);
        if digest_mismatch {
            return Err(conflict());
        }
        self.claim.clone()
    }

    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        self.sequence.lock().unwrap().push("resolve");
        self.terminal_writes
            .lock()
            .unwrap()
            .push(resolution.clone());
        if let Some(error) = &self.resolution_error {
            return Err(error.clone());
        }
        Ok(resolution.receipt().clone())
    }

    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        self.sequence.lock().unwrap().push("incomplete");
        Ok(self.incomplete.clone())
    }
}

struct RecordingExecutor {
    result: Mutex<Option<Result<ToolExecutionResult, PortError>>>,
    calls: AtomicUsize,
    sequence: RecordingSequence,
}

impl RecordingExecutor {
    fn succeeding(receipt: ProcessReceipt, sequence: RecordingSequence) -> Self {
        Self {
            result: Mutex::new(Some(Ok(ToolExecutionResult { receipt }))),
            calls: AtomicUsize::new(0),
            sequence,
        }
    }

    fn failing(error: PortError, sequence: RecordingSequence) -> Self {
        Self {
            result: Mutex::new(Some(Err(error))),
            calls: AtomicUsize::new(0),
            sequence,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl StructuredToolExecutor for RecordingExecutor {
    fn execute(&self, _: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.sequence.lock().unwrap().push("effect");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.lock().unwrap().take().unwrap()
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        Ok(CancellationReceipt {
            execution_id: execution_id.clone(),
            status: ProcessStatus::Terminated,
            job_receipt: None,
            cancelled: true,
        })
    }

    fn file_read(
        &self,
        _: local_agent_terminal_application::FileReadRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::PolicyBoundBytes,
        >,
        PortError,
    > {
        unreachable!()
    }

    fn file_write(
        &self,
        _: local_agent_terminal_application::FileWriteRequest,
    ) -> Result<local_agent_terminal_application::VerifiedWrite, PortError> {
        unreachable!()
    }

    fn git_status(
        &self,
        _: local_agent_terminal_application::GitStatusRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::GitStatusResult,
        >,
        PortError,
    > {
        unreachable!()
    }

    fn git_diff(
        &self,
        _: local_agent_terminal_application::GitDiffRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::GitDiffResult,
        >,
        PortError,
    > {
        unreachable!()
    }
}

struct AuthorizedFixture {
    request: AuthorizedToolRequest,
    operation_digest: Sha256Digest,
}

fn authorized_fixture(execution_id: &str, argument: &str) -> AuthorizedFixture {
    let request = approved_process_request(argument);
    let approval = approved_tool_binding(&request);
    let operation_digest =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(approval.payload().clone()))
            .unwrap()
            .operation_digest;
    AuthorizedFixture {
        request: AuthorizedToolRequest::new(
            ToolExecutionId::new(execution_id).unwrap(),
            approval,
            request,
        ),
        operation_digest,
    }
}

fn approved_process_request(argument: &str) -> ApprovedProcessRequest {
    approved_process_request_with(argument, Phase::Implementation, WorkspaceVersion::new(4))
}

fn approved_process_request_with(
    argument: &str,
    phase: Phase,
    workspace_version: WorkspaceVersion,
) -> ApprovedProcessRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            RunId::new("run-1").unwrap(),
            PlanStepId::new("step-1").unwrap(),
            phase,
            workspace_version,
            EnvironmentProfile::new("rust", digest('e')).unwrap(),
            1,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec![argument.to_owned()],
            CapabilityRef::worktree(task_id, ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            Vec::new(),
            Some(FencingToken::new(19).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    ApprovedProcessRequest::new(
        approved_executable_identity_at(resolver_canonical_executable_path()).unwrap(),
        process,
        Vec::new(),
        None,
        None,
    )
    .unwrap()
}

fn tool_request(argument: &str) -> ToolRequest {
    tool_request_with(
        "execution-orchestration",
        approved_process_request(argument),
        policy_context("agent-1", "run focused tests"),
    )
}

fn rich_tool_request() -> ToolRequest {
    let base = approved_process_request("test");
    let task_id = base.process().binding().task_id().clone();
    let process = ProcessToolRequest::new(
        base.process().binding().clone(),
        ProcessInvocation::new(
            base.process().executable().clone(),
            base.process().argv().to_vec(),
            base.process().cwd().clone(),
            base.process().trust_tier(),
            base.process().network(),
            vec![
                ExpectedWrite::new(CapabilityRef::worktree(task_id, "target/out").unwrap())
                    .unwrap(),
            ],
            base.process().executor_fencing_token(),
        )
        .unwrap(),
    )
    .unwrap();
    tool_request_with(
        "execution-orchestration",
        ApprovedProcessRequest::new(
            base.approved_executable().clone(),
            process,
            vec![CapabilityRef::source("revision-1", "src/lib.rs").unwrap()],
            Some(1024),
            Some(500),
        )
        .unwrap(),
        policy_context("agent-1", "run focused tests"),
    )
}

fn tool_request_with(
    execution_id: &str,
    process: ApprovedProcessRequest,
    policy: ToolPolicyContext,
) -> ToolRequest {
    ToolRequest::new(ToolExecutionId::new(execution_id).unwrap(), process, policy).unwrap()
}

fn policy_context(agent_id: &str, purpose: &str) -> ToolPolicyContext {
    ToolPolicyContext::new(
        PolicyActor {
            connection_id: "connection-1".to_owned(),
            agent_id: agent_id.to_owned(),
            trust_tier: TrustTier::IsolatedWorker,
            locality: ActorLocality::Local,
        },
        PolicyAction::new("process.exec").unwrap(),
        PolicyResource {
            capability: CapabilityRef::worktree(TaskId::new("task-1").unwrap(), ".").unwrap(),
            content_digest: digest('a'),
            resource_class: ResourceClass::InternalCode,
        },
        TaskRisk::High,
        purpose,
        digest('b'),
    )
    .unwrap()
}

fn mutate_wire_field(
    base: &serde_json::Value,
    path: &[&str],
    value: serde_json::Value,
) -> serde_json::Value {
    let mut wire = base.clone();
    let mut field = &mut wire["process"];
    for component in path {
        field = &mut field[*component];
    }
    *field = value;
    wire
}

fn canonical_wire_binding_paths(wire: &serde_json::Value) -> BTreeSet<String> {
    fn walk(value: &serde_json::Value, path: String, paths: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(fields) => {
                for (name, value) in fields {
                    walk(value, format!("{path}/{name}"), paths);
                }
            }
            serde_json::Value::Array(values) => {
                paths.insert(path.clone());
                for (index, value) in values.iter().enumerate() {
                    walk(value, format!("{path}/{index}"), paths);
                }
            }
            _ => {
                paths.insert(path);
            }
        }
    }

    let mut paths = BTreeSet::new();
    walk(wire, String::new(), &mut paths);
    paths
}

fn mutate_binding_path(wire: &mut serde_json::Value, path: &str) {
    let value = wire.pointer_mut(path).unwrap();
    match value {
        serde_json::Value::Null => *value = serde_json::json!("changed"),
        serde_json::Value::Bool(boolean) => *boolean = !*boolean,
        serde_json::Value::Number(number) => {
            *number = serde_json::Number::from(number.as_u64().unwrap() + 1);
        }
        serde_json::Value::String(text) => text.push_str("-changed"),
        serde_json::Value::Array(values) => values.push(values[0].clone()),
        serde_json::Value::Object(_) => unreachable!("only leaves and list containers are walked"),
    }
}

fn canonical_wire_digest(wire: &serde_json::Value) -> Sha256Digest {
    let bytes = serde_json_canonicalizer::to_vec(wire).unwrap();
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn approved_executable_identity_at(
    canonical_path: impl AsRef<Path>,
) -> Result<ApprovedExecutableIdentity, PortError> {
    ApprovedExecutableIdentity::new(
        ResolvedExecutable {
            canonical_path: canonical_path.as_ref().to_owned(),
            sha256: digest('d'),
            file_identity: local_agent_terminal_application::ExecutableFileIdentity::new(
                "cargo-file",
            )
            .unwrap(),
            toolchain_id: "cargo".to_owned(),
        },
        "1.97.1",
    )
}

#[cfg(windows)]
fn resolver_canonical_executable_path() -> &'static str {
    r"\\?\C:\approved\cargo.exe"
}

#[cfg(not(windows))]
fn resolver_canonical_executable_path() -> &'static str {
    "/approved/cargo"
}

#[cfg(windows)]
fn rejected_canonical_executable_paths() -> [(&'static str, &'static str); 6] {
    [
        ("dot", r"C:\approved\.\cargo.exe"),
        ("dot-dot", r"C:\approved\..\cargo.exe"),
        ("alternate data stream", r"C:\approved\cargo.exe:hostile"),
        ("UNC", r"\\server\share\cargo.exe"),
        ("verbatim UNC", r"\\?\UNC\server\share\cargo.exe"),
        ("device namespace", r"\\.\C:\approved\cargo.exe"),
    ]
}

#[cfg(not(windows))]
fn rejected_canonical_executable_paths() -> [(&'static str, &'static str); 2] {
    [
        ("dot", "/approved/./cargo"),
        ("dot-dot", "/approved/../cargo"),
    ]
}

fn approved_tool_binding(request: &ApprovedProcessRequest) -> BoundToolApproval {
    bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "unbound".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "unbound".to_owned(),
                plan_step_id: "unbound".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest('0').as_str().to_owned(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest('0').as_str().to_owned(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: digest('b').as_str().to_owned(),
            workspace_version: 0,
            requested_at: "2026-07-23T12:00:00Z".to_owned(),
            expires_at: "2026-07-23T12:15:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        request,
    )
    .unwrap()
}

fn process_receipt(
    execution_id: ToolExecutionId,
    status: ProcessStatus,
    exit_code: Option<i32>,
) -> ProcessReceipt {
    ProcessReceipt {
        execution_id,
        status,
        exit_code,
        stdout: BoundedOutput {
            bytes: b"secret stdout".to_vec(),
            truncated: false,
        },
        stderr: BoundedOutput {
            bytes: b"secret stderr".to_vec(),
            truncated: false,
        },
        duration_ms: 25,
        job_receipt: JobReceipt {
            root_pid: 42,
            job_id: r"C:\secret\runtime\job".to_owned(),
            kill_on_close: true,
            no_breakaway: true,
            job_memory_limit: false,
            job_cpu_time_limit: false,
            memory_limit_bytes: 0,
            cpu_time_limit_ms: 0,
            max_active_processes: 1,
            total_user_time_ms: 10,
            resource_limit_terminated: false,
            tree_terminated: false,
        },
        observed_writes: Vec::new(),
        output_digest: digest('9'),
    }
}

fn claim_authority(
    execution_id: ToolExecutionId,
    operation_digest: Sha256Digest,
) -> ToolExecutionClaimAuthority {
    ToolExecutionClaimAuthority::from_persisted(
        execution_id,
        operation_digest,
        RunId::new("run-1").unwrap(),
        7,
        Some(FencingToken::new(19).unwrap()),
    )
    .unwrap()
}

fn recovery_evidence(
    execution_id: ToolExecutionId,
    operation_digest: Sha256Digest,
) -> ToolExecutionRecoveryEvidence {
    ToolExecutionRecoveryEvidence {
        authority: claim_authority(execution_id, operation_digest),
        task_id: TaskId::new("task-1").unwrap(),
        canonical_request_artifact_id: ArtifactId::new("artifact-request-a").unwrap(),
        idempotency_class: IdempotencyClass::NonRepeatable,
    }
}

fn durable_receipt(
    authority: ToolExecutionClaimAuthority,
    terminal: ToolExecutionTerminal,
) -> DurableToolExecutionReceipt {
    DurableToolExecutionReceipt::new(authority, terminal)
}

fn process_output(exit_code: Option<i32>) -> ToolExecutionOutput {
    ToolExecutionOutput {
        exit_code,
        output_digest: digest('9'),
        duration_ms: 25,
        artifacts: unavailable_process_artifacts(),
    }
}

fn unavailable_process_artifacts() -> DurableToolExecutionArtifacts {
    DurableToolExecutionArtifacts::new(
        DurableToolExecutionArtifact::Unavailable,
        DurableToolExecutionArtifact::Unavailable,
        Vec::new(),
    )
}

fn available_process_artifacts() -> DurableToolExecutionArtifacts {
    DurableToolExecutionArtifacts::new(
        DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stdout").unwrap()),
        DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stderr").unwrap()),
        vec![DurableToolExecutionArtifact::Available(
            ArtifactId::new("artifact-write-0").unwrap(),
        )],
    )
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
