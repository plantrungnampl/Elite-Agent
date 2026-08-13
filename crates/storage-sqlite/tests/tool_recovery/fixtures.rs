
fn seed_authoritative_context(path: &Path, artifact_root: &Path) {
    let connection = configured_connection(path);
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES ('project-1', 'Project', 'C:/repo',
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                'policy-1', 'application_data', ?1)",
            [artifact_root.to_string_lossy().as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state, risk_level,
                base_branch, base_commit, workspace_version, fencing_epoch, created_at, updated_at
             ) VALUES ('task-1', 'project-1', 'Task', 'Objective', 'Implementation', 'Active',
                'None', 'high', 'main', ?1, 4, 19,
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
            ["a".repeat(40)],
        )
        .unwrap();
    let seed_hash = format!("sha256:{}", "d".repeat(64));
    for (id, path) in [
        ("manifest", "seed/manifest"),
        ("effective", "seed/effective"),
        ("run-config", "seed/run-config"),
    ] {
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-1', 'project-1', 'seed', ?2, ?3, ?1, 0, NULL,
                    'available', 'core', 'core', '2026-07-23T00:00:00Z', NULL, 'hash_verified')",
                params![id, path, seed_hash],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO agent_descriptors (
                id, display_name, transport_type, trust_tier, manifest_json, manifest_digest,
                executable_digest, enabled, last_health_status, updated_at
             ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                NULL, 1, 'healthy', '2026-07-23T00:00:00Z')",
            [&seed_hash],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO context_packages (
                id, task_id, agent_id, role, objective, manifest_artifact_id,
                effective_content_artifact_id, content_hash, policy_snapshot_digest,
                prompt_template_version, retrieval_pipeline_version, created_at
             ) VALUES ('context-1', 'task-1', 'agent-1', 'executor', 'execute',
                'manifest', 'effective', ?1, ?2, 'v1', 'v1', '2026-07-23T00:00:00Z')",
            params![seed_hash, format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO agent_runs (
                id, task_id, agent_id, role, phase, status, context_package_id,
                idempotency_key, connection_binding_digest, run_config_artifact_id, started_at
             ) VALUES ('run-1', 'task-1', 'agent-1', 'executor', 'Implementation', 'running',
                'context-1', 'run-1-key', ?1, 'run-config', '2026-07-23T00:00:00Z')",
            [format!("sha256:{}", "e".repeat(64))],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO executor_leases (
                id, task_id, holder_run_id, fencing_token, status,
                acquired_at, expires_at, released_at
             ) VALUES ('lease-task-1-19', 'task-1', 'run-1', 19, 'active',
                '2026-07-23T00:00:00Z', '2026-08-23T00:00:00Z', NULL)",
            [],
        )
        .unwrap();
}

fn exact_tool_request(execution_id: &str) -> ToolRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            RunId::new("run-1").unwrap(),
            PlanStepId::new("step-1").unwrap(),
            Phase::Implementation,
            WorkspaceVersion::new(4),
            EnvironmentProfile::new("rust", digest_char('e')).unwrap(),
            1,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".to_owned()],
            CapabilityRef::worktree(task_id.clone(), ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            Vec::new(),
            Some(FencingToken::new(19).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let approved = ApprovedProcessRequest::new(
        ApprovedExecutableIdentity::new(
            ResolvedExecutable {
                canonical_path: PathBuf::from(resolver_canonical_executable_path()),
                sha256: digest_char('d'),
                file_identity: ExecutableFileIdentity::new("cargo-file").unwrap(),
                toolchain_id: "cargo".to_owned(),
            },
            "1.97.1",
        )
        .unwrap(),
        process,
        Vec::new(),
        None,
        None,
        None,
    )
    .unwrap();
    let policy = ToolPolicyContext::new(
        PolicyActor {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::IsolatedWorker,
            locality: ActorLocality::Local,
        },
        PolicyAction::new("process.exec").unwrap(),
        PolicyResource {
            capability: CapabilityRef::worktree(task_id, ".").unwrap(),
            content_digest: digest_char('a'),
            resource_class: ResourceClass::InternalCode,
        },
        TaskRisk::High,
        "run focused tests",
        digest_char('b'),
    )
    .unwrap();
    ToolRequest::new(
        ToolExecutionId::new(execution_id).unwrap(),
        approved,
        policy,
    )
    .unwrap()
}

fn record_exact_policy(
    store: &SqliteStore,
    request: &ToolRequest,
    evaluated_at: Timestamp,
    effect: PolicyEffect,
    digest_marker: char,
) -> local_agent_terminal_application::PolicyDecisionId {
    record_exact_policy_with_expiry(
        store,
        request,
        evaluated_at,
        effect,
        digest_marker,
        Some(Timestamp::from_unix_seconds(4_102_444_800)),
    )
}

fn record_exact_policy_with_expiry(
    store: &SqliteStore,
    request: &ToolRequest,
    evaluated_at: Timestamp,
    effect: PolicyEffect,
    digest_marker: char,
    expires_at: Option<Timestamp>,
) -> local_agent_terminal_application::PolicyDecisionId {
    record_exact_policy_for_digest(
        store,
        request,
        evaluated_at,
        effect,
        digest_marker,
        expires_at,
        canonical_tool_request(request)
            .unwrap()
            .binding_digest()
            .as_sha256()
            .clone(),
    )
}

#[allow(clippy::too_many_arguments)]
fn record_exact_policy_for_digest(
    store: &SqliteStore,
    request: &ToolRequest,
    evaluated_at: Timestamp,
    effect: PolicyEffect,
    digest_marker: char,
    expires_at: Option<Timestamp>,
    operation_digest: Sha256Digest,
) -> local_agent_terminal_application::PolicyDecisionId {
    let policy_request = policy_request_for_tool(request, evaluated_at);
    let draft = combine_policy_rules(
        policy_request,
        PolicyVersion::new(1).unwrap(),
        vec![MatchedPolicyRule {
            rule_id: PolicyRuleId::new(format!("rule-{digest_marker}")).unwrap(),
            effect,
            redactions: Vec::new(),
        }],
        expires_at,
    )
    .unwrap();
    store
        .record(RecordedPolicyDecision::exact(
            PolicyDecision {
                draft,
                operation_digest,
            },
            evaluated_at,
        ))
        .unwrap()
}

fn exact_denial_fixture(
    database: &TempDatabase,
    execution_id: &str,
) -> (
    SqliteStore,
    ToolExecutionDenialRequest,
    AuthorizedToolExecutionClaim,
) {
    let (store, authorized, _, _) = exact_approval_claim_fixture(database, execution_id);
    let immutable = store
        .load_request_artifact(&authorized.request_artifact_id)
        .unwrap();
    let denial = ToolExecutionDenialRequest {
        request_artifact_id: authorized.request_artifact_id.clone(),
        request: immutable,
        policy_decision_id: authorized.policy_decision_id.clone(),
        policy_request_binding_digest: authorized.policy_request_binding_digest.clone(),
        effect: PolicyEffect::Deny,
        checked_at: authorized.checked_at,
    };
    (store, denial, authorized)
}

fn exact_approval_claim_fixture(
    database: &TempDatabase,
    execution_id: &str,
) -> (
    SqliteStore,
    AuthorizedToolExecutionClaim,
    ApprovalId,
    local_agent_terminal_application::PolicyDecisionId,
) {
    exact_approval_claim_fixture_with_overrides(
        database,
        execution_id,
        ExactApprovalArtifactOverrides::default(),
    )
}

#[derive(Default)]
struct ExactApprovalArtifactOverrides<'a> {
    request_logical_path: Option<&'a str>,
    request_artifact_type: Option<&'a str>,
    approval_logical_path: Option<&'a str>,
    approval_artifact_type: Option<&'a str>,
}

fn exact_approval_claim_fixture_with_overrides(
    database: &TempDatabase,
    execution_id: &str,
    overrides: ExactApprovalArtifactOverrides<'_>,
) -> (
    SqliteStore,
    AuthorizedToolExecutionClaim,
    ApprovalId,
    local_agent_terminal_application::PolicyDecisionId,
) {
    let store = SqliteStore::open(&database.path).unwrap();
    let request = exact_tool_request(execution_id);
    let immutable = canonical_tool_request(&request).unwrap();
    let request_artifact_id = ArtifactId::new(format!("request-{execution_id}")).unwrap();
    let default_request_path = format!("tool-requests/{execution_id}.json");
    persist_artifact_for_task(
        database,
        "task-1",
        request_artifact_id.as_str(),
        overrides
            .request_logical_path
            .unwrap_or(&default_request_path),
        overrides.request_artifact_type.unwrap_or("tool-request"),
        immutable.canonical_bytes(),
    );
    store
        .reserve(NewToolIntent {
            execution_id: request.execution_id().clone(),
            operation_digest: immutable.binding_digest().as_sha256().clone(),
        })
        .unwrap();

    let checked_at = Timestamp::from_unix_seconds(1_753_272_300);
    let approval_policy_id = record_exact_policy_for_digest(
        &store,
        &request,
        Timestamp::from_unix_seconds(checked_at.unix_seconds() - 60),
        PolicyEffect::RequireApproval,
        '3',
        Some(Timestamp::from_unix_seconds(4_102_444_800)),
        digest_char('3'),
    );
    let effective_policy_id = record_exact_policy(
        &store,
        &request,
        checked_at,
        PolicyEffect::RequireApproval,
        '4',
    );
    let policy_binding =
        canonical_policy_binding_digest(&policy_request_for_tool(&request, checked_at)).unwrap();
    let bound = bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "unbound".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "unbound".to_owned(),
                plan_step_id: "unbound".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest_char('0').to_string(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest_char('0').to_string(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: request.policy().policy_snapshot_digest().to_string(),
            workspace_version: 0,
            requested_at: "2026-07-23T12:00:00Z".to_owned(),
            expires_at: "2099-07-23T12:15:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        request.process(),
    )
    .unwrap();
    let approval_id = ApprovalId::new(format!("approval-{execution_id}")).unwrap();
    let approval_artifact_id =
        ArtifactId::new(format!("approval-artifact-{execution_id}")).unwrap();
    let approval = ToolApprovalRequest::from_persisted(
        approval_id.clone(),
        approval_artifact_id.clone(),
        request.execution_id().clone(),
        approval_policy_id.clone(),
        policy_binding.clone(),
        request_artifact_id.clone(),
        immutable.binding_digest().clone(),
        bound.payload().clone(),
    )
    .unwrap();
    let default_approval_path = format!("approvals/{}.json", approval_id.as_str());
    persist_artifact_for_task(
        database,
        "task-1",
        approval_artifact_id.as_str(),
        overrides
            .approval_logical_path
            .unwrap_or(&default_approval_path),
        overrides
            .approval_artifact_type
            .unwrap_or("approval-payload"),
        &approval.canonical_payload().canonical_bytes,
    );
    let connection = configured_connection(&database.path);
    let actor_binding_digest: String = connection
        .query_row(
            "SELECT actor_binding_digest FROM operation_intents WHERE id = ?1",
            [request.execution_id().as_str()],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approvals (
                id, task_id, operation_intent_id, approval_type, schema_version,
                operation_digest, actor_binding_digest, nonce, status, requested_at,
                resolved_at, expires_at, request_artifact_id, invalidation_reason
             ) VALUES (?1, 'task-1', ?2, 'tool', 'approval-digest.v1', ?3, ?4, ?5,
                'pending', ?6, NULL, ?7, ?8, NULL)",
            params![
                approval_id.as_str(),
                request.execution_id().as_str(),
                immutable.binding_digest().as_sha256().as_str(),
                actor_binding_digest,
                approval.payload().nonce,
                approval.payload().requested_at,
                approval.payload().expires_at,
                approval_artifact_id.as_str(),
            ],
        )
        .unwrap();
    let unique_digest = |label: &str| {
        format!(
            "sha256:{:x}",
            Sha256::digest(format!("{label}:{execution_id}").as_bytes())
        )
    };
    connection
        .execute_batch(&format!(
            "INSERT INTO actor_bindings (
                id, actor_kind, actor_id, session_id, proof_type, binding_digest,
                issued_at, expires_at, revoked_at, session_epoch
             ) VALUES ('actor-binding-{execution_id}', 'user', 'user-1', 'session-1',
                'local_authenticated_session', '{actor_binding_digest}',
                '2026-07-20T00:00:00Z', '2099-07-30T00:00:00Z', NULL, 1);
             INSERT INTO credential_challenges (
                id, actor_binding_id, purpose, operation_digest, nonce,
                challenge_digest, issued_at, expires_at
             ) VALUES ('challenge-{execution_id}', 'actor-binding-{execution_id}',
                'policy_exception.approval', '{}', 'credential-challenge-{execution_id}',
                '{}', '2026-07-29T00:00:00Z', '2026-07-31T00:00:00Z');
             INSERT INTO credential_challenge_receipts (
                id, challenge_id, actor_binding_id, proof_type, proof_artifact_id,
                verified_at, receipt_digest
             ) VALUES ('challenge-receipt-{execution_id}', 'challenge-{execution_id}',
                'actor-binding-{execution_id}', 'local_authenticated_session', '{}',
                '2026-07-30T00:00:00Z', '{}');",
            immutable.binding_digest().as_sha256().as_str(),
            unique_digest("challenge"),
            approval_artifact_id.as_str(),
            unique_digest("challenge-receipt"),
        ))
        .unwrap();
    connection
        .execute(
            "INSERT INTO approval_decision_receipts (
                id, approval_id, task_id, operation_intent_id, operation_digest,
                actor_binding_digest, nonce, decision, credential_evidence_artifact_id,
                decided_at, receipt_digest
             ) VALUES (?1, ?2, 'task-1', ?3, ?4, ?5, ?6, 'granted', ?7,
                '2026-07-30T00:00:00Z', ?8)",
            params![
                format!("approval-receipt-{execution_id}"),
                approval_id.as_str(),
                request.execution_id().as_str(),
                immutable.binding_digest().as_sha256().as_str(),
                actor_binding_digest,
                approval.payload().nonce,
                approval_artifact_id.as_str(),
                unique_digest("approval-receipt"),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approval_actor_proof_bindings (
                approval_receipt_id, actor_binding_id, challenge_receipt_id, created_at
             ) VALUES (?1, ?2, ?3, '2026-07-30T00:00:00Z')",
            params![
                format!("approval-receipt-{execution_id}"),
                format!("actor-binding-{execution_id}"),
                format!("challenge-receipt-{execution_id}"),
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE approvals SET status = 'granted', resolved_at = '2026-07-30T00:00:00Z'
             WHERE id = ?1",
            [approval_id.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, 'task-1', 1, 'approval.requested', 1, 'core',
                'approval-store', 'core_observed', ?2, '{}', ?3, ?3,
                '2026-07-23T12:00:00Z')",
            params![
                format!("approval.requested:{}:1", approval_id.as_str()),
                serde_json::json!({
                    "approvalId": approval_id.as_str(),
                    "approvalType": "tool",
                    "operationDigest": immutable.binding_digest().as_sha256().as_str(),
                    "executionId": request.execution_id().as_str(),
                    "approvalPolicyDecisionId": approval_policy_id.as_str(),
                    "policyRequestBindingDigest": policy_binding.as_sha256().as_str(),
                    "toolRequestArtifactId": request_artifact_id.as_str(),
                    "toolRequestBindingDigest": immutable.binding_digest().as_sha256().as_str(),
                    "workspaceVersion": request.process().process().binding().workspace_version().get(),
                    "policySnapshotDigest": request.policy().policy_snapshot_digest().as_str(),
                    "fencingToken": request
                        .process()
                        .process()
                        .executor_fencing_token()
                        .map(FencingToken::get),
                    "nonce": approval.payload().nonce,
                    "requestArtifactId": approval_artifact_id.as_str(),
                })
                .to_string(),
                format!("approval:{}", approval_id.as_str()),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, 'task-1', 2, 'approval.granted', 1, 'core',
                'approval-store', 'core_observed', ?2, '{}', ?3, ?3,
                '2026-07-30T00:00:00Z')",
            params![
                format!("approval.granted:{}:2", approval_id.as_str()),
                serde_json::json!({
                    "approvalId": approval_id.as_str(),
                    "status": "granted",
                })
                .to_string(),
                format!("approval:{}", approval_id.as_str()),
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE tasks SET operation_state = 'None', current_sequence = 2,
                row_version = row_version + 1
             WHERE id = 'task-1'",
            [],
        )
        .unwrap();

    let process = request.process().process();
    let binding = process.binding();
    let claim = AuthorizedToolExecutionClaim {
        execution_id: request.execution_id().clone(),
        request_artifact_id,
        request_content_digest: immutable.binding_digest().as_sha256().clone(),
        request_binding_digest: immutable.binding_digest().clone(),
        task_id: binding.task_id().clone(),
        run_id: binding.run_id().clone(),
        tool_name: "process.exec".to_owned(),
        policy_decision_id: effective_policy_id.clone(),
        policy_request_binding_digest: policy_binding,
        approval: Some(approval),
        workspace_version: binding.workspace_version(),
        policy_snapshot_digest: request.policy().policy_snapshot_digest().clone(),
        fencing_token: process.executor_fencing_token(),
        checked_at,
        effect_checked_at: checked_at,
        approval_checked_at: Some(checked_at),
    };
    (store, claim, approval_id, effective_policy_id)
}

#[cfg(windows)]
fn resolver_canonical_executable_path() -> &'static str {
    r"\\?\C:\approved\cargo.exe"
}

#[cfg(not(windows))]
fn resolver_canonical_executable_path() -> &'static str {
    "/approved/cargo"
}

fn persist_request_artifact(database: &TempDatabase, execution_id: &str) -> Sha256Digest {
    let canonical = canonical_tool_request(&exact_tool_request(execution_id)).unwrap();
    persist_artifact(
        database,
        "request-artifact",
        &format!("tool-requests/{execution_id}.json"),
        "tool-request",
        canonical.canonical_bytes(),
    );
    canonical.binding_digest().as_sha256().clone()
}

fn file_write_recovery(
    database: &TempDatabase,
    execution_id: &str,
) -> (FileWriteRecoveryIntent, FileWriteRecoveryCompletion) {
    let task_id = TaskId::new("task-1").unwrap();
    let pre_image = persist_evidence_artifact(
        database,
        &format!("{execution_id}-pre-image"),
        b"old contents",
    );
    let pre_evidence = persist_evidence_artifact(
        database,
        &format!("{execution_id}-pre-evidence"),
        b"{\"workspace\":\"before\"}",
    );
    let post_evidence = persist_evidence_artifact(
        database,
        &format!("{execution_id}-post-evidence"),
        b"{\"workspace\":\"after\"}",
    );
    let policy_operation_digest = digest_char('6');
    let policy_snapshot_digest = digest_char('0');
    persist_file_policy_decision(
        &database.path,
        "policy-file-write",
        "task-1",
        &policy_operation_digest,
        &policy_snapshot_digest,
        "allow",
    );
    let expected_post_digest =
        Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(b"new contents"))).unwrap();
    let request = FileWriteRecoveryRequest {
        execution_id: ToolExecutionId::new(execution_id).unwrap(),
        task_id: task_id.clone(),
        root_identity: CapabilityRootIdentity::new("worktree-root-1").unwrap(),
        relative_components: RelativePathComponents::new(vec![
            "src".to_owned(),
            "main.rs".to_owned(),
        ])
        .unwrap(),
        lease_claim: LeaseClaim::new(
            task_id,
            RunId::new("run-1").unwrap(),
            FencingToken::new(19).unwrap(),
        ),
        expected_sequence: Sequence::new(0),
        pre_image: FileWritePreImage::Artifact(pre_image),
        expected_post_digest: expected_post_digest.clone(),
        expected_post_size: b"new contents".len() as u64,
        pre_fingerprint: workspace_fingerprint('a', '1', '2'),
        pre_evidence,
        actor_id: ActorId::new("tool-runtime").unwrap(),
        correlation_id: format!("file-write:{execution_id}"),
        policy: FileWritePolicyBinding {
            decision_id: "policy-file-write".to_owned(),
            operation_digest: policy_operation_digest,
            policy_snapshot_digest,
            effect: PolicyEffect::Allow,
            approval_id: None,
        },
    };
    let request_artifact =
        persist_recovery_request_artifact(database, &request, &format!("{execution_id}-request"));
    let completion = FileWriteRecoveryCompletion {
        execution_id: request.execution_id.clone(),
        observed_post_digest: expected_post_digest,
        post_fingerprint: workspace_fingerprint('b', '3', '4'),
        post_evidence,
    };
    (
        FileWriteRecoveryIntent {
            request,
            request_artifact,
        },
        completion,
    )
}

fn persist_recovery_request_artifact(
    database: &TempDatabase,
    request: &FileWriteRecoveryRequest,
    artifact_id: &str,
) -> CanonicalEvidenceRef {
    let canonical = canonical_file_write_recovery_request(request).unwrap();
    persist_artifact(
        database,
        artifact_id,
        &format!("tool-requests/{artifact_id}.json"),
        "file-write-request",
        &canonical.canonical_bytes,
    );
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).unwrap(),
        content_hash: canonical.operation_digest.as_str().to_owned(),
        storage_key: format!("objects/{}", &canonical.operation_digest.as_str()[7..]),
        size_bytes: canonical.canonical_bytes.len() as u64,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(TaskId::new("task-1").unwrap()),
    }
}

fn persist_evidence_artifact(
    database: &TempDatabase,
    artifact_id: &str,
    bytes: &[u8],
) -> CanonicalEvidenceRef {
    let digest = Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap();
    persist_artifact(
        database,
        artifact_id,
        &format!("file-write/{artifact_id}"),
        "file-write-evidence",
        bytes,
    );
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).unwrap(),
        content_hash: digest.as_str().to_owned(),
        storage_key: format!("objects/{}", &digest.as_str()[7..]),
        size_bytes: bytes.len() as u64,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(TaskId::new("task-1").unwrap()),
    }
}

fn persist_file_policy_decision(
    path: &Path,
    decision_id: &str,
    task_id: &str,
    operation_digest: &Sha256Digest,
    policy_snapshot_digest: &Sha256Digest,
    effect: &str,
) {
    let connection = configured_connection(path);
    connection
        .execute(
            "INSERT INTO policy_decisions (
                id, task_id, actor_json, actor_binding_digest, action, resource_json,
                resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
             ) VALUES (?1, ?2, '{}', ?3, 'tool.write', '{}', ?3,
                'file write', 'Implementation', ?4, '[]', ?5, ?6,
                '2026-07-23T12:00:00Z', NULL, NULL)",
            params![
                decision_id,
                task_id,
                digest_char('7').as_str(),
                effect,
                policy_snapshot_digest.as_str(),
                operation_digest.as_str(),
            ],
        )
        .unwrap();
}

fn workspace_fingerprint(
    head: char,
    index_digest: char,
    status_digest: char,
) -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(
        GitObjectId::new(head.to_string().repeat(40)).unwrap(),
        digest_char(index_digest).as_str(),
        digest_char(status_digest).as_str(),
    )
    .unwrap()
}

fn digest_char(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn persist_artifact(
    database: &TempDatabase,
    id: &str,
    logical_path: &str,
    artifact_type: &str,
    bytes: &[u8],
) {
    persist_artifact_for_task(database, "task-1", id, logical_path, artifact_type, bytes);
}

fn persist_artifact_for_task(
    database: &TempDatabase,
    task_id: &str,
    id: &str,
    logical_path: &str,
    artifact_type: &str,
    bytes: &[u8],
) {
    let hash = format!("sha256:{:x}", Sha256::digest(bytes));
    let storage_key = format!("objects/{}", &hash[7..]);
    let object = database.directory.join(&storage_key);
    fs::create_dir_all(object.parent().unwrap()).unwrap();
    fs::write(object, bytes).unwrap();
    configured_connection(&database.path)
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash, storage_key,
                size_bytes, mime_type, availability, created_by_type, created_by_id, created_at,
                supersedes, verification_state
             ) VALUES (?1, ?2, 'project-1', ?3, ?4, ?5, ?6, ?7, NULL, 'available',
                'tool', 'execution', '2026-07-23T12:00:00Z', NULL, 'hash_verified')",
            params![
                id,
                task_id,
                artifact_type,
                logical_path,
                hash,
                storage_key,
                bytes.len() as i64
            ],
        )
        .unwrap();
}

fn persist_policy_decision(path: &Path, operation_digest: &Sha256Digest, effect: &str) {
    let digest = format!("sha256:{}", "0".repeat(64));
    let ApprovalDigestPayload::Tool(payload) = parse_approval_payload(TOOL_FIXTURE).unwrap() else {
        unreachable!();
    };
    configured_connection(path)
        .execute(
            "INSERT INTO policy_decisions (
                id, task_id, actor_json, actor_binding_digest, action, resource_json,
                resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
             ) VALUES ('policy-1', 'task-1', '{}', ?1, 'process.exec', '{}', ?1,
                'test', 'Implementation', ?3, '[]', ?4, ?2,
                '2026-07-23T12:00:00Z', NULL, NULL)",
            params![
                digest,
                operation_digest.as_str(),
                effect,
                payload.policy_snapshot_digest
            ],
        )
        .unwrap();
}

fn configured_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    connection
}
