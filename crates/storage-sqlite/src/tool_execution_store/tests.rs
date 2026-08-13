
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use local_agent_terminal_application::{
        canonical_tool_request, ApprovedExecutableIdentity, ApprovedProcessRequest,
        ExecutableFileIdentity, ResolvedExecutable, ToolExecutionId, ToolPolicyContext, ToolRequest,
    };
    use local_agent_terminal_domain::{
        ActorLocality, CapabilityRef, EnvironmentProfile, NetworkProfile, Phase, PlanStepId,
        PolicyAction, PolicyActor, PolicyResource, ProcessBinding, ProcessInvocation,
        ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, TaskId, TaskRisk, TrustTier,
        WorkspaceVersion,
    };

    use super::*;

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn incomplete_reads_candidates_and_rows_from_one_snapshot() {
        let directory = std::env::temp_dir().join(format!(
            "tool-incomplete-snapshot-{}-{}",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("state.sqlite3");
        let store = SqliteStore::open(&path).unwrap();
        let operation_digest = seed_tool_context(&store, &directory);
        let execution_id = ToolExecutionId::new("snapshot-execution").unwrap();
        store
            .reserve(NewToolIntent {
                execution_id: execution_id.clone(),
                operation_digest: operation_digest.clone(),
            })
            .unwrap();
        seed_claimed_execution(&store, &execution_id);
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let listed = std::thread::scope(|scope| {
            let writer = store.clone();
            let terminal = scope.spawn(move || {
                start_rx.recv().unwrap();
                let mut connection = writer.connection().unwrap();
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                transaction
                    .execute(
                        "UPDATE operation_attempts
                         SET status = 'interrupted', terminal_at = '2026-07-23T12:01:00Z'
                         WHERE operation_intent_id = 'snapshot-execution'",
                        [],
                    )
                    .unwrap();
                transaction
                    .execute(
                        "UPDATE tool_executions
                         SET status = 'interrupted', completed_at = '2026-07-23T12:01:00Z'
                         WHERE id = 'snapshot-execution'",
                        [],
                    )
                    .unwrap();
                transaction
                    .execute(
                        "UPDATE operation_intents
                         SET status = 'interrupted', updated_at = '2026-07-23T12:01:00Z'
                         WHERE id = 'snapshot-execution'",
                        [],
                    )
                    .unwrap();
                transaction.commit().unwrap();
                done_tx.send(()).unwrap();
            });
            let listed = incomplete_with_checkpoint(&store, || {
                start_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            });
            terminal.join().unwrap();
            listed
        });

        assert!(matches!(
            listed.unwrap().as_slice(),
            [IncompleteToolExecution::InFlight(_)]
        ));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    fn seed_claimed_execution(store: &SqliteStore, execution_id: &ToolExecutionId) {
        let connection = store.connection().unwrap();
        connection
            .execute(
                "INSERT INTO operation_attempts (
                    id, operation_intent_id, task_id, attempt_no, owner_run_id,
                    fencing_token, policy_decision_id, approval_id, status,
                    external_request_id, boundary_crossed_at, started_at, terminal_at,
                    result_artifact_id, receipt_artifact_id, error_artifact_id
                 ) VALUES ('snapshot-execution:attempt:1', ?1, 'task-1', 1, 'run-1',
                    19, 'policy-1', NULL, 'claimed', NULL, NULL,
                    '2026-07-23T12:00:00Z', NULL, NULL, NULL, NULL)",
                [execution_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE operation_intents
                 SET status = 'claimed', current_attempt_no = 1
                 WHERE id = ?1",
                [execution_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tool_executions (
                    id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
                    policy_decision_id, approval_id, operation_intent_id,
                    operation_attempt_id, executor_fencing_token, status, started_at,
                    completed_at, exit_code, stdout_artifact_id, stderr_artifact_id
                 ) VALUES (?1, 'task-1', 'run-1', ?1, 'process.exec', 'request-artifact',
                    'policy-1', NULL, ?1, 'snapshot-execution:attempt:1', 19,
                    'pending', NULL, NULL, NULL, NULL, NULL)",
                [execution_id.as_str()],
            )
            .unwrap();
    }

    fn seed_tool_context(store: &SqliteStore, artifact_root: &Path) -> Sha256Digest {
        let connection = store.connection().unwrap();
        let seed_hash = format!("sha256:{}", "d".repeat(64));
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
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, workspace_version, fencing_epoch,
                    created_at, updated_at
                 ) VALUES ('task-1', 'project-1', 'Task', 'Objective', 'Implementation',
                    'Active', 'None', 'high', 'main', ?1, 4, 19,
                    '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
                ["a".repeat(40)],
            )
            .unwrap();
        for (id, logical_path) in [
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
                        'available', 'core', 'core', '2026-07-23T00:00:00Z',
                        NULL, 'hash_verified')",
                    params![id, logical_path, seed_hash],
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
                    'manifest', 'effective', ?1, ?2, 'v1', 'v1',
                    '2026-07-23T00:00:00Z')",
                params![seed_hash, format!("sha256:{}", "0".repeat(64))],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_runs (
                    id, task_id, agent_id, role, phase, status, context_package_id,
                    idempotency_key, connection_binding_digest, run_config_artifact_id, started_at
                 ) VALUES ('run-1', 'task-1', 'agent-1', 'executor', 'Implementation',
                    'running', 'context-1', 'run-1-key', ?1, 'run-config',
                    '2026-07-23T00:00:00Z')",
                [format!("sha256:{}", "e".repeat(64))],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO executor_leases (
                    id, task_id, holder_run_id, fencing_token, status, acquired_at, expires_at
                 ) VALUES ('lease-1', 'task-1', 'run-1', 19, 'active',
                    '2026-07-23T00:00:00Z', '2026-08-23T00:00:00Z')",
                [],
            )
            .unwrap();

        let request = exact_tool_request("snapshot-execution");
        let canonical = canonical_tool_request(&request).unwrap();
        let operation_digest = canonical.binding_digest().as_sha256();
        let actor = json!({
            "connectionId": request.policy().actor().connection_id,
            "agentId": request.policy().actor().agent_id,
            "trustTier": request.policy().actor().trust_tier.as_str(),
            "locality": "local",
        });
        let actor_binding_digest = digest_json(&actor).unwrap();
        let storage_key = format!("objects/{}", &operation_digest.as_str()[7..]);
        let request_path = artifact_root.join(&storage_key);
        fs::create_dir_all(request_path.parent().unwrap()).unwrap();
        fs::write(request_path, canonical.canonical_bytes()).unwrap();
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES ('request-artifact', 'task-1', 'project-1', 'tool-request',
                    'tool-requests/snapshot.json', ?1, ?2, ?3, NULL, 'available',
                    'tool', 'snapshot-execution', '2026-07-23T12:00:00Z',
                    NULL, 'hash_verified')",
                params![
                    operation_digest.as_str(),
                    storage_key,
                    canonical.canonical_bytes().len() as i64,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO policy_decisions (
                    id, task_id, actor_json, actor_binding_digest, action, resource_json,
                    resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                    policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
                 ) VALUES ('policy-1', 'task-1', ?1, ?2, 'process.exec', '{}', ?3,
                    'test', 'Implementation', 'allow', '[]', ?4, ?5,
                    '2026-07-23T12:00:00Z', NULL, NULL)",
                params![
                    actor.to_string(),
                    actor_binding_digest,
                    format!("sha256:{}", "0".repeat(64)),
                    request.policy().policy_snapshot_digest().as_str(),
                    operation_digest.as_str(),
                ],
            )
            .unwrap();
        operation_digest.clone()
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

    fn digest_char(character: char) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
    }

    #[cfg(windows)]
    fn resolver_canonical_executable_path() -> &'static str {
        r"\\?\C:\approved\cargo.exe"
    }

    #[cfg(not(windows))]
    fn resolver_canonical_executable_path() -> &'static str {
        "/approved/cargo"
    }
}
