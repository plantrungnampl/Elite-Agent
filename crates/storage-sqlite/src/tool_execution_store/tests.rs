
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use local_agent_terminal_application::{
        canonical_approval_payload, parse_approval_payload, ToolExecutionTerminal,
    };

    use super::*;

    const TOOL_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/contracts/fixtures/m2/tool-approval-valid.json"
    ));
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
        let ToolExecutionClaim::Claimed(authority) = store
            .begin(NewToolExecution {
                execution_id,
                operation_digest,
            })
            .unwrap()
        else {
            panic!("fresh execution must be claimed");
        };
        let receipt =
            DurableToolExecutionReceipt::new(authority, ToolExecutionTerminal::cancelled());
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let listed = std::thread::scope(|scope| {
            let writer = store.clone();
            let terminal = scope.spawn(move || {
                start_rx.recv().unwrap();
                let result = writer.resolve_terminal(ToolExecutionResolution::new(receipt.clone()));
                done_tx.send(()).unwrap();
                result
            });
            let listed = incomplete_with_checkpoint(&store, || {
                start_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            });
            terminal.join().unwrap().unwrap();
            listed
        });

        assert!(matches!(
            listed.unwrap().as_slice(),
            [IncompleteToolExecution::InFlight(_)]
        ));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    fn seed_tool_context(store: &SqliteStore, artifact_root: &Path) -> Sha256Digest {
        let connection = store.connection().unwrap();
        let seed_hash = format!("sha256:{}", "d".repeat(64));
        connection
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES ('project-1', 'Project', 'C:/repo', 'repo-1',
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
                    executable_digest, enabled, containment_verified, last_health_status, updated_at
                 ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                    NULL, 1, 1, 'healthy', '2026-07-23T00:00:00Z')",
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
                    task_id, holder_run_id, fencing_token, status, acquired_at, expires_at
                 ) VALUES ('task-1', 'run-1', 19, 'active',
                    '2026-07-23T00:00:00Z', '2026-08-23T00:00:00Z')",
                [],
            )
            .unwrap();

        let payload = parse_approval_payload(TOOL_FIXTURE).unwrap();
        let canonical = canonical_approval_payload(&payload).unwrap();
        let storage_key = format!("objects/{}", &canonical.operation_digest.as_str()[7..]);
        let request_path = artifact_root.join(&storage_key);
        fs::create_dir_all(request_path.parent().unwrap()).unwrap();
        fs::write(request_path, &canonical.canonical_bytes).unwrap();
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
                    canonical.operation_digest.as_str(),
                    storage_key,
                    canonical.canonical_bytes.len() as i64,
                ],
            )
            .unwrap();
        let ApprovalDigestPayload::Tool(tool_payload) = payload else {
            unreachable!();
        };
        connection
            .execute(
                "INSERT INTO policy_decisions (
                    id, task_id, actor_json, actor_binding_digest, action, resource_json,
                    resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                    policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
                 ) VALUES ('policy-1', 'task-1', '{}', ?1, 'process.exec', '{}', ?1,
                    'test', 'Implementation', 'allow', '[]', ?2, ?3,
                    '2026-07-23T12:00:00Z', NULL, NULL)",
                params![
                    format!("sha256:{}", "0".repeat(64)),
                    tool_payload.policy_snapshot_digest,
                    canonical.operation_digest.as_str(),
                ],
            )
            .unwrap();
        canonical.operation_digest
    }
}
