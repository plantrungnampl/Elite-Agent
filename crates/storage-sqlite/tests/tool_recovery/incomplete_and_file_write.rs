fn durable_read_fingerprint(database: &TempDatabase) -> (i64, String) {
    configured_connection(&database.path)
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM events),
                oi.status || ':' || te.status || ':' || oa.status || ':' ||
                    oi.current_attempt_no
             FROM operation_intents oi
             JOIN tool_executions te ON te.id = oi.id
             JOIN operation_attempts oa ON oa.id = te.operation_attempt_id
             ORDER BY oi.id
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn lifecycle_state(database: &TempDatabase, execution_id: &str) -> String {
    configured_connection(&database.path)
        .query_row(
            "SELECT oi.status || ':' || te.status || ':' || oa.status
             FROM operation_intents oi
             JOIN tool_executions te ON te.id = oi.id
             JOIN operation_attempts oa ON oa.id = te.operation_attempt_id
             WHERE oi.id = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn terminal_event_count(database: &TempDatabase) -> i64 {
    configured_connection(&database.path)
        .query_row(
            "SELECT COUNT(*) FROM events WHERE event_type = 'tool.execution.completed'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn tool_boundary_fingerprint(database: &TempDatabase, execution_id: &str) -> (String, i64, i64) {
    configured_connection(&database.path)
        .query_row(
            "SELECT
                oi.status,
                (SELECT COUNT(*) FROM tool_executions WHERE id = oi.id),
                (SELECT COUNT(*) FROM events)
             FROM operation_intents oi
             WHERE oi.id = ?1",
            [execution_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn assert_integrity_failure<T: std::fmt::Debug>(
    result: Result<T, local_agent_terminal_application::PortError>,
) {
    assert_eq!(
        result.unwrap_err().safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
}

#[test]
fn file_write_ports_fail_closed_without_v7_attempt_and_receipt_authority() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let (intent, completion) = file_write_recovery(&database, "file-write-no-authority");
    let execution_id = intent.request.execution_id.clone();

    assert_integrity_failure(store.prepare(intent));
    assert_integrity_failure(store.start(&execution_id));
    assert_integrity_failure(store.complete(completion.clone()));
    assert_integrity_failure(store.complete_recovery(completion));
    assert_integrity_failure(store.fail(&execution_id, FileWriteRecoveryFailure::NotStarted));
    assert_integrity_failure(store.mark_indeterminate(&execution_id));
    assert_integrity_failure(store.recover());

    let connection = configured_connection(&database.path);
    let rows: i64 = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM operation_intents WHERE id = ?1) +
                (SELECT COUNT(*) FROM tool_executions WHERE id = ?1)",
            [execution_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}
