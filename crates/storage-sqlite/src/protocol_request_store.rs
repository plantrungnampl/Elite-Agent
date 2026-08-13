use std::path::Path;

use local_agent_terminal_application::{
    ArtifactRef, ArtifactRootReader, PortError, ProtocolRequestBegin, ProtocolRequestBeginResult,
    ProtocolRequestIdentity, ProtocolRequestRecord, ProtocolRequestState, ProtocolRequestStore,
    ProtocolRequestTerminal, ProtocolRequestTerminalStatus, ProtocolResponseArtifact,
    ProtocolStreamAdvance, ProtocolStreamIdentity, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{ArtifactId, RunId, Sequence, Sha256Digest, TaskId};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

struct RawProtocolRequest {
    method: String,
    request_digest: String,
    task_id: Option<String>,
    run_id: Option<String>,
    status: String,
    response_artifact_id: Option<String>,
    created_at: String,
    completed_at: Option<String>,
}

struct RawResponseArtifact {
    owner: Option<String>,
    project_id: String,
    kind: String,
    content_hash: String,
    size_bytes: i64,
    storage_key: String,
    availability: String,
    verification: String,
}

impl ProtocolRequestStore for SqliteStore {
    fn begin(
        &self,
        request: &ProtocolRequestBegin,
    ) -> Result<ProtocolRequestBeginResult, PortError> {
        request.validate()?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let existing = raw_protocol_request(&transaction, request.identity())?;
        let result = match existing {
            None => {
                transaction
                    .execute(
                        "INSERT INTO protocol_requests (
                            connection_id, request_id, method, request_digest, task_id, run_id,
                            status, response_artifact_id, created_at, completed_at
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, ?7, NULL)",
                        params![
                            request.identity().connection_id(),
                            request.identity().request_id(),
                            request.identity().method(),
                            request.identity().request_digest().as_str(),
                            request.task_id().map(TaskId::as_str),
                            request.run_id().map(RunId::as_str),
                            request.created_at(),
                        ],
                    )
                    .map_err(sqlite_error_to_port)?;
                ProtocolRequestBeginResult::Begun
            }
            Some(raw) => {
                require_matching_identity(&raw, request.identity())?;
                let record = protocol_request_record(
                    &transaction,
                    self.artifact_reader(),
                    request.identity(),
                    raw,
                )?;
                match record.state() {
                    ProtocolRequestState::Pending => ProtocolRequestBeginResult::Pending,
                    ProtocolRequestState::Terminal(terminal) => {
                        ProtocolRequestBeginResult::Replayed(terminal.clone())
                    }
                }
            }
        };
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(result)
    }

    fn load(
        &self,
        identity: &ProtocolRequestIdentity,
    ) -> Result<Option<ProtocolRequestRecord>, PortError> {
        identity.validate()?;
        let connection = self.connection().map_err(open_error_to_port)?;
        let Some(raw) = raw_protocol_request(&connection, identity)? else {
            return Ok(None);
        };
        require_matching_identity(&raw, identity)?;
        protocol_request_record(&connection, self.artifact_reader(), identity, raw).map(Some)
    }

    fn complete(
        &self,
        terminal: &ProtocolRequestTerminal,
    ) -> Result<ProtocolRequestTerminal, PortError> {
        terminal.validate()?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let raw = raw_protocol_request(&transaction, terminal.identity())?.ok_or_else(not_found)?;
        require_matching_identity(&raw, terminal.identity())?;
        let begin = begin_from_raw(terminal.identity(), &raw)?;
        let result = match raw.status.as_str() {
            "pending" => {
                if raw.response_artifact_id.is_some() || raw.completed_at.is_some() {
                    return Err(integrity_failure());
                }
                verify_response_artifact(
                    &transaction,
                    self.artifact_reader(),
                    begin.task_id(),
                    terminal.response(),
                )?;
                let updated = transaction
                    .execute(
                        "UPDATE protocol_requests
                         SET status = ?1, response_artifact_id = ?2, completed_at = ?3
                         WHERE connection_id = ?4 AND request_id = ?5
                           AND status = 'pending' AND response_artifact_id IS NULL
                           AND completed_at IS NULL",
                        params![
                            terminal.status().as_str(),
                            terminal.response().artifact_id().as_str(),
                            terminal.completed_at(),
                            terminal.identity().connection_id(),
                            terminal.identity().request_id(),
                        ],
                    )
                    .map_err(sqlite_error_to_port)?;
                if updated != 1 {
                    return Err(conflict());
                }
                terminal.clone()
            }
            "completed" | "failed" => {
                let existing = terminal_from_raw(
                    &transaction,
                    self.artifact_reader(),
                    terminal.identity(),
                    &begin,
                    &raw,
                )?;
                if existing != *terminal {
                    return Err(conflict());
                }
                existing
            }
            _ => return Err(integrity_failure()),
        };
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(result)
    }

    fn load_stream_head(
        &self,
        stream: &ProtocolStreamIdentity,
    ) -> Result<Option<Sequence>, PortError> {
        stream.validate()?;
        let connection = self.connection().map_err(open_error_to_port)?;
        let sequence: Option<i64> = connection
            .query_row(
                "SELECT last_sequence FROM protocol_stream_heads
                 WHERE connection_id = ?1 AND run_id = ?2 AND channel = ?3",
                params![
                    stream.connection_id(),
                    stream.run_id().as_str(),
                    stream.channel()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        sequence
            .map(|sequence| Sequence::try_from(sequence).map_err(|_| integrity_failure()))
            .transpose()
    }

    fn advance_stream(&self, advance: &ProtocolStreamAdvance) -> Result<(), PortError> {
        advance.validate()?;
        let sequence = i64::try_from(advance.sequence().get()).map_err(|_| invalid_input())?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT last_sequence FROM protocol_stream_heads
                 WHERE connection_id = ?1 AND run_id = ?2 AND channel = ?3",
                params![
                    advance.connection_id(),
                    advance.run_id().as_str(),
                    advance.channel(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        match current {
            None => {
                transaction
                    .execute(
                        "INSERT INTO protocol_stream_heads (
                            connection_id, run_id, channel, last_sequence
                         ) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            advance.connection_id(),
                            advance.run_id().as_str(),
                            advance.channel(),
                            sequence,
                        ],
                    )
                    .map_err(sqlite_error_to_port)?;
            }
            Some(current) if current == sequence => {}
            Some(current) if current.checked_add(1) == Some(sequence) => {
                let updated = transaction
                    .execute(
                        "UPDATE protocol_stream_heads
                         SET last_sequence = ?1
                         WHERE connection_id = ?2 AND run_id = ?3 AND channel = ?4
                           AND last_sequence = ?5",
                        params![
                            sequence,
                            advance.connection_id(),
                            advance.run_id().as_str(),
                            advance.channel(),
                            current,
                        ],
                    )
                    .map_err(sqlite_error_to_port)?;
                if updated != 1 {
                    return Err(conflict());
                }
            }
            Some(_) => return Err(conflict()),
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

fn raw_protocol_request(
    connection: &Connection,
    identity: &ProtocolRequestIdentity,
) -> Result<Option<RawProtocolRequest>, PortError> {
    connection
        .query_row(
            "SELECT method, request_digest, task_id, run_id, status, response_artifact_id,
                    created_at, completed_at
             FROM protocol_requests
             WHERE connection_id = ?1 AND request_id = ?2",
            params![identity.connection_id(), identity.request_id()],
            |row| {
                Ok(RawProtocolRequest {
                    method: row.get(0)?,
                    request_digest: row.get(1)?,
                    task_id: row.get(2)?,
                    run_id: row.get(3)?,
                    status: row.get(4)?,
                    response_artifact_id: row.get(5)?,
                    created_at: row.get(6)?,
                    completed_at: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)
}

fn require_matching_identity(
    raw: &RawProtocolRequest,
    identity: &ProtocolRequestIdentity,
) -> Result<(), PortError> {
    if raw.method == identity.method() && raw.request_digest == identity.request_digest().as_str() {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn protocol_request_record(
    connection: &Connection,
    artifact_reader: Option<&dyn ArtifactRootReader>,
    identity: &ProtocolRequestIdentity,
    raw: RawProtocolRequest,
) -> Result<ProtocolRequestRecord, PortError> {
    let begin = begin_from_raw(identity, &raw)?;
    match raw.status.as_str() {
        "pending" => {
            if raw.response_artifact_id.is_some() || raw.completed_at.is_some() {
                return Err(integrity_failure());
            }
            Ok(ProtocolRequestRecord::pending(begin))
        }
        "completed" | "failed" => ProtocolRequestRecord::terminal(
            begin.clone(),
            terminal_from_raw(connection, artifact_reader, identity, &begin, &raw)?,
        ),
        _ => Err(integrity_failure()),
    }
}

fn begin_from_raw(
    identity: &ProtocolRequestIdentity,
    raw: &RawProtocolRequest,
) -> Result<ProtocolRequestBegin, PortError> {
    let task_id = raw
        .task_id
        .as_deref()
        .map(TaskId::new)
        .transpose()
        .map_err(|_| integrity_failure())?;
    let run_id = raw
        .run_id
        .as_deref()
        .map(RunId::new)
        .transpose()
        .map_err(|_| integrity_failure())?;
    ProtocolRequestBegin::new(identity.clone(), task_id, run_id, raw.created_at.clone())
        .map_err(|_| integrity_failure())
}

fn terminal_from_raw(
    connection: &Connection,
    artifact_reader: Option<&dyn ArtifactRootReader>,
    identity: &ProtocolRequestIdentity,
    begin: &ProtocolRequestBegin,
    raw: &RawProtocolRequest,
) -> Result<ProtocolRequestTerminal, PortError> {
    let status =
        ProtocolRequestTerminalStatus::parse(&raw.status).map_err(|_| integrity_failure())?;
    let artifact_id = raw
        .response_artifact_id
        .as_deref()
        .map(ArtifactId::new)
        .transpose()
        .map_err(|_| integrity_failure())?
        .ok_or_else(integrity_failure)?;
    let completed_at = raw.completed_at.as_deref().ok_or_else(integrity_failure)?;
    let response =
        load_response_artifact(connection, artifact_reader, begin.task_id(), &artifact_id)?;
    ProtocolRequestTerminal::new(identity.clone(), status, response, completed_at)
        .map_err(|_| integrity_failure())
}

fn verify_response_artifact(
    connection: &Connection,
    artifact_reader: Option<&dyn ArtifactRootReader>,
    task_id: Option<&TaskId>,
    expected: &ProtocolResponseArtifact,
) -> Result<(), PortError> {
    let actual =
        load_response_artifact(connection, artifact_reader, task_id, expected.artifact_id())?;
    if actual == *expected {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn load_response_artifact(
    connection: &Connection,
    artifact_reader: Option<&dyn ArtifactRootReader>,
    task_id: Option<&TaskId>,
    artifact_id: &ArtifactId,
) -> Result<ProtocolResponseArtifact, PortError> {
    let artifact_reader = artifact_reader.ok_or_else(unavailable)?;
    let artifact: Option<RawResponseArtifact> = connection
        .query_row(
            "SELECT a.task_id, a.project_id, a.artifact_type, a.content_hash,
                        a.size_bytes, a.storage_key, a.availability, a.verification_state
                 FROM artifacts a
                 WHERE a.id = ?1",
            [artifact_id.as_str()],
            |row| {
                Ok(RawResponseArtifact {
                    owner: row.get(0)?,
                    project_id: row.get(1)?,
                    kind: row.get(2)?,
                    content_hash: row.get(3)?,
                    size_bytes: row.get(4)?,
                    storage_key: row.get(5)?,
                    availability: row.get(6)?,
                    verification: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some(RawResponseArtifact {
        owner,
        project_id,
        kind,
        content_hash,
        size_bytes,
        storage_key,
        availability,
        verification,
    }) = artifact
    else {
        return Err(integrity_failure());
    };
    if kind != "protocol-response"
        || availability != "available"
        || verification != "hash_verified"
        || owner.as_deref() != task_id.map(TaskId::as_str)
    {
        return Err(integrity_failure());
    }
    if let Some(task_id) = task_id {
        let task_project: Option<String> = connection
            .query_row(
                "SELECT project_id FROM tasks WHERE id = ?1",
                [task_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if task_project.as_deref() != Some(project_id.as_str()) {
            return Err(integrity_failure());
        }
    }
    let content_hash = Sha256Digest::new(content_hash).map_err(|_| integrity_failure())?;
    let size_bytes = u64::try_from(size_bytes).map_err(|_| integrity_failure())?;
    let artifact_root: String = connection
        .query_row(
            "SELECT artifact_root_path FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    let bytes = artifact_reader
        .read_from_root(
            Path::new(&artifact_root),
            &ArtifactRef {
                content_hash: content_hash.as_str().to_owned(),
                storage_key,
                size_bytes,
            },
        )
        .map_err(|_| integrity_failure())?
        .bytes;
    let response = ProtocolResponseArtifact::new(artifact_id.clone(), bytes)
        .map_err(|_| integrity_failure())?;
    if response.content_digest() != &content_hash || response.size_bytes() != size_bytes {
        return Err(integrity_failure());
    }
    Ok(response)
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::NonRetryable,
    )
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
