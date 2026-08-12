use local_agent_terminal_application::{
    ArtifactRootReader, ContextArtifactRef, ContextChunkRecord, ContextIndexProvenance,
    ContextIndexProvenanceRehydration, ContextPackagePersistence, ContextPolicyDecisionRef,
    ContextQuery, ContextSensitivity, ContextSourceClassification, ContextSourceKind,
    ContextSourceRecord, ContextSourceState, ContextStore, PortError, RetrievedContextItem,
    Retryability, SafeErrorClassification, SourceStateTransition,
};
use local_agent_terminal_domain::{
    ArtifactId, LineRange, ProjectId, Sha256Digest, SourceIdentity, TaskId, Timestamp,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Map, Value};

use crate::agent_store::{validate_available_artifact, validate_available_artifact_kind};
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContextPackageView {
    pub package_id: String,
    pub task_id: String,
    pub agent_id: String,
    pub role: String,
    pub objective: String,
    pub artifact_id: String,
    pub policy_snapshot_digest: String,
    pub prompt_template_version: String,
    pub retrieval_pipeline_version: String,
    pub artifact: local_agent_terminal_application::ArtifactRef,
    pub policy_decision_ids: Vec<String>,
}

impl SqliteStore {
    pub fn context_package_is_invalidated(&self, package_id: &str) -> Result<bool, PortError> {
        if package_id.trim().is_empty() {
            return Err(invalid_input());
        }
        self.connection()
            .map_err(open_error_to_port)?
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM deliberation_context_package_invalidations
                    WHERE context_package_id = ?1
                 )",
                [package_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)
    }

    pub fn context_package_view(
        &self,
        package_id: &str,
    ) -> Result<Option<StoredContextPackageView>, PortError> {
        if package_id.trim().is_empty() {
            return Err(invalid_input());
        }
        let connection = self.connection().map_err(open_error_to_port)?;
        let row = connection
            .query_row(
                "SELECT c.id, c.task_id, c.agent_id, c.role, c.objective,
                        c.effective_content_artifact_id, c.policy_snapshot_digest,
                        c.prompt_template_version, c.retrieval_pipeline_version,
                        a.content_hash, a.storage_key, a.size_bytes
                 FROM context_packages c
                 JOIN artifacts a ON a.id = c.effective_content_artifact_id
                  WHERE c.id = ?1 AND a.availability = 'available'
                    AND NOT EXISTS (
                        SELECT 1 FROM deliberation_context_package_invalidations invalidation
                        WHERE invalidation.context_package_id = c.id
                    )",
                [package_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, i64>(11)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some((
            package_id,
            task_id,
            agent_id,
            role,
            objective,
            artifact_id,
            policy_snapshot_digest,
            prompt_template_version,
            retrieval_pipeline_version,
            content_hash,
            storage_key,
            size_bytes,
        )) = row
        else {
            return Ok(None);
        };
        let size_bytes = u64::try_from(size_bytes).map_err(|_| integrity_failure())?;
        Ok(Some(StoredContextPackageView {
            policy_decision_ids: load_policy_links(&connection, &package_id)?,
            package_id,
            task_id,
            agent_id,
            role,
            objective,
            artifact_id,
            policy_snapshot_digest,
            prompt_template_version,
            retrieval_pipeline_version,
            artifact: local_agent_terminal_application::ArtifactRef {
                content_hash,
                storage_key,
                size_bytes,
            },
        }))
    }
}

type PersistedSourceIdentity = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

impl ContextStore for SqliteStore {
    fn persist_source(&self, source: ContextSourceRecord) -> Result<(), PortError> {
        source.validate()?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        validate_context_artifact(
            &transaction,
            artifact_reader,
            source.classification.evidence(),
            &source.task_id,
        )?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO source_documents (
                    id, project_id, task_id, source_kind, logical_path, revision,
                    content_hash, sensitivity, classification_digest, index_state, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    source.document_id,
                    source.project_id.as_str(),
                    source.task_id.as_str(),
                    source.source_kind.as_str(),
                    source.logical_identity.as_str(),
                    source.revision,
                    source.content_hash.as_str(),
                    source.classification.sensitivity().as_str(),
                    source.classification.result_digest().as_str(),
                    source_state_name(source.state),
                    source.updated_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let persisted: Option<PersistedSourceIdentity> = transaction
            .query_row(
                "SELECT project_id, task_id, source_kind, logical_path, revision,
                            content_hash, sensitivity, classification_digest, index_state
                     FROM source_documents WHERE id = ?1 AND updated_at = ?2",
                params![source.document_id, source.updated_at],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let expected = (
            source.project_id.as_str().to_owned(),
            source.task_id.as_str().to_owned(),
            source.source_kind.as_str().to_owned(),
            source.logical_identity.as_str().to_owned(),
            source.revision,
            source.content_hash.as_str().to_owned(),
            source.classification.sensitivity().as_str().to_owned(),
            source.classification.result_digest().as_str().to_owned(),
            source_state_name(source.state).to_owned(),
        );
        if persisted.as_ref() != Some(&expected) {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn persist_chunk(&self, chunk: ContextChunkRecord) -> Result<(), PortError> {
        chunk.validate()?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        validate_context_artifact(
            &transaction,
            artifact_reader,
            &chunk.artifact,
            &chunk.task_id,
        )?;
        validate_context_artifact(
            &transaction,
            artifact_reader,
            chunk.classification.evidence(),
            &chunk.task_id,
        )?;
        verify_chunk_source(&transaction, &chunk)?;
        let metadata_json = canonical_chunk_metadata(&chunk)?;
        let start_line = chunk.line_range.map(|range| i64::from(range.start()));
        let end_line = chunk.line_range.map(|range| i64::from(range.end()));
        transaction
            .execute(
                "INSERT OR IGNORE INTO source_chunks (
                    id, document_id, symbol, start_line, end_line, content_hash,
                    metadata_json, vector_key, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                    strftime('%Y-%m-%dT%H:%M:%SZ', ?9, 'unixepoch'))",
                params![
                    chunk.member_id,
                    chunk.document_id,
                    chunk.symbol,
                    start_line,
                    end_line,
                    chunk.artifact.content_digest().as_str(),
                    metadata_json,
                    chunk.artifact.artifact_id().as_str(),
                    chunk.created_at.unix_seconds(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let exact: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM source_chunks
                    WHERE id = ?1 AND document_id = ?2 AND symbol IS ?3
                      AND start_line IS ?4 AND end_line IS ?5 AND content_hash = ?6
                      AND metadata_json = ?7 AND vector_key = ?8 AND unixepoch(created_at) = ?9
                 )",
                params![
                    chunk.member_id,
                    chunk.document_id,
                    chunk.symbol,
                    start_line,
                    end_line,
                    chunk.artifact.content_digest().as_str(),
                    metadata_json,
                    chunk.artifact.artifact_id().as_str(),
                    chunk.created_at.unix_seconds(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !exact {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn transition_source(&self, transition: SourceStateTransition) -> Result<(), PortError> {
        transition.validate()?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let changed = transaction
            .execute(
                "UPDATE source_documents SET index_state = ?1, updated_at = ?2
                 WHERE id = ?3 AND index_state = ?4",
                params![
                    source_state_name(transition.next_state),
                    transition.updated_at,
                    transition.document_id,
                    source_state_name(transition.expected_state),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed == 0 {
            let exact: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM source_documents
                        WHERE id = ?1 AND index_state = ?2 AND updated_at = ?3
                     )",
                    params![
                        transition.document_id,
                        source_state_name(transition.next_state),
                        transition.updated_at,
                    ],
                    |row| row.get(0),
                )
                .map_err(sqlite_error_to_port)?;
            if !exact {
                return Err(conflict());
            }
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn query(&self, query: ContextQuery) -> Result<Vec<RetrievedContextItem>, PortError> {
        validate_query(&query)?;
        let artifact_reader = configured_artifact_reader(self)?;
        let connection = self.connection().map_err(open_error_to_port)?;
        let mut statement = connection
            .prepare(
                "SELECT d.id, d.project_id, d.logical_path, d.revision, d.content_hash,
                        d.source_kind, d.sensitivity, d.classification_digest,
                        c.id, c.symbol, c.start_line, c.end_line, c.content_hash,
                        c.metadata_json, c.vector_key, unixepoch(c.created_at)
                 FROM source_chunks c
                 JOIN source_documents d ON d.id = c.document_id
                 WHERE d.task_id = ?1 AND d.index_state = 'current'
                 ORDER BY c.created_at, c.id",
            )
            .map_err(sqlite_error_to_port)?;
        let rows = statement
            .query_map([query.task_id.as_str()], |row| {
                Ok(RawContextChunk {
                    document_id: row.get(0)?,
                    project_id: row.get(1)?,
                    logical_path: row.get(2)?,
                    revision: row.get(3)?,
                    source_content_hash: row.get(4)?,
                    source_kind: row.get(5)?,
                    sensitivity: row.get(6)?,
                    classification_digest: row.get(7)?,
                    member_id: row.get(8)?,
                    symbol: row.get(9)?,
                    start_line: row.get(10)?,
                    end_line: row.get(11)?,
                    artifact_content_hash: row.get(12)?,
                    metadata_json: row.get(13)?,
                    artifact_id: row.get(14)?,
                    created_at: row.get(15)?,
                })
            })
            .map_err(sqlite_error_to_port)?;
        let mut items = Vec::new();
        let mut tokens = 0_u64;
        for row in rows {
            let raw = row.map_err(sqlite_error_to_port)?;
            let item = rehydrate_item(&connection, artifact_reader, &query.task_id, raw)?;
            if !query_matches(&query, &item) {
                continue;
            }
            let next_tokens = tokens
                .checked_add(item.artifact.size_bytes())
                .ok_or_else(invalid_input)?;
            if next_tokens > query.max_tokens {
                continue;
            }
            tokens = next_tokens;
            items.push(item);
            if items.len() == usize::try_from(query.max_items).map_err(|_| invalid_input())? {
                break;
            }
        }
        Ok(items)
    }

    fn persist_package_with_policy_decisions(
        &self,
        persistence: ContextPackagePersistence,
    ) -> Result<(), PortError> {
        let binding = &persistence.package.binding;
        let descriptor = binding.descriptor();
        let artifact_reader = configured_artifact_reader(self)?;
        let mut requested: Vec<_> = persistence
            .policy_decision_ids
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect();
        requested.sort();
        if requested.windows(2).any(|pair| pair[0] == pair[1])
            || requested != binding.policy().decision_ids()
        {
            return Err(invalid_input());
        }
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        validate_available_artifact_kind(
            &transaction,
            artifact_reader,
            descriptor.agent_manifest_artifact_id(),
            descriptor.task_id(),
            "manifest",
            None,
            None,
        )?;
        validate_available_artifact(
            &transaction,
            artifact_reader,
            binding.artifact().artifact_id(),
            descriptor.task_id(),
            Some(binding.artifact().content_digest().as_str()),
            None,
        )?;
        verify_policy_decisions(&transaction, &persistence)?;
        let existing = package_exists(&transaction, descriptor.package_id())?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO context_packages (
                    id, task_id, agent_id, role, objective, manifest_artifact_id,
                    effective_content_artifact_id, content_hash, policy_snapshot_digest,
                    prompt_template_version, retrieval_pipeline_version, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                    strftime('%Y-%m-%dT%H:%M:%SZ', ?12, 'unixepoch'))",
                params![
                    descriptor.package_id(),
                    descriptor.task_id().as_str(),
                    descriptor.agent_id(),
                    descriptor.role(),
                    descriptor.objective(),
                    descriptor.agent_manifest_artifact_id().as_str(),
                    descriptor.effective_content_artifact_id().as_str(),
                    binding.artifact().content_digest().as_str(),
                    binding.policy().policy_snapshot_digest().as_str(),
                    descriptor.versions().prompt_template(),
                    descriptor.versions().retrieval_pipeline(),
                    descriptor.created_at().unix_seconds(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if !package_matches(&transaction, &persistence)? {
            return Err(conflict());
        }
        if existing {
            if load_policy_links(&transaction, descriptor.package_id())? != requested {
                return Err(conflict());
            }
        } else {
            for decision_id in &requested {
                transaction
                    .execute(
                        "INSERT INTO context_package_policy_decisions (
                            package_id, policy_decision_id
                         ) VALUES (?1, ?2)",
                        params![descriptor.package_id(), decision_id],
                    )
                    .map_err(sqlite_error_to_port)?;
            }
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

struct RawContextChunk {
    document_id: String,
    project_id: String,
    logical_path: String,
    revision: String,
    source_content_hash: String,
    source_kind: String,
    sensitivity: String,
    classification_digest: String,
    member_id: String,
    symbol: Option<String>,
    start_line: Option<i64>,
    end_line: Option<i64>,
    artifact_content_hash: String,
    metadata_json: String,
    artifact_id: Option<String>,
    created_at: i64,
}

fn verify_chunk_source(
    connection: &Connection,
    chunk: &ContextChunkRecord,
) -> Result<(), PortError> {
    let exact: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM source_documents
                WHERE id = ?1 AND task_id = ?2 AND project_id = ?3
                  AND logical_path = ?4 AND revision = ?5 AND content_hash = ?6
                  AND sensitivity = ?7 AND classification_digest = ?8
                  AND index_state = 'current'
             )",
            params![
                chunk.document_id,
                chunk.task_id.as_str(),
                chunk.identity.project_id().as_str(),
                chunk.identity.path_identity(),
                chunk.identity.revision(),
                chunk.identity.content_hash().as_str(),
                chunk.classification.sensitivity().as_str(),
                chunk.classification.result_digest().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if exact {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn canonical_chunk_metadata(chunk: &ContextChunkRecord) -> Result<String, PortError> {
    let value = json!({
        "schema": "context-chunk-record",
        "version": 1,
        "taskId": chunk.task_id.as_str(),
        "identity": {
            "projectId": chunk.identity.project_id().as_str(),
            "revision": chunk.identity.revision(),
            "pathIdentity": chunk.identity.path_identity(),
            "contentHash": chunk.identity.content_hash().as_str(),
        },
        "artifact": artifact_json(&chunk.artifact),
        "metadataBytes": chunk.metadata,
        "classification": classification_json(&chunk.classification),
        "provenance": {
            "indexMetadata": policy_ref_json(chunk.provenance.index_metadata()),
            "indexContent": policy_ref_json(chunk.provenance.index_content()),
            "bindingDigest": chunk.provenance.binding_digest().as_str(),
        },
    });
    let bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    String::from_utf8(bytes).map_err(|_| invalid_input())
}

fn artifact_json(reference: &ContextArtifactRef) -> Value {
    json!({
        "artifactId": reference.artifact_id().as_str(),
        "contentDigest": reference.content_digest().as_str(),
        "sizeBytes": reference.size_bytes(),
    })
}

fn classification_json(classification: &ContextSourceClassification) -> Value {
    json!({
        "requestDigest": classification.request_digest().as_str(),
        "sensitivity": classification.sensitivity().as_str(),
        "evidence": artifact_json(classification.evidence()),
        "resultDigest": classification.result_digest().as_str(),
        "classifiedAt": classification.classified_at().unix_seconds(),
    })
}

fn policy_ref_json(reference: &ContextPolicyDecisionRef) -> Value {
    json!({
        "decisionId": reference.decision_id().as_str(),
        "operationDigest": reference.operation_digest().as_str(),
    })
}

fn rehydrate_item(
    connection: &Connection,
    artifact_reader: &dyn ArtifactRootReader,
    task_id: &TaskId,
    raw: RawContextChunk,
) -> Result<RetrievedContextItem, PortError> {
    let value: Value = serde_json::from_str(&raw.metadata_json).map_err(|_| integrity_failure())?;
    let root = object(&value)?;
    if string(root, "schema")? != "context-chunk-record" || integer(root, "version")? != 1 {
        return Err(integrity_failure());
    }
    if string(root, "taskId")? != task_id.as_str() {
        return Err(integrity_failure());
    }
    let identity_value = nested(root, "identity")?;
    let identity = SourceIdentity::new(
        ProjectId::new(string(identity_value, "projectId")?).map_err(|_| integrity_failure())?,
        string(identity_value, "revision")?,
        string(identity_value, "pathIdentity")?,
        digest(identity_value, "contentHash")?,
    )
    .map_err(|_| integrity_failure())?;
    let artifact = parse_artifact(nested(root, "artifact")?)?;
    let classification_value = nested(root, "classification")?;
    let classification = ContextSourceClassification::rehydrate(
        digest(classification_value, "requestDigest")?,
        parse_sensitivity(string(classification_value, "sensitivity")?)?,
        parse_artifact(nested(classification_value, "evidence")?)?,
        digest(classification_value, "resultDigest")?,
        Timestamp::from_unix_seconds(integer(classification_value, "classifiedAt")?),
    )?;
    let provenance_value = nested(root, "provenance")?;
    let line_range = parse_line_range(raw.start_line, raw.end_line)?;
    let metadata = bytes(root, "metadataBytes")?;
    let created_at = Timestamp::from_unix_seconds(raw.created_at);
    let provenance = ContextIndexProvenance::rehydrate(ContextIndexProvenanceRehydration {
        task_id: task_id.clone(),
        document_id: raw.document_id.clone(),
        member_id: raw.member_id.clone(),
        identity: identity.clone(),
        artifact: artifact.clone(),
        metadata: metadata.clone(),
        line_range,
        symbol: raw.symbol.clone(),
        created_at,
        classification: classification.clone(),
        index_metadata: parse_policy_ref(nested(provenance_value, "indexMetadata")?)?,
        index_content: parse_policy_ref(nested(provenance_value, "indexContent")?)?,
        binding_digest: digest(provenance_value, "bindingDigest")?,
    })?;
    if raw.project_id != identity.project_id().as_str()
        || raw.logical_path != identity.path_identity()
        || raw.revision != identity.revision()
        || raw.source_content_hash != identity.content_hash().as_str()
        || raw.source_kind != ContextSourceKind::RepositoryFile.as_str()
        || raw.sensitivity != classification.sensitivity().as_str()
        || raw.classification_digest != classification.result_digest().as_str()
        || raw.artifact_content_hash != artifact.content_digest().as_str()
        || raw.artifact_id.as_deref() != Some(artifact.artifact_id().as_str())
    {
        return Err(integrity_failure());
    }
    validate_context_artifact(connection, artifact_reader, &artifact, task_id)?;
    validate_context_artifact(
        connection,
        artifact_reader,
        classification.evidence(),
        task_id,
    )?;
    let item = RetrievedContextItem {
        document_id: raw.document_id,
        task_id: task_id.clone(),
        member_id: raw.member_id,
        artifact,
        identity,
        metadata,
        line_range,
        symbol: raw.symbol,
        created_at,
        classification,
        provenance,
    };
    item.validate(task_id)?;
    Ok(item)
}

fn validate_context_artifact(
    connection: &Connection,
    artifact_reader: &dyn ArtifactRootReader,
    reference: &ContextArtifactRef,
    task_id: &TaskId,
) -> Result<(), PortError> {
    reference.validate()?;
    validate_available_artifact(
        connection,
        artifact_reader,
        reference.artifact_id(),
        task_id,
        Some(reference.content_digest().as_str()),
        Some(reference.size_bytes()),
    )
}

fn configured_artifact_reader(store: &SqliteStore) -> Result<&dyn ArtifactRootReader, PortError> {
    store.artifact_reader().ok_or_else(unavailable)
}

fn parse_artifact(value: &Map<String, Value>) -> Result<ContextArtifactRef, PortError> {
    ContextArtifactRef::new(
        ArtifactId::new(string(value, "artifactId")?).map_err(|_| integrity_failure())?,
        digest(value, "contentDigest")?,
        unsigned(value, "sizeBytes")?,
    )
}

fn parse_policy_ref(value: &Map<String, Value>) -> Result<ContextPolicyDecisionRef, PortError> {
    Ok(ContextPolicyDecisionRef::new(
        local_agent_terminal_application::PolicyDecisionId::from_persisted(string(
            value,
            "decisionId",
        )?)?,
        digest(value, "operationDigest")?,
    ))
}

fn parse_line_range(start: Option<i64>, end: Option<i64>) -> Result<Option<LineRange>, PortError> {
    match (start, end) {
        (None, None) => Ok(None),
        (Some(start), Some(end)) => LineRange::new(
            u32::try_from(start).map_err(|_| integrity_failure())?,
            u32::try_from(end).map_err(|_| integrity_failure())?,
        )
        .map(Some)
        .map_err(|_| integrity_failure()),
        _ => Err(integrity_failure()),
    }
}

fn verify_policy_decisions(
    connection: &Connection,
    persistence: &ContextPackagePersistence,
) -> Result<(), PortError> {
    let binding = &persistence.package.binding;
    for decision_id in &persistence.policy_decision_ids {
        let exact: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM policy_decisions
                    WHERE id = ?1 AND task_id = ?2 AND policy_snapshot_digest = ?3
                 )",
                params![
                    decision_id.as_str(),
                    binding.descriptor().task_id().as_str(),
                    binding.policy().policy_snapshot_digest().as_str(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !exact {
            return Err(integrity_failure());
        }
    }
    Ok(())
}

fn package_exists(connection: &Connection, package_id: &str) -> Result<bool, PortError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM context_packages WHERE id = ?1)",
            [package_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn package_matches(
    connection: &Connection,
    persistence: &ContextPackagePersistence,
) -> Result<bool, PortError> {
    let binding = &persistence.package.binding;
    let descriptor = binding.descriptor();
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM context_packages
                WHERE id = ?1 AND task_id = ?2 AND agent_id = ?3 AND role = ?4
                  AND objective = ?5 AND manifest_artifact_id = ?6
                  AND effective_content_artifact_id = ?7 AND content_hash = ?8
                  AND policy_snapshot_digest = ?9 AND prompt_template_version = ?10
                  AND retrieval_pipeline_version = ?11 AND unixepoch(created_at) = ?12
             )",
            params![
                descriptor.package_id(),
                descriptor.task_id().as_str(),
                descriptor.agent_id(),
                descriptor.role(),
                descriptor.objective(),
                descriptor.agent_manifest_artifact_id().as_str(),
                descriptor.effective_content_artifact_id().as_str(),
                binding.artifact().content_digest().as_str(),
                binding.policy().policy_snapshot_digest().as_str(),
                descriptor.versions().prompt_template(),
                descriptor.versions().retrieval_pipeline(),
                descriptor.created_at().unix_seconds(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn load_policy_links(connection: &Connection, package_id: &str) -> Result<Vec<String>, PortError> {
    let mut statement = connection
        .prepare(
            "SELECT policy_decision_id FROM context_package_policy_decisions
             WHERE package_id = ?1 ORDER BY policy_decision_id",
        )
        .map_err(sqlite_error_to_port)?;
    let links = statement
        .query_map([package_id], |row| row.get(0))
        .map_err(sqlite_error_to_port)?
        .map(|row| row.map_err(sqlite_error_to_port))
        .collect();
    links
}

fn validate_query(query: &ContextQuery) -> Result<(), PortError> {
    if query.query_id.trim().is_empty()
        || query.max_items == 0
        || query.max_tokens == 0
        || query.terms.iter().any(|term| term.trim().is_empty())
    {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn query_matches(query: &ContextQuery, item: &RetrievedContextItem) -> bool {
    let mut searchable = format!(
        "{} {} {} {} {} {}",
        item.document_id,
        item.member_id,
        item.identity.path_identity(),
        item.identity.revision(),
        item.identity.content_hash().as_str(),
        item.symbol.as_deref().unwrap_or_default(),
    )
    .to_lowercase();
    searchable.push(' ');
    searchable.push_str(&String::from_utf8_lossy(&item.metadata).to_lowercase());
    query
        .terms
        .iter()
        .all(|term| searchable.contains(&term.to_lowercase()))
}

fn object(value: &Value) -> Result<&Map<String, Value>, PortError> {
    value.as_object().ok_or_else(integrity_failure)
}

fn nested<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, PortError> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(integrity_failure)
}

fn string<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a str, PortError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(integrity_failure)
}

fn integer(value: &Map<String, Value>, field: &str) -> Result<i64, PortError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(integrity_failure)
}

fn unsigned(value: &Map<String, Value>, field: &str) -> Result<u64, PortError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(integrity_failure)
}

fn bytes(value: &Map<String, Value>, field: &str) -> Result<Vec<u8>, PortError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(integrity_failure)?
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(integrity_failure)
        })
        .collect()
}

fn digest(value: &Map<String, Value>, field: &str) -> Result<Sha256Digest, PortError> {
    Sha256Digest::new(string(value, field)?).map_err(|_| integrity_failure())
}

fn parse_sensitivity(value: &str) -> Result<ContextSensitivity, PortError> {
    match value {
        "public" => Ok(ContextSensitivity::Public),
        "internal-code" => Ok(ContextSensitivity::InternalCode),
        "restricted" => Ok(ContextSensitivity::Restricted),
        "secret" => Ok(ContextSensitivity::Secret),
        _ => Err(integrity_failure()),
    }
}

fn source_state_name(state: ContextSourceState) -> &'static str {
    match state {
        ContextSourceState::Pending => "pending",
        ContextSourceState::Current => "current",
        ContextSourceState::Stale => "stale",
        ContextSourceState::Denied => "denied",
        ContextSourceState::Failed => "failed",
    }
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}
