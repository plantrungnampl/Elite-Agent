use std::collections::{BTreeMap, BTreeSet};

use local_agent_terminal_application::{
    ContextSourceState, PortError, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{Sha256Digest, SourceIdentity, TaskId};

#[derive(Debug, Clone)]
pub struct KeywordDocumentInput {
    pub document_id: String,
    pub member_id: String,
    pub task_id: TaskId,
    pub identity: SourceIdentity,
    pub symbol: Option<String>,
    pub text: Option<String>,
    pub role_tags: Vec<String>,
    pub task_file: bool,
    pub accepted_decision: bool,
    pub state: ContextSourceState,
}

#[derive(Debug, Clone)]
pub struct KeywordDocument {
    document_id: String,
    member_id: String,
    task_id: TaskId,
    identity: SourceIdentity,
    symbol: Option<String>,
    terms: BTreeSet<String>,
    role_tags: BTreeSet<String>,
    task_file: bool,
    accepted_decision: bool,
    state: ContextSourceState,
}

impl KeywordDocument {
    pub fn new(input: KeywordDocumentInput) -> Result<Self, PortError> {
        if !valid_label(&input.document_id)
            || !valid_label(&input.member_id)
            || input
                .symbol
                .as_deref()
                .is_some_and(|value| !valid_label(value))
            || input.role_tags.iter().any(|value| !valid_label(value))
        {
            return Err(invalid());
        }
        let mut terms = tokenize(input.identity.path_identity());
        if let Some(symbol) = &input.symbol {
            terms.extend(tokenize(symbol));
        }
        if let Some(text) = &input.text {
            terms.extend(tokenize(text));
        }
        Ok(Self {
            document_id: input.document_id,
            member_id: input.member_id,
            task_id: input.task_id,
            identity: input.identity,
            symbol: input.symbol,
            terms,
            role_tags: input
                .role_tags
                .into_iter()
                .map(|value| normalize_exact(&value))
                .collect(),
            task_file: input.task_file,
            accepted_decision: input.accepted_decision,
            state: input.state,
        })
    }

    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }
}

#[derive(Debug, Clone)]
pub struct KeywordRetrievalQuery {
    pub task_id: TaskId,
    pub terms: Vec<String>,
    pub role: String,
    pub current_sources: Vec<SourceIdentity>,
    pub max_items: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeywordHit {
    document_id: String,
    member_id: String,
    score: u64,
}

impl KeywordHit {
    pub fn document_id(&self) -> &str {
        &self.document_id
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    pub const fn score(&self) -> u64 {
        self.score
    }
}

#[derive(Debug, Default)]
pub struct KeywordIndex {
    documents: Vec<KeywordDocument>,
    inverted: BTreeMap<String, BTreeSet<usize>>,
}

impl KeywordIndex {
    pub fn rebuild(mut documents: Vec<KeywordDocument>) -> Result<Self, PortError> {
        documents.sort_by(|left, right| {
            left.identity
                .path_identity()
                .cmp(right.identity.path_identity())
                .then_with(|| left.member_id.cmp(&right.member_id))
        });
        let mut member_ids = BTreeSet::new();
        if documents.iter().any(|document| {
            !member_ids.insert((
                document.task_id.as_str().to_owned(),
                document.member_id.as_str(),
            ))
        }) {
            return Err(invalid());
        }
        let mut inverted = BTreeMap::<String, BTreeSet<usize>>::new();
        for (index, document) in documents.iter().enumerate() {
            for term in &document.terms {
                inverted.entry(term.clone()).or_default().insert(index);
            }
        }
        Ok(Self {
            documents,
            inverted,
        })
    }

    pub fn search(&self, query: &KeywordRetrievalQuery) -> Vec<KeywordHit> {
        if query.max_items == 0 || !valid_label(&query.role) {
            return Vec::new();
        }
        let current_sources = query.current_sources.iter().collect::<BTreeSet<_>>();
        let query_tokens = query
            .terms
            .iter()
            .flat_map(|term| tokenize(term))
            .collect::<BTreeSet<_>>();
        let mut candidates = BTreeSet::new();
        for token in &query_tokens {
            if let Some(indices) = self.inverted.get(token) {
                candidates.extend(indices);
            }
        }
        for (index, document) in self.documents.iter().enumerate() {
            if query.terms.iter().any(|term| {
                normalize_exact(term) == normalize_exact(document.identity.path_identity())
                    || document
                        .symbol
                        .as_deref()
                        .is_some_and(|symbol| normalize_exact(term) == normalize_exact(symbol))
            }) {
                candidates.insert(index);
            }
        }

        let role = normalize_exact(&query.role);
        let mut ranked = candidates
            .into_iter()
            .filter_map(|index| {
                let document = &self.documents[index];
                if document.task_id != query.task_id
                    || document.state != ContextSourceState::Current
                    || !current_sources.contains(&document.identity)
                {
                    return None;
                }
                let mut score = 0u64;
                for term in &query.terms {
                    let exact = normalize_exact(term);
                    if exact == normalize_exact(document.identity.path_identity()) {
                        score = score.saturating_add(1_000);
                    }
                    if document
                        .symbol
                        .as_deref()
                        .is_some_and(|symbol| exact == normalize_exact(symbol))
                    {
                        score = score.saturating_add(800);
                    }
                }
                score = score.saturating_add(
                    u64::try_from(query_tokens.intersection(&document.terms).count())
                        .unwrap_or(u64::MAX)
                        .saturating_mul(100),
                );
                if document.role_tags.contains(&role) {
                    score = score.saturating_add(80);
                }
                if document.accepted_decision {
                    score = score.saturating_add(40);
                }
                if document.task_file {
                    score = score.saturating_add(20);
                }
                (score > 0).then_some((index, score))
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|(left_index, left_score), (right_index, right_score)| {
            right_score
                .cmp(left_score)
                .then_with(|| {
                    self.documents[*left_index]
                        .identity
                        .path_identity()
                        .cmp(self.documents[*right_index].identity.path_identity())
                })
                .then_with(|| {
                    self.documents[*left_index]
                        .member_id
                        .cmp(&self.documents[*right_index].member_id)
                })
        });

        let mut content_hashes = BTreeSet::<Sha256Digest>::new();
        ranked
            .into_iter()
            .filter_map(|(index, score)| {
                let document = &self.documents[index];
                content_hashes
                    .insert(document.identity.content_hash().clone())
                    .then_some(KeywordHit {
                        document_id: document.document_id.clone(),
                        member_id: document.member_id.clone(),
                        score,
                    })
            })
            .take(query.max_items as usize)
            .collect()
    }
}

fn tokenize(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn normalize_exact(value: &str) -> String {
    value.trim().to_lowercase()
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1_024 && !value.contains('\0')
}

fn invalid() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
