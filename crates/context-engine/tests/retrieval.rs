use local_agent_terminal_application::ContextSourceState;
use local_agent_terminal_context_engine::{
    KeywordDocument, KeywordDocumentInput, KeywordIndex, KeywordRetrievalQuery,
};
use local_agent_terminal_domain::{ProjectId, Sha256Digest, SourceIdentity, TaskId};
use sha2::{Digest, Sha256};

#[test]
fn ranks_exact_path_symbol_and_terms_before_stable_tie_order() {
    let documents = vec![
        document(
            "doc-path",
            "member-path",
            "src/auth/token.rs",
            Some("unrelated"),
            Some("refresh credential"),
        ),
        document(
            "doc-symbol",
            "member-symbol",
            "src/session.rs",
            Some("rotate_refresh_token"),
            Some("refresh credential"),
        ),
        document(
            "doc-term-b",
            "member-term-b",
            "src/z.rs",
            None,
            Some("rotate refresh token safely"),
        ),
        document(
            "doc-term-a",
            "member-term-a",
            "src/a.rs",
            None,
            Some("rotate refresh token safely"),
        ),
    ];
    let current = documents
        .iter()
        .map(|document| document.identity().clone())
        .collect();
    let index = KeywordIndex::rebuild(documents).unwrap();

    let hits = index.search(&KeywordRetrievalQuery {
        task_id: task(),
        terms: vec![
            "src/auth/token.rs".to_owned(),
            "rotate_refresh_token".to_owned(),
            "refresh".to_owned(),
        ],
        role: "reviewer".to_owned(),
        current_sources: current,
        max_items: 10,
    });

    assert_eq!(
        hit_ids(&hits),
        vec![
            "member-path",
            "member-symbol",
            "member-term-a",
            "member-term-b"
        ]
    );
    assert!(hits
        .windows(2)
        .all(|pair| pair[0].score() >= pair[1].score()));
}

#[test]
fn boosts_task_files_accepted_decisions_and_matching_roles_deterministically() {
    let plain = document(
        "doc-plain",
        "member-plain",
        "src/plain.rs",
        None,
        Some("shared evidence"),
    );
    let task_file = KeywordDocument::new(KeywordDocumentInput {
        task_file: true,
        ..input(
            "doc-task",
            "member-task",
            "src/task.rs",
            None,
            Some("shared evidence"),
        )
    })
    .unwrap();
    let accepted = KeywordDocument::new(KeywordDocumentInput {
        accepted_decision: true,
        ..input(
            "doc-accepted",
            "member-accepted",
            "src/accepted.rs",
            None,
            Some("shared evidence"),
        )
    })
    .unwrap();
    let role = KeywordDocument::new(KeywordDocumentInput {
        role_tags: vec!["security-critic".to_owned()],
        ..input(
            "doc-role",
            "member-role",
            "src/role.rs",
            None,
            Some("shared evidence"),
        )
    })
    .unwrap();
    let documents = vec![plain, task_file, accepted, role];
    let current = documents
        .iter()
        .map(|document| document.identity().clone())
        .collect();
    let index = KeywordIndex::rebuild(documents).unwrap();

    let hits = index.search(&KeywordRetrievalQuery {
        task_id: task(),
        terms: vec!["shared evidence".to_owned()],
        role: "security-critic".to_owned(),
        current_sources: current,
        max_items: 10,
    });

    assert_eq!(hits[0].member_id(), "member-role");
    assert!(
        hits.iter()
            .position(|hit| hit.member_id() == "member-accepted")
            .unwrap()
            < hits
                .iter()
                .position(|hit| hit.member_id() == "member-plain")
                .unwrap()
    );
    assert!(
        hits.iter()
            .position(|hit| hit.member_id() == "member-task")
            .unwrap()
            < hits
                .iter()
                .position(|hit| hit.member_id() == "member-plain")
                .unwrap()
    );
}

#[test]
fn metadata_only_mode_still_finds_exact_paths_without_content_terms() {
    let metadata_only = document(
        "doc-metadata",
        "member-metadata",
        "docs/security-model.md",
        Some("ThreatModel"),
        None,
    );
    let current = vec![metadata_only.identity().clone()];
    let index = KeywordIndex::rebuild(vec![metadata_only]).unwrap();

    let hits = index.search(&KeywordRetrievalQuery {
        task_id: task(),
        terms: vec!["docs/security-model.md".to_owned()],
        role: "reviewer".to_owned(),
        current_sources: current,
        max_items: 5,
    });

    assert_eq!(hit_ids(&hits), vec!["member-metadata"]);
}

#[test]
fn excludes_noncurrent_cross_task_and_changed_sources_and_deduplicates_hashes() {
    let current = document(
        "doc-current",
        "member-current",
        "src/current.rs",
        None,
        Some("needle"),
    );
    let duplicate = KeywordDocument::new(KeywordDocumentInput {
        identity: SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            "src/duplicate.rs",
            current.identity().content_hash().clone(),
        )
        .unwrap(),
        ..input(
            "doc-duplicate",
            "member-duplicate",
            "src/duplicate.rs",
            None,
            Some("needle"),
        )
    })
    .unwrap();
    let stale = with_state("stale", ContextSourceState::Stale);
    let failed = with_state("failed", ContextSourceState::Failed);
    let denied = with_state("denied", ContextSourceState::Denied);
    let other_task = KeywordDocument::new(KeywordDocumentInput {
        task_id: TaskId::new("task-2").unwrap(),
        ..input(
            "doc-other",
            "member-other",
            "src/other.rs",
            None,
            Some("needle"),
        )
    })
    .unwrap();
    let changed = document(
        "doc-changed",
        "member-changed",
        "src/changed.rs",
        None,
        Some("needle"),
    );
    let changed_current_identity = SourceIdentity::new(
        ProjectId::new("project-1").unwrap(),
        "commit-2",
        "src/changed.rs",
        digest(b"new bytes"),
    )
    .unwrap();
    let valid_sources = vec![
        current.identity().clone(),
        duplicate.identity().clone(),
        changed_current_identity,
    ];
    let index = KeywordIndex::rebuild(vec![
        duplicate, current, stale, failed, denied, other_task, changed,
    ])
    .unwrap();

    let hits = index.search(&KeywordRetrievalQuery {
        task_id: task(),
        terms: vec!["needle".to_owned()],
        role: "reviewer".to_owned(),
        current_sources: valid_sources,
        max_items: 10,
    });

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].member_id(), "member-current");
}

#[test]
fn bounds_results_even_when_every_candidate_matches() {
    let documents = (0..20)
        .map(|index| {
            document(
                &format!("doc-{index:02}"),
                &format!("member-{index:02}"),
                &format!("src/{index:02}.rs"),
                None,
                Some("common term"),
            )
        })
        .collect::<Vec<_>>();
    let current = documents
        .iter()
        .map(|document| document.identity().clone())
        .collect();
    let index = KeywordIndex::rebuild(documents).unwrap();

    let hits = index.search(&KeywordRetrievalQuery {
        task_id: task(),
        terms: vec!["common".to_owned()],
        role: "reviewer".to_owned(),
        current_sources: current,
        max_items: 3,
    });

    assert_eq!(hit_ids(&hits), vec!["member-00", "member-01", "member-02"]);
}

#[test]
fn rejects_duplicate_task_member_ids_even_when_paths_sort_apart() {
    let duplicate_a = document(
        "doc-duplicate-a",
        "member-duplicate",
        "src/a.rs",
        None,
        Some("first"),
    );
    let middle = document(
        "doc-middle",
        "member-middle",
        "src/m.rs",
        None,
        Some("middle"),
    );
    let duplicate_z = document(
        "doc-duplicate-z",
        "member-duplicate",
        "src/z.rs",
        None,
        Some("last"),
    );

    let error = KeywordIndex::rebuild(vec![duplicate_a, middle, duplicate_z]).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::InvalidInput
    );
}

fn with_state(suffix: &str, state: ContextSourceState) -> KeywordDocument {
    KeywordDocument::new(KeywordDocumentInput {
        state,
        ..input(
            &format!("doc-{suffix}"),
            &format!("member-{suffix}"),
            &format!("src/{suffix}.rs"),
            None,
            Some("needle"),
        )
    })
    .unwrap()
}

fn document(
    document_id: &str,
    member_id: &str,
    path: &str,
    symbol: Option<&str>,
    text: Option<&str>,
) -> KeywordDocument {
    KeywordDocument::new(input(document_id, member_id, path, symbol, text)).unwrap()
}

fn input(
    document_id: &str,
    member_id: &str,
    path: &str,
    symbol: Option<&str>,
    text: Option<&str>,
) -> KeywordDocumentInput {
    KeywordDocumentInput {
        document_id: document_id.to_owned(),
        member_id: member_id.to_owned(),
        task_id: task(),
        identity: SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            path,
            digest(format!("content:{document_id}").as_bytes()),
        )
        .unwrap(),
        symbol: symbol.map(str::to_owned),
        text: text.map(str::to_owned),
        role_tags: Vec::new(),
        task_file: false,
        accepted_decision: false,
        state: ContextSourceState::Current,
    }
}

fn hit_ids(hits: &[local_agent_terminal_context_engine::KeywordHit]) -> Vec<&str> {
    hits.iter().map(|hit| hit.member_id()).collect()
}

fn task() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
