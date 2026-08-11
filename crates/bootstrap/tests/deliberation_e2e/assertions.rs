use local_agent_terminal_domain::{DisclosureKind, EvidenceFreshness};
use rusqlite::{params, Connection};

use super::{RolePackageSpec, POLICY_DIGEST, TASK_ID};

pub(super) fn assert_role_package(
    package: &local_agent_terminal_domain::ContextPackageBinding,
    role: &RolePackageSpec,
    revision: &str,
) {
    assert_eq!(package.descriptor().package_id(), role.package_id);
    assert_eq!(package.descriptor().agent_id(), role.agent_id);
    assert_eq!(package.descriptor().role(), role.role);
    assert_eq!(package.descriptor().objective(), role.objective);
    assert_eq!(
        package.descriptor().agent_manifest_artifact_id().as_str(),
        role.manifest_artifact_id
    );
    assert_eq!(
        package
            .descriptor()
            .effective_content_artifact_id()
            .as_str(),
        role.context_artifact_id
    );
    assert_eq!(
        package.policy().policy_snapshot_digest().as_str(),
        POLICY_DIGEST
    );
    assert_eq!(package.members().len(), 2);
    assert!(package.members().iter().all(|member| {
        member.citation().source().revision() == revision
            && member.citation().freshness() == EvidenceFreshness::Current
            && member.disclosure().kind() == DisclosureKind::Allowed
            && member.citation().source().path_identity() != ".env"
    }));
    assert!(package
        .policy()
        .decision_ids()
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
}

pub(super) fn assert_linked_policy(
    connection: &Connection,
    role: &RolePackageSpec,
    expected_actions: [i64; 4],
    expected_redacted_rules: i64,
    expected_denials: i64,
) {
    let actions = [
        "context.index_metadata",
        "context.index_content",
        "context.retrieve_item",
        "context.final_package",
    ];
    for (action, expected) in actions.into_iter().zip(expected_actions) {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*)
                 FROM context_package_policy_decisions links
                 JOIN policy_decisions decisions ON decisions.id = links.policy_decision_id
                 WHERE links.package_id = ?1 AND decisions.action = ?2",
                params![role.package_id, action],
                |row| row.get(0),
            )
            .expect("linked action count");
        assert_eq!(count, expected, "{} action {action}", role.role);
    }
    let redacted_rules: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM context_package_policy_decisions links
             JOIN policy_decisions decisions ON decisions.id = links.policy_decision_id
             WHERE links.package_id = ?1
               AND json_extract(decisions.matched_rules_json, '$.redactions[0]') = 'secret_scanner'",
            [role.package_id],
            |row| row.get(0),
        )
        .expect("linked redaction count");
    let denials: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM context_package_policy_decisions links
             JOIN policy_decisions decisions ON decisions.id = links.policy_decision_id
             WHERE links.package_id = ?1 AND decisions.effect = 'deny'",
            [role.package_id],
            |row| row.get(0),
        )
        .expect("linked denial count");
    let manifest_is_exact: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM artifacts
                WHERE id = ?1 AND task_id = ?2 AND artifact_type = 'manifest'
                  AND content_hash = ?3 AND availability = 'available'
             )",
            params![role.manifest_artifact_id, TASK_ID, role.manifest_digest],
            |row| row.get(0),
        )
        .expect("manifest binding");
    let package_is_exact: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM context_packages
                WHERE id = ?1 AND task_id = ?2 AND agent_id = ?3 AND role = ?4
                  AND objective = ?5 AND manifest_artifact_id = ?6
                  AND effective_content_artifact_id = ?7 AND policy_snapshot_digest = ?8
             )",
            params![
                role.package_id,
                TASK_ID,
                role.agent_id,
                role.role,
                role.objective,
                role.manifest_artifact_id,
                role.context_artifact_id,
                POLICY_DIGEST,
            ],
            |row| row.get(0),
        )
        .expect("package binding");
    assert_eq!(
        redacted_rules, expected_redacted_rules,
        "{} redactions",
        role.role
    );
    assert_eq!(denials, expected_denials, "{} denials", role.role);
    assert!(manifest_is_exact, "{} manifest", role.role);
    assert!(package_is_exact, "{} package", role.role);
}
