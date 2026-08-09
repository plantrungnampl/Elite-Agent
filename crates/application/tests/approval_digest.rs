use local_agent_terminal_application::{
    build_approval_request, canonical_approval_payload, parse_approval_payload,
    parse_canonical_approval_payload, ApprovalDigestPayload, ApprovalId, PlanApprovalOperationV1,
    PlanApprovalPathScopeV1, PlanApprovalPayloadV1, PlanApprovalPlanRefV1, ToolApprovalPayloadV1,
};
use local_agent_terminal_domain::{ArtifactId, ProjectId, TaskId};
use serde_json::{json, Value};

const TOOL_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/contracts/fixtures/m2/tool-approval-valid.json"
));
const UNKNOWN_TOOL_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/contracts/fixtures/m2/tool-approval-unknown-field.json"
));
const POLICY_EXCEPTION: &str = r#"{
  "schema":"approval-digest.v1",
  "approvalType":"policy_exception",
  "taskId":"task-1",
  "operation":{
    "actorBindingDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "purpose":"review",
    "resourceDigest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "destination":"provider",
    "effectivePayloadDigest":"sha256:3333333333333333333333333333333333333333333333333333333333333333",
    "redactionReportDigest":"sha256:4444444444444444444444444444444444444444444444444444444444444444"
  },
  "policySnapshotDigest":"sha256:5555555555555555555555555555555555555555555555555555555555555555",
  "workspaceVersion":4,
  "requestedAt":"2026-07-23T12:00:00Z",
  "expiresAt":"2026-07-23T12:15:00Z",
  "nonce":"0123456789abcdef0123456789abcdef"
}"#;
const OTHER_DIGEST: &str =
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

type PlanPayloadMutation = (&'static str, Box<dyn Fn(&mut PlanApprovalPayloadV1)>);

#[test]
fn shared_parser_round_trips_only_canonical_normative_plan_payloads() {
    let payload = ApprovalDigestPayload::Plan(plan_payload());
    let canonical = canonical_approval_payload(&payload).unwrap();
    let canonical_text = std::str::from_utf8(&canonical.canonical_bytes).unwrap();

    assert_eq!(
        parse_canonical_approval_payload(canonical_text).unwrap(),
        payload
    );

    let duplicate = canonical_text.replacen(
        "\"taskId\":\"task-1\"",
        "\"taskId\":\"task-1\",\"taskId\":\"task-2\"",
        1,
    );
    assert!(parse_canonical_approval_payload(&duplicate).is_err());

    let noncanonical =
        serde_json::to_string_pretty(&serde_json::to_value(&payload).unwrap()).unwrap();
    assert!(parse_canonical_approval_payload(&noncanonical).is_err());
}

#[test]
fn normative_plan_payload_validates_every_schema_shape() {
    let mutations: Vec<PlanPayloadMutation> = vec![
        ("schema", Box::new(|value| value.schema = "other".into())),
        (
            "approval_type",
            Box::new(|value| value.approval_type = "tool".into()),
        ),
        ("task_id", Box::new(|value| value.task_id.clear())),
        ("plan_id", Box::new(|value| value.operation.plan.id.clear())),
        (
            "plan_version_zero",
            Box::new(|value| value.operation.plan.version = 0),
        ),
        (
            "plan_version_unsafe",
            Box::new(|value| value.operation.plan.version = 9_007_199_254_740_992),
        ),
        (
            "plan_digest",
            Box::new(|value| value.operation.plan.content_digest = "bad".into()),
        ),
        (
            "base_commit",
            Box::new(|value| value.operation.base_commit = "bad".into()),
        ),
        (
            "allowed_paths",
            Box::new(|value| value.operation.allowed_paths.clear()),
        ),
        (
            "root_capability",
            Box::new(|value| value.operation.allowed_paths[0].root_capability.clear()),
        ),
        (
            "patterns_empty",
            Box::new(|value| value.operation.allowed_paths[0].patterns.clear()),
        ),
        (
            "patterns_duplicate",
            Box::new(|value| {
                value.operation.allowed_paths[0].patterns = vec!["src/**".into(), "src/**".into()]
            }),
        ),
        (
            "planned_tool_digest",
            Box::new(|value| value.operation.planned_tool_digests[0] = "bad".into()),
        ),
        (
            "planned_tool_duplicate",
            Box::new(|value| {
                value.operation.planned_tool_digests =
                    vec![OTHER_DIGEST.into(), OTHER_DIGEST.into()]
            }),
        ),
        (
            "verification_profile_digest",
            Box::new(|value| value.operation.verification_profile_digest = "bad".into()),
        ),
        (
            "risk_class",
            Box::new(|value| value.operation.risk_class = "unknown".into()),
        ),
        (
            "policy_snapshot_digest",
            Box::new(|value| value.policy_snapshot_digest = "bad".into()),
        ),
        (
            "workspace_version",
            Box::new(|value| value.workspace_version = 9_007_199_254_740_992),
        ),
        (
            "requested_at",
            Box::new(|value| value.requested_at = "bad".into()),
        ),
        (
            "expires_at",
            Box::new(|value| value.expires_at = value.requested_at.clone()),
        ),
        ("nonce", Box::new(|value| value.nonce = "bad".into())),
    ];

    for (name, mutate) in mutations {
        let mut invalid = plan_payload();
        mutate(&mut invalid);
        assert!(
            canonical_approval_payload(&ApprovalDigestPayload::Plan(invalid)).is_err(),
            "{name}"
        );
    }
}

#[test]
fn authorization_parser_rejects_duplicate_keys_floats_negative_zero_and_unsafe_integers() {
    let hostile = [
        TOOL_FIXTURE.replace("\"workspaceVersion\": 4", "\"workspaceVersion\": -0"),
        TOOL_FIXTURE.replace("\"workspaceVersion\": 4", "\"workspaceVersion\": 1.0"),
        TOOL_FIXTURE.replace("\"workspaceVersion\": 4", "\"workspaceVersion\": 1e3"),
        TOOL_FIXTURE.replace(
            "\"taskId\": \"task-1\",",
            "\"taskId\": \"task-1\",\n  \"taskId\": \"task-2\",",
        ),
        TOOL_FIXTURE.replace(
            "\"workspaceVersion\": 4",
            "\"workspaceVersion\": 9007199254740992",
        ),
    ];
    for raw in hostile {
        assert!(parse_approval_payload(&raw).is_err(), "{raw}");
    }
}

#[test]
fn tool_parser_requires_nullable_fencing_and_rejects_null_optional_digests() {
    let value: Value = serde_json::from_str(TOOL_FIXTURE).unwrap();
    let mut missing_fencing = value.clone();
    missing_fencing
        .pointer_mut("/operation")
        .and_then(Value::as_object_mut)
        .unwrap()
        .remove("executorFencingToken");
    let mut null_executable_digest = value.clone();
    set(
        &mut null_executable_digest,
        "/operation/executableDigest",
        Value::Null,
    );
    let mut null_script_digest = value.clone();
    null_script_digest
        .pointer_mut("/operation")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert("scriptDigest".to_owned(), Value::Null);

    for hostile in &[missing_fencing, null_executable_digest, null_script_digest] {
        assert!(
            parse_approval_payload(&serde_json::to_string(hostile).unwrap()).is_err(),
            "{hostile}"
        );
        assert!(serde_json::from_value::<ToolApprovalPayloadV1>(hostile.clone()).is_err());
    }

    let mut explicit_null_fencing = value.clone();
    set(
        &mut explicit_null_fencing,
        "/operation/executorFencingToken",
        Value::Null,
    );
    assert!(
        parse_approval_payload(&serde_json::to_string(&explicit_null_fencing).unwrap()).is_ok()
    );
    assert!(serde_json::from_value::<ToolApprovalPayloadV1>(explicit_null_fencing.clone()).is_ok());

    let mut absent_optional_digests = value;
    absent_optional_digests
        .pointer_mut("/operation")
        .and_then(Value::as_object_mut)
        .unwrap()
        .remove("executableDigest");
    assert!(
        parse_approval_payload(&serde_json::to_string(&absent_optional_digests).unwrap()).is_ok()
    );
    assert!(serde_json::from_value::<ToolApprovalPayloadV1>(absent_optional_digests).is_ok());
}

#[test]
fn approval_ids_are_safe_opaque_path_segments() {
    for invalid in [
        "../../x",
        "..\\..\\x",
        ".",
        "..",
        "approval/1",
        "approval\\1",
    ] {
        assert!(ApprovalId::new(invalid).is_err(), "{invalid}");
    }

    let valid = ApprovalId::new("approval_ABC-123").unwrap();
    assert_eq!(valid.as_str(), "approval_ABC-123");
}

#[test]
fn rfc8785_vectors_cover_ordering_unicode_escaping_and_integer_bounds() {
    let mut value = parsed_value(POLICY_EXCEPTION);
    set(
        &mut value,
        "/operation/purpose",
        json!("€😀\n\t\u{000f}\"\\/"),
    );
    set(
        &mut value,
        "/workspaceVersion",
        json!(9_007_199_254_740_991_u64),
    );

    let canonical = canonical(&value);
    let text = std::str::from_utf8(&canonical.canonical_bytes).unwrap();

    assert!(text.starts_with("{\"approvalType\":\"policy_exception\","));
    assert!(text.contains("\"purpose\":\"€😀\\n\\t\\u000f\\\"\\\\/\""));
    assert!(text.contains("\"workspaceVersion\":9007199254740991"));
}

#[test]
fn timestamp_offsets_and_fractions_normalize_to_utc_before_hashing() {
    let mut value = parsed_value(TOOL_FIXTURE);
    set(
        &mut value,
        "/requestedAt",
        json!("2026-07-23T19:30:00.120+07:30"),
    );
    set(
        &mut value,
        "/expiresAt",
        json!("2026-07-23T05:15:00.500-07:00"),
    );

    let payload = parse_value(&value);
    let ApprovalDigestPayload::Tool(payload) = payload else {
        panic!("tool payload expected");
    };
    assert_eq!(payload.requested_at, "2026-07-23T12:00:00.12Z");
    assert_eq!(payload.expires_at, "2026-07-23T12:15:00.5Z");
}

#[test]
fn every_present_tool_leaf_changes_the_digest_one_at_a_time() {
    let value = parsed_value(TOOL_FIXTURE);
    assert_each_mutation_changes_digest(
        &value,
        &[
            ("/taskId", json!("task-2")),
            ("/operation/runId", json!("run-2")),
            ("/operation/planStepId", json!("step-2")),
            ("/operation/tool", json!("process.other")),
            ("/operation/executableDigest", json!(OTHER_DIGEST)),
            ("/operation/argumentsDigest", json!(OTHER_DIGEST)),
            ("/operation/cwdCapability", json!("worktree:task-2")),
            ("/operation/environmentProfileDigest", json!(OTHER_DIGEST)),
            ("/operation/networkProfile", json!("approved_destinations")),
            ("/operation/expectedWrites/0", json!("generated/**")),
            ("/operation/executorFencingToken", json!(20)),
            ("/policySnapshotDigest", json!(OTHER_DIGEST)),
            ("/workspaceVersion", json!(5)),
            ("/requestedAt", json!("2026-07-23T12:00:01Z")),
            ("/expiresAt", json!("2026-07-23T12:15:01Z")),
            ("/nonce", json!("abcdef0123456789abcdef0123456789")),
        ],
    );
    assert!(parse_approval_payload(UNKNOWN_TOOL_FIXTURE).is_err());
}

#[test]
fn every_policy_exception_leaf_changes_the_digest_one_at_a_time() {
    let value = parsed_value(POLICY_EXCEPTION);
    assert_each_mutation_changes_digest(
        &value,
        &[
            ("/taskId", json!("task-2")),
            ("/operation/actorBindingDigest", json!(OTHER_DIGEST)),
            ("/operation/purpose", json!("release review")),
            ("/operation/resourceDigest", json!(OTHER_DIGEST)),
            ("/operation/destination", json!("provider-2")),
            ("/operation/effectivePayloadDigest", json!(OTHER_DIGEST)),
            ("/operation/redactionReportDigest", json!(OTHER_DIGEST)),
            ("/policySnapshotDigest", json!(OTHER_DIGEST)),
            ("/workspaceVersion", json!(5)),
            ("/requestedAt", json!("2026-07-23T12:00:01Z")),
            ("/expiresAt", json!("2026-07-23T12:15:01Z")),
            ("/nonce", json!("abcdef0123456789abcdef0123456789")),
        ],
    );

    let mut unknown = value;
    unknown
        .pointer_mut("/operation")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert("unknown".to_owned(), json!(true));
    assert!(parse_approval_payload(&serde_json::to_string(&unknown).unwrap()).is_err());
}

#[test]
fn approval_request_uses_the_same_canonical_bytes_and_full_digest() {
    let payload = parse_approval_payload(TOOL_FIXTURE).unwrap();
    let canonical = canonical_approval_payload(&payload).unwrap();
    let built = build_approval_request(
        ArtifactId::new("artifact-approval-1").unwrap(),
        ProjectId::new("project-1").unwrap(),
        TaskId::new("task-1").unwrap(),
        &ApprovalId::new("approval-1").unwrap(),
        &payload,
        "core",
    )
    .unwrap();

    assert_eq!(built.operation_digest, canonical.operation_digest);
    assert_eq!(
        built.artifact_request.canonical_bytes,
        canonical.canonical_bytes
    );
    assert_eq!(
        built.artifact_request.expected_hash,
        built.operation_digest.as_str()
    );
    assert_eq!(built.artifact_request.artifact_type, "approval-payload");
    assert_eq!(
        built.artifact_request.logical_path,
        "approvals/approval-1.json"
    );
}

#[test]
fn programmatic_payloads_enforce_variant_type_integer_and_task_binding() {
    let ApprovalDigestPayload::Tool(tool) = parse_approval_payload(TOOL_FIXTURE).unwrap() else {
        panic!("tool payload expected");
    };

    let mut wrong_type = tool.clone();
    wrong_type.approval_type = "policy_exception".to_owned();
    assert!(canonical_approval_payload(&ApprovalDigestPayload::Tool(wrong_type)).is_err());

    let mut unsafe_integer = tool.clone();
    unsafe_integer.workspace_version = 9_007_199_254_740_992;
    assert!(canonical_approval_payload(&ApprovalDigestPayload::Tool(unsafe_integer)).is_err());

    let mut unsafe_fencing_token = tool.clone();
    unsafe_fencing_token.operation.executor_fencing_token = Some(9_007_199_254_740_992);
    assert!(
        canonical_approval_payload(&ApprovalDigestPayload::Tool(unsafe_fencing_token)).is_err()
    );

    assert!(build_approval_request(
        ArtifactId::new("artifact-approval-1").unwrap(),
        ProjectId::new("project-1").unwrap(),
        TaskId::new("task-2").unwrap(),
        &ApprovalId::new("approval-1").unwrap(),
        &ApprovalDigestPayload::Tool(tool),
        "core",
    )
    .is_err());
}

#[test]
fn shared_plan_extension_preserves_tool_and_policy_exception_round_trips() {
    for raw in [TOOL_FIXTURE, POLICY_EXCEPTION] {
        let payload = parse_approval_payload(raw).unwrap();
        let canonical = canonical_approval_payload(&payload).unwrap();
        assert_eq!(
            parse_canonical_approval_payload(
                std::str::from_utf8(&canonical.canonical_bytes).unwrap(),
            )
            .unwrap(),
            payload
        );
    }
}

fn parsed_value(raw: &str) -> Value {
    serde_json::to_value(parse_approval_payload(raw).unwrap()).unwrap()
}

fn parse_value(value: &Value) -> ApprovalDigestPayload {
    parse_approval_payload(&serde_json::to_string(value).unwrap()).unwrap()
}

fn canonical(value: &Value) -> local_agent_terminal_application::CanonicalApprovalPayload {
    canonical_approval_payload(&parse_value(value)).unwrap()
}

fn assert_each_mutation_changes_digest(value: &Value, mutations: &[(&str, Value)]) {
    let baseline = canonical(value).operation_digest;
    for (path, replacement) in mutations {
        let mut changed = value.clone();
        set(&mut changed, path, replacement.clone());
        assert_ne!(canonical(&changed).operation_digest, baseline, "{path}");
    }
}

fn set(value: &mut Value, path: &str, replacement: Value) {
    *value
        .pointer_mut(path)
        .unwrap_or_else(|| panic!("missing fixture path {path}")) = replacement;
}

fn plan_payload() -> PlanApprovalPayloadV1 {
    PlanApprovalPayloadV1 {
        schema: "approval-digest.v1".to_owned(),
        approval_type: "plan".to_owned(),
        task_id: "task-1".to_owned(),
        operation: PlanApprovalOperationV1 {
            plan: PlanApprovalPlanRefV1 {
                id: "plan-1".to_owned(),
                version: 2,
                content_digest: format!("sha256:{}", "1".repeat(64)),
            },
            base_commit: "a".repeat(40),
            allowed_paths: vec![PlanApprovalPathScopeV1 {
                root_capability: "worktree:task-1".to_owned(),
                patterns: vec!["src/**".to_owned()],
            }],
            planned_tool_digests: vec![format!("sha256:{}", "2".repeat(64))],
            verification_profile_digest: format!("sha256:{}", "3".repeat(64)),
            risk_class: "high".to_owned(),
        },
        policy_snapshot_digest: format!("sha256:{}", "4".repeat(64)),
        workspace_version: 9,
        requested_at: "2026-07-23T12:00:00Z".to_owned(),
        expires_at: "2026-07-23T12:15:00Z".to_owned(),
        nonce: "0123456789abcdef0123456789abcdef".to_owned(),
    }
}
