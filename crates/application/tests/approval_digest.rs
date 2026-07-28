use local_agent_terminal_application::{
    build_approval_request, canonical_approval_payload, parse_approval_payload,
    ApprovalDigestPayload, ApprovalId, ToolApprovalPayloadV1,
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
