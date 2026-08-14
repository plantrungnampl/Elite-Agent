#!/usr/bin/env python3
"""Executable self-review for the v4.3 implementation/product-proof baseline."""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SC = ROOT / "schemas"
VAL = ROOT / "validation"
sys.path.insert(0, str(VAL))
from validate_v3 import NOW, LATER, SHA_A, seed  # noqa: E402


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


checks: list[Check] = []


def record(name: str, passed: bool, detail: str) -> None:
    checks.append(Check(name, passed, detail))
    print(("PASS" if passed else "FAIL"), name, "-", detail)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(ch: str) -> str:
    return "sha256:" + ch * 64


def expect_blocked(name: str, action: Callable[[], None], contains: str | tuple[str, ...] = "") -> None:
    try:
        action()
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        needles = (contains,) if isinstance(contains, str) else contains
        ok = not any(needles) or any(n in str(exc) for n in needles)
        record(name, ok, str(exc))
    else:
        record(name, False, "unsafe operation succeeded")


def required_files() -> None:
    names = [
        "sqlite-v7.sql",
        "migrate-v6-to-v7.sql",
        "workflow-transitions.v3.json",
        "workflow-transition-command.v1.schema.json",
        "run-configuration.v1.schema.json",
        "assurance-degradation-receipt.v1.schema.json",
        "orchestration-benchmark-suite.v1.schema.json",
        "orchestration-benchmark-run-receipt.v1.schema.json",
        "orchestration-benchmark-case-result.v1.schema.json",
        "orchestration-benchmark-comparison-report.v1.schema.json",
        "product-traceability.v1.schema.json",
        "product-traceability.v43.json",
    ]
    for name in names:
        record(f"file.schema.{name}", (SC / name).exists(), "present" if (SC / name).exists() else "missing")
    docs = [
        "38-v4.3-implementation-product-proof.md",
        "39-run-configuration-and-assurance.md",
        "40-orchestration-product-proof-benchmark.md",
        "41-v4.3-self-review-report.md",
        "42-v4.2-to-v4.3-migration-contract.md",
        "V4.3-CHANGELOG.md",
    ]
    for name in docs:
        record(f"file.doc.{name}", (ROOT / name).exists(), "present" if (ROOT / name).exists() else "missing")


def validate_protocol() -> None:
    text = (ROOT / "03-agent-protocol.md").read_text(encoding="utf-8")
    schema = load(SC / "agent-protocol.v2.schema.json")
    pattern = re.compile(
        r"<!--\s*protocol-schema:([A-Za-z0-9]+)\s+fixture=([^\s]+)\s*-->\s*```json\s*(\{.*?\})\s*```",
        re.S,
    )
    frames = pattern.findall(text)
    record("protocol.annotated_complete_frames", len(frames) == 13, f"annotated={len(frames)} expected=13")
    valid = 0
    identical = 0
    details: list[str] = []
    for definition, fixture_rel, raw in frames:
        try:
            frame = json.loads(raw)
            fixture = load(ROOT / fixture_rel)
            target = {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                "$ref": f"#/$defs/{definition}",
            }
            errors = list(Draft202012Validator(target).iter_errors(frame))
            if not errors:
                valid += 1
            else:
                details.append(f"{definition}: {errors[0].message}")
            if frame == fixture:
                identical += 1
            else:
                details.append(f"{definition}: fixture differs")
        except Exception as exc:
            details.append(f"{definition}: {exc}")
    record("protocol.frames_schema_valid", valid == 13, f"valid={valid}/13" + (f"; {details[:3]}" if details else ""))
    record("protocol.frames_fixture_identical", identical == 13, f"identical={identical}/13")
    record("protocol.v2_initialize_only", '"protocolVersions": ["1.0"]' not in text and '"2.0"' in text, "v1 initialize removed; v2 declared")
    record("protocol.connection_binding", "connectionBindingDigest" in text, "connection binding is normative")
    cognitive_ok = "cognitive-memory.v1" in text and "cognitive-memory.v4.schema.json" in text and "evolve independently" in text
    record("protocol.cognitive_version_separation", cognitive_ok, "extension capability and payload schema versions are separate")


def validate_new_schemas() -> None:
    pairs = [
        ("workflow-transition-command.v1.schema.json", "examples-v43/workflow-transition-command.example.json"),
        ("run-configuration.v1.schema.json", "examples-v43/run-configuration.example.json"),
        ("assurance-degradation-receipt.v1.schema.json", "examples-v43/assurance-degradation-receipt.example.json"),
        ("orchestration-benchmark-suite.v1.schema.json", "examples-v43/orchestration-benchmark-suite.example.json"),
        ("orchestration-benchmark-run-receipt.v1.schema.json", "examples-v43/orchestration-benchmark-run-receipt.example.json"),
        ("orchestration-benchmark-case-result.v1.schema.json", "examples-v43/orchestration-benchmark-case-result.example.json"),
        ("orchestration-benchmark-comparison-report.v1.schema.json", "examples-v43/orchestration-benchmark-comparison-report.example.json"),
        ("product-traceability.v1.schema.json", "product-traceability.v43.json"),
    ]
    for schema_name, example_name in pairs:
        schema = load(SC / schema_name)
        example = load(SC / example_name)
        try:
            Draft202012Validator.check_schema(schema)
            errors = list(Draft202012Validator(schema).iter_errors(example))
        except Exception as exc:
            record(f"schema.{schema_name}", False, str(exc))
        else:
            record(f"schema.{schema_name}", not errors, "schema compiles and example validates" if not errors else errors[0].message)

    run_schema = load(SC / "run-configuration.v1.schema.json")
    run_example = load(SC / "examples-v43/run-configuration.example.json")
    leaked = dict(run_example)
    leaked["apiKey"] = "forbidden"
    record(
        "schema.run_configuration_rejects_credentials",
        bool(list(Draft202012Validator(run_schema).iter_errors(leaked))),
        "credential-bearing instance rejected",
    )
    bad_fallback = json.loads(json.dumps(run_example))
    bad_fallback["fallbackPolicy"]["userApprovalRequired"] = False
    record(
        "schema.fallback_requires_approval",
        bool(list(Draft202012Validator(run_schema).iter_errors(bad_fallback))),
        "explicit fallback without approval rejected",
    )
    assurance_schema = load(SC / "assurance-degradation-receipt.v1.schema.json")
    assurance = load(SC / "examples-v43/assurance-degradation-receipt.example.json")
    assurance.pop("actorBindingId")
    record(
        "schema.degraded_continue_requires_actor",
        bool(list(Draft202012Validator(assurance_schema).iter_errors(assurance))),
        "continue_degraded without actor proof rejected",
    )


def workflow_contract() -> tuple[dict, dict[str, dict]]:
    wf = load(SC / "workflow-transitions.v3.json")
    rules = list(wf["phaseTransitions"]) + [wf["workspaceDirtyTransition"]] + list(wf["globalPhaseTransitions"])
    by_id = {r["ruleId"]: r for r in rules}
    record("workflow.rule_ids_unique", len(by_id) == len(rules), f"rules={len(rules)} unique={len(by_id)}")
    phases = set(wf["phases"])
    bad_endpoints = []
    for r in rules:
        sources = r.get("fromPhases", [r.get("from")])
        if any(s not in phases for s in sources) or r["to"] not in phases:
            bad_endpoints.append(r["ruleId"])
        if set(r.get("effects", [])) != set(r.get("requiredEffectKinds", [])):
            bad_endpoints.append(r["ruleId"] + ":effect-mismatch")
    record("workflow.rules_well_formed", not bad_endpoints, "all endpoints and effect requirements align" if not bad_endpoints else str(bad_endpoints))
    p8, p9, p15 = by_id["WF-P008"], by_id["WF-P009"], by_id["WF-P015"]
    record("workflow.standard_severe_route", set(p8["allowedProfiles"]) == {"Standard", "HighAssurance", "ReadOnlyResearch"} and p8["to"] == "CrossReview", str(p8["allowedProfiles"]))
    record("workflow.quick_severe_route", p9["allowedProfiles"] == ["Quick"] and p9["to"] == "PrePlanVerification", str(p9["allowedProfiles"]))
    record("workflow.plan_exact_guard", "plan_approval_receipt" in p15["requiredEvidenceKinds"], str(p15["requiredEvidenceKinds"]))
    record("workflow.plan_effects_complete", set(p15["requiredEffectKinds"]) == {"persist_approved_plan_version", "allocate_executor_lease"}, str(p15["requiredEffectKinds"]))
    escalations = {(e["from"], e["to"]) for e in wf["profileEscalations"]}
    record("workflow.monotonic_escalation", escalations == {("Quick", "Standard"), ("Quick", "HighAssurance"), ("Standard", "HighAssurance")}, str(sorted(escalations)))
    record("workflow.no_profile_downgrade", wf.get("profileDowngradeWithinTaskForbidden") is True, "in-task downgrade forbidden")
    record("workflow.read_only_child_boundary", "child_task" in wf.get("readOnlyResearchWriteConversion", ""), wf.get("readOnlyResearchWriteConversion", ""))
    return wf, by_id


def object_sql(con: sqlite3.Connection) -> dict[tuple[str, str], str]:
    return {
        (t, n): re.sub(r"\s+", "", sql or "").lower()
        for t, n, sql in con.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
    }


def clean_install(seed_data: bool = False) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v7.sql").read_text(encoding="utf-8"))
    if seed_data:
        seed(con)
    return con


def validate_install_and_migration() -> None:
    clean = clean_install()
    migrated = sqlite3.connect(":memory:")
    migrated.execute("PRAGMA foreign_keys=ON")
    migrated.executescript((SC / "sqlite-v6.sql").read_text(encoding="utf-8"))
    migrated.executescript((SC / "migrate-v6-to-v7.sql").read_text(encoding="utf-8"))
    a, b = object_sql(clean), object_sql(migrated)
    record("sqlite.v7_integrity", clean.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "clean integrity_check=ok")
    record("sqlite.v6_to_v7_integrity", migrated.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "migrated integrity_check=ok")
    record("sqlite.v7_foreign_keys", not clean.execute("PRAGMA foreign_key_check").fetchall() and not migrated.execute("PRAGMA foreign_key_check").fetchall(), "no foreign-key violations")
    record("sqlite.clean_migration_parity", a == b and len(a) == 481, f"clean={len(a)} migrated={len(b)} identical={a == b}")
    clean.close()
    migrated.close()


def add_artifact(con: sqlite3.Connection, artifact_id: str, content_digest: str, artifact_type: str = "workflow_transition_command") -> None:
    con.execute(
        """INSERT INTO artifacts(id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,supersedes,verification_state)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (artifact_id, "t1", "p1", artifact_type, artifact_id, content_digest, artifact_id, 1, "application/json", "available", "core", "core", NOW, None, "hash_verified"),
    )


def workflow_db(profile: str = "Quick", outcome: str = "WorkspaceChange") -> sqlite3.Connection:
    con = clean_install(seed_data=True)
    con.execute(
        """INSERT INTO task_workflow_authority(task_id,workflow_profile,outcome_mode,phase,selected_by_kind,selected_by_actor_binding_id,selection_policy_digest,created_at,updated_at,completed_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        ("t1", profile, outcome, "Intake", "core", None, digest("1"), NOW, NOW, None),
    )
    return con


def prepare_event(con: sqlite3.Connection, rule: dict, event_id: str, bind_guards: bool = True, bind_effects: bool = True, special_guards: dict[str, tuple] | None = None) -> None:
    phase, profile, outcome, version = con.execute(
        "SELECT phase,workflow_profile,outcome_mode,stream_version FROM task_workflow_authority WHERE task_id='t1'"
    ).fetchone()
    artifact_id = f"cmd-{event_id}"
    add_artifact(con, artifact_id, digest("2"))
    con.execute(
        """INSERT INTO workflow_transition_events(id,task_id,rule_id,expected_stream_version,from_phase,event_type,to_phase,workflow_profile,outcome_mode,transition_command_artifact_id,guard_set_digest,effect_set_digest,core_actor_digest,reducer_version,status,prepared_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (event_id, "t1", rule["ruleId"], version, phase, rule["event"], rule["to"], profile, outcome, artifact_id, digest("3"), digest("4"), digest("5"), "workflow-reducer-test-1", "prepared", NOW),
    )
    if bind_guards:
        for kind in rule.get("requiredEvidenceKinds", []):
            if special_guards and kind in special_guards:
                values = special_guards[kind]
                con.execute(
                    """INSERT INTO workflow_transition_guard_bindings(transition_event_id,evidence_kind,evidence_ref,subject_digest,evidence_digest,artifact_id,approval_receipt_id,acceptance_receipt_id,verification_receipt_id,ref_promotion_receipt_id)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (event_id, kind, *values),
                )
            else:
                con.execute(
                    "INSERT INTO workflow_transition_guard_bindings(transition_event_id,evidence_kind,evidence_ref,subject_digest,evidence_digest) VALUES (?,?,?,?,?)",
                    (event_id, kind, f"{event_id}:{kind}", digest("6"), digest("7")),
                )
    if bind_effects:
        for kind in rule.get("requiredEffectKinds", []):
            con.execute(
                "INSERT INTO workflow_transition_effect_bindings(transition_event_id,effect_kind,effect_ref,effect_digest) VALUES (?,?,?,?)",
                (event_id, kind, f"{event_id}:{kind}", digest("8")),
            )


def accept_and_project(con: sqlite3.Connection, rule: dict, event_id: str) -> None:
    version = con.execute("SELECT stream_version FROM task_workflow_authority WHERE task_id='t1'").fetchone()[0]
    con.execute("UPDATE workflow_transition_events SET status='accepted',accepted_at=? WHERE id=?", (LATER, event_id))
    completed_at = "2026-08-07T10:00:00Z" if rule["to"] in {"Completed", "Cancelled", "Failed"} else None
    con.execute(
        """UPDATE task_workflow_authority
        SET phase=?,stream_version=stream_version+1,last_transition_event_id=?,updated_at=?,completed_at=?
        WHERE task_id='t1'""",
        (rule["to"], event_id, f"2026-08-07T09:{version + 1:02d}:00Z", completed_at),
    )


def execute_rule(con: sqlite3.Connection, rules: dict[str, dict], rule_id: str, event_id: str, special_guards: dict[str, tuple] | None = None) -> None:
    rule = rules[rule_id]
    prepare_event(con, rule, event_id, special_guards=special_guards)
    accept_and_project(con, rule, event_id)


def advance_to_final_objection(con: sqlite3.Connection, rules: dict[str, dict], profile: str) -> None:
    route = ["WF-P001"]
    route += ["WF-P003"] if profile == "Quick" else ["WF-P002", "WF-P004", "WF-P005"]
    route += ["WF-P006", "WF-P007"]
    for index, rule_id in enumerate(route, 1):
        execute_rule(con, rules, rule_id, f"{profile.lower()}-{index}")


def advance_to_plan_approval(con: sqlite3.Connection, rules: dict[str, dict], profile: str = "Standard") -> None:
    advance_to_final_objection(con, rules, profile)
    execute_rule(con, rules, "WF-P013", f"{profile.lower()}-plan-request")


def create_exact_plan_approval(con: sqlite3.Connection) -> tuple[str, str, str]:
    operation_digest = digest("a")
    actor_digest = digest("b")
    receipt_digest = digest("c")
    add_artifact(con, "plan-request-artifact", operation_digest, "approval_request")
    add_artifact(con, "plan-proof-artifact", digest("d"), "credential_evidence")
    con.execute(
        "INSERT INTO actor_bindings VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("actor-plan", "user", "user-1", "session-plan", "local_authenticated_session", actor_digest, NOW, LATER, None, 1),
    )
    con.execute(
        "INSERT INTO credential_challenges VALUES (?,?,?,?,?,?,?,?)",
        ("challenge-plan", "actor-plan", "plan.approval", operation_digest, "plan-challenge-nonce-0000000001", digest("e"), NOW, LATER),
    )
    con.execute(
        "INSERT INTO credential_challenge_receipts VALUES (?,?,?,?,?,?,?)",
        ("challenge-receipt-plan", "challenge-plan", "actor-plan", "local_authenticated_session", "plan-proof-artifact", NOW, digest("f")),
    )
    con.execute(
        """INSERT INTO operation_intents(id,task_id,run_id,operation_kind,idempotency_class,idempotency_key,canonical_request_artifact_id,operation_digest,actor_binding_digest,status,current_attempt_no,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("plan-intent", "t1", "r1", "plan.approval", "queryable", "plan-intent-key", "plan-request-artifact", operation_digest, actor_digest, "pending", 0, NOW, NOW),
    )
    con.execute(
        "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("approval-plan", "t1", "plan-intent", "plan", "approval-digest.v2", operation_digest, actor_digest, "plan-approval-nonce-0000000001", "pending", NOW, None, LATER, "plan-request-artifact", None),
    )
    con.execute(
        "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("approval-receipt-plan", "approval-plan", "t1", "plan-intent", operation_digest, actor_digest, "plan-approval-nonce-0000000001", "granted", "plan-proof-artifact", NOW, receipt_digest),
    )
    con.execute(
        "INSERT INTO approval_actor_proof_bindings VALUES (?,?,?,?)",
        ("approval-receipt-plan", "actor-plan", "challenge-receipt-plan", NOW),
    )
    con.execute("UPDATE approvals SET status='granted',resolved_at=? WHERE id='approval-plan'", (NOW,))
    return operation_digest, receipt_digest, "approval-receipt-plan"


def validate_workflow_sql(rules: dict[str, dict]) -> None:
    con = workflow_db()
    expect_blocked(
        "sqlite.raw_phase_update_rejected",
        lambda: con.execute("UPDATE task_workflow_authority SET phase='PrePlanVerification',updated_at='2026-08-07T09:00:00Z' WHERE task_id='t1'"),
        "matching accepted transition event",
    )
    con.close()

    con = workflow_db()
    prepare_event(con, rules["WF-P001"], "valid-p001")
    accept_and_project(con, rules["WF-P001"], "valid-p001")
    row = con.execute("SELECT phase,stream_version,last_transition_event_id FROM task_workflow_authority WHERE task_id='t1'").fetchone()
    record("sqlite.valid_event_projection", row == ("ContextBuild", 1, "valid-p001"), str(row))
    expect_blocked(
        "sqlite.stale_event_rejected",
        lambda: con.execute(
            """INSERT INTO workflow_transition_events(id,task_id,rule_id,expected_stream_version,from_phase,event_type,to_phase,workflow_profile,outcome_mode,transition_command_artifact_id,guard_set_digest,effect_set_digest,core_actor_digest,reducer_version,status,prepared_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("stale", "t1", "WF-P001", 0, "Intake", "task.validated", "ContextBuild", "Quick", "WorkspaceChange", "cmd-valid-p001", digest("1"), digest("2"), digest("3"), "test", "prepared", NOW),
        ),
        ("current authority", "UNIQUE"),
    )
    con.close()

    con = workflow_db()
    prepare_event(con, rules["WF-P001"], "missing-effect", bind_effects=False)
    expect_blocked(
        "sqlite.missing_required_effect_rejected",
        lambda: con.execute("UPDATE workflow_transition_events SET status='accepted',accepted_at=? WHERE id='missing-effect'", (NOW,)),
        "missing required effects",
    )
    con.close()

    con = workflow_db()
    prepare_event(con, rules["WF-P001"], "rejected-1", bind_guards=False, bind_effects=False)
    con.execute("UPDATE workflow_transition_events SET status='rejected',rejected_at=? WHERE id='rejected-1'", (NOW,))
    try:
        prepare_event(con, rules["WF-P001"], "retry-2", bind_guards=False, bind_effects=False)
    except Exception as exc:
        record("sqlite.rejected_command_retry", False, str(exc))
    else:
        record("sqlite.rejected_command_retry", True, "new command ID may retry the unchanged stream version")
    con.close()

    con = workflow_db("Quick")
    advance_to_final_objection(con, rules, "Quick")
    wrong = rules["WF-P008"]
    expect_blocked(
        "sqlite.quick_crossreview_route_rejected",
        lambda: prepare_event(con, wrong, "quick-wrong-route", bind_guards=False, bind_effects=False),
        "profile route",
    )
    con.close()

    con = workflow_db("Standard")
    advance_to_final_objection(con, rules, "Standard")
    wrong = rules["WF-P009"]
    expect_blocked(
        "sqlite.standard_quick_route_rejected",
        lambda: prepare_event(con, wrong, "standard-wrong-route", bind_guards=False, bind_effects=False),
        "profile route",
    )
    con.close()

    con = workflow_db("Standard")
    advance_to_plan_approval(con, rules)
    prepare_event(con, rules["WF-P015"], "plan-without-receipt", bind_guards=False, bind_effects=True)
    expect_blocked(
        "sqlite.plan_without_receipt_rejected",
        lambda: con.execute("UPDATE workflow_transition_events SET status='accepted',accepted_at=? WHERE id='plan-without-receipt'", (NOW,)),
        "missing required guard evidence",
    )
    con.close()

    con = workflow_db("Standard")
    advance_to_plan_approval(con, rules)
    operation_digest, receipt_digest, receipt_id = create_exact_plan_approval(con)
    special = {
        "plan_approval_receipt": (
            receipt_id,
            operation_digest,
            receipt_digest,
            None,
            receipt_id,
            None,
            None,
            None,
        )
    }
    try:
        execute_rule(con, rules, "WF-P015", "plan-valid", special)
    except Exception as exc:
        record("sqlite.exact_plan_transition", False, str(exc))
    else:
        row = con.execute("SELECT phase,stream_version FROM task_workflow_authority WHERE task_id='t1'").fetchone()
        record("sqlite.exact_plan_transition", row == ("Implementation", 8), str(row))
    con.close()


def validate_profile_and_assurance_sql() -> None:
    con = workflow_db("Quick")
    add_artifact(con, "profile-reason", digest("d"), "receipt")
    try:
        con.execute(
            """INSERT INTO workflow_profile_revisions(id,task_id,revision_no,expected_stream_version,from_profile,to_profile,reason_artifact_id,policy_digest,decided_by_kind,actor_binding_id,created_at,receipt_digest)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("profile-revision-2", "t1", 2, 0, "Quick", "Standard", "profile-reason", digest("e"), "core", None, NOW, digest("f")),
        )
        con.execute(
            """UPDATE task_workflow_authority SET workflow_profile='Standard',stream_version=1,profile_revision=2,last_profile_revision_id='profile-revision-2',updated_at='2026-08-07T09:00:00Z' WHERE task_id='t1'"""
        )
    except Exception as exc:
        record("sqlite.profile_escalation_valid", False, str(exc))
    else:
        row = con.execute("SELECT workflow_profile,stream_version,profile_revision FROM task_workflow_authority WHERE task_id='t1'").fetchone()
        record("sqlite.profile_escalation_valid", row == ("Standard", 1, 2), str(row))
    expect_blocked(
        "sqlite.profile_downgrade_rejected",
        lambda: con.execute("UPDATE task_workflow_authority SET workflow_profile='Quick',stream_version=2,profile_revision=3,updated_at='2026-08-07T09:01:00Z' WHERE task_id='t1'"),
        "matching monotonic escalation receipt",
    )
    con.close()

    con = workflow_db("Standard")
    add_artifact(con, "bad-profile-reason", digest("0"), "receipt")
    expect_blocked(
        "sqlite.profile_revision_downgrade_shape_rejected",
        lambda: con.execute(
            """INSERT INTO workflow_profile_revisions(id,task_id,revision_no,expected_stream_version,from_profile,to_profile,reason_artifact_id,policy_digest,decided_by_kind,actor_binding_id,created_at,receipt_digest)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("bad-revision", "t1", 2, 0, "Standard", "Quick", "bad-profile-reason", digest("1"), "core", None, NOW, digest("2")),
        ),
        "CHECK constraint",
    )
    con.close()

    con = clean_install(seed_data=True)
    expect_blocked(
        "sqlite.readonly_write_outcome_rejected",
        lambda: con.execute(
            """INSERT INTO task_workflow_authority(task_id,workflow_profile,outcome_mode,phase,selected_by_kind,selection_policy_digest,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)""",
            ("t1", "ReadOnlyResearch", "WorkspaceChange", "Intake", "core", digest("1"), NOW, NOW),
        ),
        "CHECK constraint",
    )
    con.close()

    con = clean_install(seed_data=True)
    try:
        con.execute(
            "INSERT INTO run_configuration_bindings VALUES (?,?,?,?,?,?,?,?,?)",
            ("r1", "a1", SHA_A, "provider-connection-1", "adapter-1", "model-1", "group-1", digest("3"), NOW),
        )
    except Exception as exc:
        record("sqlite.run_configuration_exact_binding", False, str(exc))
    else:
        record("sqlite.run_configuration_exact_binding", True, "run binds the exact configured artifact and digest")
    expect_blocked(
        "sqlite.run_configuration_immutable",
        lambda: con.execute("UPDATE run_configuration_bindings SET resolved_model_id='model-2' WHERE run_id='r1'"),
        "immutable",
    )
    con.close()

    con = clean_install(seed_data=True)
    actor_digest = digest("4")
    receipt_digest = digest("5")
    con.execute("INSERT INTO actor_bindings VALUES (?,?,?,?,?,?,?,?,?,?)", ("actor-degraded", "user", "u1", "session-d", "local_authenticated_session", actor_digest, NOW, LATER, None, 1))
    add_artifact(con, "degradation-artifact", receipt_digest, "receipt")
    try:
        con.execute(
            "INSERT INTO assurance_degradation_receipts VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("degradation-1", "t1", "HighAssurance", "provider_unavailable", digest("6"), "continue_degraded", "actor-degraded", "degradation-artifact", NOW, receipt_digest),
        )
    except Exception as exc:
        record("sqlite.degradation_with_actor_valid", False, str(exc))
    else:
        record("sqlite.degradation_with_actor_valid", True, "continue_degraded has exact task-scoped artifact and actor proof")
    expect_blocked(
        "sqlite.degradation_receipt_immutable",
        lambda: con.execute("UPDATE assurance_degradation_receipts SET decision='pause' WHERE id='degradation-1'"),
        "immutable",
    )
    con.close()

    con = clean_install(seed_data=True)
    add_artifact(con, "degradation-no-actor", digest("7"), "receipt")
    expect_blocked(
        "sqlite.degradation_without_actor_rejected",
        lambda: con.execute(
            "INSERT INTO assurance_degradation_receipts VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("degradation-bad", "t1", "HighAssurance", "provider_unavailable", digest("8"), "continue_degraded", None, "degradation-no-actor", NOW, digest("7")),
        ),
        "requires explicit actor proof",
    )
    con.close()


def validate_product_proof() -> None:
    suite = load(SC / "examples-v43/orchestration-benchmark-suite.example.json")
    expected_arms = {
        "single_direct", "single_with_retrieval_and_verification", "same_model_multi_sample",
        "quick_profile", "standard_cross_review", "high_assurance", "heterogeneous_models",
    }
    expected_metrics = {
        "accepted_outcome", "defect_escape_count", "first_pass_test_success", "unsupported_claim_count",
        "requirement_omission_count", "human_correction_minutes", "time_to_accepted_ms", "input_tokens",
        "output_tokens", "tool_calls", "cost_microunits", "approval_interruptions", "task_abandoned",
        "reviewer_unique_findings",
    }
    record("benchmark.all_required_arms", set(suite["arms"]) == expected_arms, str(suite["arms"]))
    record("benchmark.strong_single_baseline", "single_with_retrieval_and_verification" in suite["arms"], "strong single-agent baseline included")
    record("benchmark.equal_budget_dimensions", set(suite["equalBudgetPolicy"]["controlledDimensions"]) >= {"input_tokens", "output_tokens", "tool_calls", "wall_time_ms", "cost_microunits", "repository_revision", "acceptance_rules", "tool_policy", "evaluator_configuration"}, str(suite["equalBudgetPolicy"]["controlledDimensions"]))
    record("benchmark.user_effort_metrics", set(suite["requiredMetrics"]) == expected_metrics, f"metrics={len(suite['requiredMetrics'])}")
    record("benchmark.minimum_repetitions", suite["replicationCount"] >= 3, str(suite["replicationCount"]))
    report = load(SC / "examples-v43/orchestration-benchmark-comparison-report.example.json")
    record("benchmark.bootstrap_no_false_claim", report["decision"] == {"status": "inconclusive", "qualityClaimAllowed": False, "rationale": report["decision"]["rationale"]}, str(report["decision"]))
    doc = (ROOT / "40-orchestration-product-proof-benchmark.md").read_text(encoding="utf-8")
    order = [doc.find(x) for x in ["single_direct", "single_with_retrieval_and_verification", "same_model_multi_sample", "quick_profile", "standard_cross_review", "high_assurance", "heterogeneous_models"]]
    record("benchmark.doc_all_arms", all(i >= 0 for i in order), str(order))


def validate_traceability_and_docs() -> None:
    trace = load(SC / "product-traceability.v43.json")
    ids = [r["requirementId"] for r in trace["requirements"]]
    expected = {f"FR-{i:03d}" for i in range(1, 38)} | {f"NFR-{i:03d}" for i in range(1, 15)}
    record("traceability.full_requirement_coverage", set(ids) == expected and len(ids) == len(set(ids)) == 51, f"covered={len(set(ids))}/51 rows={len(ids)}")
    missing: list[str] = []
    for req in trace["requirements"]:
        for rel in req["designAnchors"] + req["machineContracts"] + req["validationAnchors"]:
            if not (ROOT / rel).exists():
                missing.append(f"{req['requirementId']}:{rel}")
    record("traceability.anchors_resolve", not missing, "all traceability file anchors resolve" if not missing else str(missing[:10]))
    proof_statuses = ("contract_proven", "partially_proven", "runtime_unproven", "product_unproven")
    proof_counts = {status: sum(r["proofStatus"] == status for r in trace["requirements"]) for status in proof_statuses}
    record("traceability.proof_boundaries_explicit", proof_counts["runtime_unproven"] > 0 and proof_counts["product_unproven"] > 0, str(proof_counts))

    readme = (ROOT / "00-README.md").read_text(encoding="utf-8")
    record("docs.readme_v43_authority", "Design Baseline v4.3" in readme and "sqlite-v7.sql" in readme and "workflow-transitions.v3.json" in readme, "README selects v4.3 authority")
    roadmap = (ROOT / "11-mvp-roadmap.md").read_text(encoding="utf-8")
    positions = [roadmap.find(f"S{i}") for i in range(7)]
    record("docs.roadmap_s0_s6_order", all(x >= 0 for x in positions) and positions == sorted(positions), str(positions))
    roadmap_lower = roadmap.lower()
    record("docs.real_slice_before_memory", roadmap_lower.find("real read-only") >= 0 and roadmap_lower.find("real read-only") < roadmap_lower.find("memory and learning"), "real product slice precedes broad memory")
    record("docs.fake_agents_not_product_gate", "Fake agents" in roadmap and "cannot" in roadmap, "fake agents excluded from real-runtime gate")

    marker = re.compile(r"^\s*(?:[-*]\s*)?(?:TODO|TBD|FIXME|XXX|PLACEHOLDER)(?:\s*[:\-]|\s*$)", re.I)
    offenders = []
    for path in [ROOT / f for f in ["38-v4.3-implementation-product-proof.md", "39-run-configuration-and-assurance.md", "40-orchestration-product-proof-benchmark.md", "41-v4.3-self-review-report.md", "42-v4.2-to-v4.3-migration-contract.md", "V4.3-CHANGELOG.md"]]:
        if any(marker.search(line) for line in path.read_text(encoding="utf-8").splitlines()):
            offenders.append(path.name)
    record("docs.v43_no_placeholders", not offenders, "no active placeholder markers" if not offenders else str(offenders))


def write_report() -> None:
    payload = {"baseline": "v4.3", "checks": [asdict(c) for c in checks]}
    (VAL / "v43-implementation-product-proof-results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# v4.3 Implementation and Product-Proof Validation Results",
        "",
        "Generated by `python validation/validate_v43_implementation_product_proof.py`.",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for check in checks:
        detail = check.detail.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{check.name}` | {'PASS' if check.passed else 'FAIL'} | {detail} |")
    passed = sum(c.passed for c in checks)
    lines.extend(["", f"**v4.3 checks:** {passed}/{len(checks)} passed.", ""])
    (VAL / "V4.3-IMPLEMENTATION-PRODUCT-PROOF-RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    required_files()
    validate_protocol()
    validate_new_schemas()
    _, rules = workflow_contract()
    validate_install_and_migration()
    validate_workflow_sql(rules)
    validate_profile_and_assurance_sql()
    validate_product_proof()
    validate_traceability_and_docs()
    write_report()
    passed = sum(c.passed for c in checks)
    print(f"\n{passed}/{len(checks)} v4.3 implementation/product-proof checks passed")
    return 0 if all(c.passed for c in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
