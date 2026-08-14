#!/usr/bin/env python3
"""Executable structural and negative validation for design package v3.2 core regression."""
from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
OID_A = "a" * 40
NOW = "2026-08-04T08:00:00Z"
LATER = "2026-08-04T09:00:00Z"


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


checks: list[Check] = []


def record(name: str, passed: bool, detail: str) -> None:
    checks.append(Check(name, passed, detail))
    print(("PASS" if passed else "FAIL"), name, "-", detail)


def expect_blocked(name: str, fn: Callable[[], None], contains: str | None = None) -> None:
    try:
        fn()
    except sqlite3.IntegrityError as exc:
        ok = contains is None or contains in str(exc)
        record(name, ok, str(exc))
    else:
        record(name, False, "unsafe operation succeeded")


def load_json(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def seed(con: sqlite3.Connection) -> None:
    con.execute(
        "INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?)",
        ("p1", "Project 1", "C:/repo1", SHA_A, NOW, NOW, "policy", "application_data", "C:/data/p1"),
    )
    con.execute(
        "INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?)",
        ("p2", "Project 2", "C:/repo2", SHA_B, NOW, NOW, "policy", "application_data", "C:/data/p2"),
    )
    task = """INSERT INTO tasks(
      id,project_id,title,objective,phase,condition,operation_state,risk_level,
      base_branch,base_commit,created_at,updated_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"""
    con.execute(task, ("t1", "p1", "Task 1", "Objective", "Intake", "Active", "None", "medium", "main", OID_A, NOW, NOW))
    con.execute(task, ("t2", "p2", "Task 2", "Objective", "Intake", "Active", "None", "medium", "main", OID_A, NOW, NOW))

    art = """INSERT INTO artifacts(
      id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,
      size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,
      supersedes,verification_state
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    rows = [
        ("a1", "t1", "p1", "context", "a1", SHA_A, "a1", 1, "application/json", "available", "core", "core", NOW, None, "hash_verified"),
        ("a2", "t2", "p2", "context", "a2", SHA_B, "a2", 1, "application/json", "available", "core", "core", NOW, None, "hash_verified"),
        ("cred", "t1", "p1", "credential_evidence", "cred", SHA_A, "cred", 1, "application/json", "available", "core", "core", NOW, None, "tool_verified"),
        ("receipt1", "t1", "p1", "receipt", "receipt1", SHA_A, "receipt1", 1, "application/json", "available", "core", "core", NOW, None, "tool_verified"),
        ("receipt2", "t1", "p1", "receipt", "receipt2", SHA_B, "receipt2", 1, "application/json", "available", "core", "core", NOW, None, "tool_verified"),
        ("response", "t1", "p1", "protocol_response", "response", SHA_A, "response", 1, "application/json", "available", "core", "core", NOW, None, "hash_verified"),
    ]
    con.executemany(art, rows)

    con.execute(
        "INSERT INTO agent_descriptors VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("core-agent", "Core", "inproc", "core_adapter", "{}", SHA_A, None, None, 1, "healthy", NOW),
    )
    cp = """INSERT INTO context_packages(
      id,task_id,agent_id,role,objective,manifest_artifact_id,effective_content_artifact_id,
      content_hash,policy_snapshot_digest,prompt_template_version,retrieval_pipeline_version,created_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"""
    con.execute(cp, ("cp1", "t1", "core-agent", "implementer", "Objective", "a1", "a1", SHA_A, SHA_A, "1", "1", NOW))
    con.execute(cp, ("cp2", "t2", "core-agent", "implementer", "Objective", "a2", "a2", SHA_B, SHA_B, "1", "1", NOW))

    run = """INSERT INTO agent_runs(
      id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,
      connection_binding_digest,run_config_artifact_id
    ) VALUES (?,?,?,?,?,?,?,?,?,?)"""
    con.execute(run, ("r1", "t1", "core-agent", "implementer", "Implementation", "running", "cp1", "run-key-1", SHA_A, "a1"))
    con.execute(run, ("r2", "t2", "core-agent", "implementer", "Implementation", "running", "cp2", "run-key-2", SHA_B, "a2"))

    pd = """INSERT INTO policy_decisions(
      id,task_id,actor_json,actor_binding_digest,action,resource_json,resource_digest,
      purpose,workflow_phase,effect,matched_rules_json,policy_snapshot_digest,
      operation_digest,created_at,expires_at,approval_id
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    con.execute(pd, ("pd1", "t1", "{}", SHA_A, "tool.execute", "{}", SHA_A, "test", "Implementation", "allow", "[]", SHA_A, SHA_A, NOW, LATER, None))
    con.execute(pd, ("pd2", "t2", "{}", SHA_B, "tool.execute", "{}", SHA_B, "test", "Implementation", "allow", "[]", SHA_B, SHA_B, NOW, LATER, None))

    intent = """INSERT INTO operation_intents(
      id,task_id,run_id,operation_kind,idempotency_class,idempotency_key,
      canonical_request_artifact_id,operation_digest,actor_binding_digest,status,
      current_attempt_no,created_at,updated_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    con.execute(intent, ("i1", "t1", "r1", "tool.execute", "queryable", "intent-key-1", "a1", SHA_A, SHA_A, "pending", 0, NOW, NOW))
    con.execute(intent, ("i2", "t2", "r2", "tool.execute", "queryable", "intent-key-2", "a2", SHA_B, SHA_B, "pending", 0, NOW, NOW))


def validate_sqlite() -> None:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SCHEMAS / "sqlite-v2.sql").read_text(encoding="utf-8"))
    record("sqlite.clean_install", con.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "schema created and integrity_check=ok")
    seed(con)

    con.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", ("e1", "task:t1", 1, "TaskCreated", 1, "core", "core", "core_observed", "{}", "{}", None, "c1", NOW))
    expect_blocked("sqlite.events_update_forbidden", lambda: con.execute("UPDATE events SET payload_json='{}' WHERE event_id='e1'"), "append-only")
    expect_blocked("sqlite.events_delete_forbidden", lambda: con.execute("DELETE FROM events WHERE event_id='e1'"), "append-only")

    con.execute("UPDATE tasks SET fencing_epoch=1,row_version=1 WHERE id='t1'")
    expect_blocked("sqlite.fencing_epoch_cannot_decrease", lambda: con.execute("UPDATE tasks SET fencing_epoch=0,row_version=2 WHERE id='t1'"), "cannot decrease")
    expect_blocked(
        "sqlite.task_update_requires_row_version_increment",
        lambda: con.execute("UPDATE tasks SET phase='ContextBuild' WHERE id='t1'"),
        "row version",
    )

    con.execute("INSERT INTO executor_leases VALUES (?,?,?,?,?,?,?,?)", ("lease1", "t1", "r1", 1, "active", NOW, LATER, None))
    expect_blocked("sqlite.lease_holder_cannot_change", lambda: con.execute("UPDATE executor_leases SET holder_run_id='r2' WHERE id='lease1'"), "immutable")

    expect_blocked(
        "sqlite.external_agent_cannot_enable_without_attestation",
        lambda: con.execute("INSERT INTO agent_descriptors VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("ext", "External", "stdio", "isolated_worker", "{}", SHA_A, SHA_A, None, 1, "unknown", NOW)),
        "attestation",
    )

    expect_blocked(
        "sqlite.agent_run_cross_task_context_rejected",
        lambda: con.execute(
            "INSERT INTO agent_runs(id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("r-bad", "t1", "core-agent", "implementer", "Implementation", "running", "cp2", "run-key-bad", SHA_A, "a2"),
        ),
        "scope",
    )
    expect_blocked(
        "sqlite.agent_run_role_is_immutable",
        lambda: con.execute("UPDATE agent_runs SET role='reviewer' WHERE id='r1'"),
        "immutable",
    )

    con.execute("UPDATE agent_runs SET status='succeeded',completed_at=? WHERE id='r1'", (NOW,))
    expect_blocked("sqlite.run_terminal_irreversible", lambda: con.execute("UPDATE agent_runs SET status='running' WHERE id='r1'"), "irreversible")

    con.execute(
        "INSERT INTO operation_attempts(id,operation_intent_id,task_id,attempt_no,owner_run_id,fencing_token,policy_decision_id,approval_id,status,started_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("at1", "i1", "t1", 1, "r1", 1, "pd1", None, "started", NOW),
    )
    con.execute("UPDATE operation_intents SET current_attempt_no=1,status='started',updated_at=? WHERE id='i1'", (NOW,))
    con.execute("UPDATE operation_attempts SET status='succeeded',terminal_at=?,receipt_artifact_id='receipt1' WHERE id='at1'", (NOW,))
    expect_blocked("sqlite.attempt_evidence_set_once", lambda: con.execute("UPDATE operation_attempts SET receipt_artifact_id='receipt2' WHERE id='at1'"), "set-once")
    expect_blocked("sqlite.attempt_evidence_cannot_be_cleared", lambda: con.execute("UPDATE operation_attempts SET receipt_artifact_id=NULL WHERE id='at1'"))
    con.execute("UPDATE operation_intents SET status='succeeded',updated_at=? WHERE id='i1'", (NOW,))
    expect_blocked("sqlite.intent_terminal_irreversible", lambda: con.execute("UPDATE operation_intents SET status='pending' WHERE id='i1'"), "irreversible")

    expect_blocked(
        "sqlite.cross_task_authority_splicing_rejected",
        lambda: con.execute(
            "INSERT INTO tool_executions(id,task_id,run_id,request_id,tool_name,arguments_artifact_id,policy_decision_id,approval_id,operation_intent_id,operation_attempt_id,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("tx-bad", "t1", "r1", "req-bad", "test", "a1", "pd2", None, "i1", "at1", "pending"),
        ),
        "authority",
    )

    msg = "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)"
    con.execute(msg, ("m1", "t1", "r1", "thread", "terminal_result", None, "a1", "accepted", NOW, None))
    expect_blocked("sqlite.one_terminal_message_per_run", lambda: con.execute(msg, ("m2", "t1", "r1", "thread", "terminal_result", None, "a1", "accepted", NOW, None)), "UNIQUE")
    expect_blocked(
        "sqlite.message_cross_task_run_and_artifact_rejected",
        lambda: con.execute(msg, ("m-bad", "t1", "r2", "thread", "analysis", None, "a2", "accepted", NOW, None)),
        "scope",
    )
    expect_blocked(
        "sqlite.message_identity_is_immutable",
        lambda: con.execute("UPDATE messages SET run_id='r2' WHERE id='m1'"),
        "immutable",
    )
    expect_blocked("sqlite.operation_attempt_delete_forbidden", lambda: con.execute("DELETE FROM operation_attempts WHERE id='at1'"), "retained")

    # A separate final-commit intent is used for exact approval binding.
    con.execute(
        "INSERT INTO operation_intents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("ic", "t1", "r1", "git.final_commit", "queryable", "commit-key", "a1", SHA_A, SHA_A, "pending", 0, NOW, NOW),
    )
    con.execute(
        "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("ap1", "t1", "ic", "final_commit", "approval-digest.v2", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz123456", "pending", NOW, None, LATER, "a1", None),
    )
    expect_blocked(
        "sqlite.approval_receipt_wrong_actor_rejected",
        lambda: con.execute(
            "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("adr-bad", "ap1", "t1", "ic", SHA_A, SHA_B, "nonce_abcdefghijklmnopqrstuvwxyz123456", "granted", "cred", NOW, SHA_A),
        ),
        "does not match",
    )
    con.execute(
        "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("adr1", "ap1", "t1", "ic", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz123456", "granted", "cred", NOW, SHA_A),
    )
    con.execute("UPDATE approvals SET status='granted',resolved_at=? WHERE id='ap1'", (NOW,))
    expect_blocked("sqlite.approval_receipt_immutable", lambda: con.execute("UPDATE approval_decision_receipts SET actor_binding_digest=? WHERE id='adr1'", (SHA_B,)), "immutable")

    expect_blocked(
        "sqlite.protocol_request_cross_task_run_rejected",
        lambda: con.execute(
            "INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("conn-bad", "core:bad", "initialize", SHA_A, "t1", "r2", "pending", None, NOW, None),
        ),
        "scope",
    )

    con.execute("INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)", ("conn-scope", "core:scope", "initialize", SHA_A, "t1", "r1", "pending", None, NOW, None))
    expect_blocked(
        "sqlite.protocol_response_cross_task_artifact_rejected",
        lambda: con.execute(
            "UPDATE protocol_requests SET status='completed',response_artifact_id='a2',completed_at=? WHERE connection_id='conn-scope' AND request_id='core:scope'",
            (NOW,),
        ),
        "scope",
    )

    con.execute("INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)", ("conn", "core:99", "initialize", SHA_A, "t1", "r1", "pending", None, NOW, None))
    con.execute("UPDATE protocol_requests SET status='completed',response_artifact_id='response',completed_at=? WHERE connection_id='conn' AND request_id='core:99'", (NOW,))
    expect_blocked("sqlite.protocol_terminal_irreversible", lambda: con.execute("UPDATE protocol_requests SET status='pending' WHERE connection_id='conn' AND request_id='core:99'"))
    expect_blocked(
        "sqlite.protocol_response_evidence_cannot_be_cleared",
        lambda: con.execute("UPDATE protocol_requests SET response_artifact_id=NULL WHERE connection_id='conn' AND request_id='core:99'"),
    )

    def reset_protocol_request() -> None:
        con.execute("DELETE FROM protocol_requests WHERE connection_id='conn' AND request_id='core:99'")
        con.execute(
            "INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("conn", "core:99", "initialize", SHA_B, "t1", "r1", "pending", None, LATER, None),
        )

    expect_blocked("sqlite.protocol_request_delete_reset_forbidden", reset_protocol_request, "retained")

    con.execute("INSERT INTO protocol_stream_heads VALUES (?,?,?,?)", ("conn", "r1", "content", 1))
    expect_blocked("sqlite.protocol_stream_gap_rejected", lambda: con.execute("UPDATE protocol_stream_heads SET last_sequence=3 WHERE connection_id='conn' AND run_id='r1' AND channel='content'"), "exactly by one")

    def reset_protocol_stream() -> None:
        con.execute("DELETE FROM protocol_stream_heads WHERE connection_id='conn' AND run_id='r1' AND channel='content'")
        con.execute("INSERT INTO protocol_stream_heads VALUES (?,?,?,?)", ("conn", "r1", "content", 1))

    expect_blocked("sqlite.protocol_stream_delete_reset_forbidden", reset_protocol_stream, "retained")

    record("sqlite.foreign_keys_runtime", con.execute("PRAGMA foreign_keys").fetchone()[0] == 1, "runtime connection reports foreign_keys=ON")


def expect_schema_valid(name: str, schema: dict, instance: dict, definition: str | None = None) -> None:
    target = schema if definition is None else {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{definition}"}
    try:
        Draft202012Validator(target).validate(instance)
    except ValidationError as exc:
        record(name, False, exc.message)
    else:
        record(name, True, "accepted")


def expect_schema_invalid(name: str, schema: dict, instance: dict, definition: str | None = None) -> None:
    target = schema if definition is None else {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{definition}"}
    try:
        Draft202012Validator(target).validate(instance)
    except ValidationError as exc:
        record(name, True, exc.message)
    else:
        record(name, False, "invalid instance was accepted")


def validate_json_schemas() -> None:
    protocol = load_json("agent-protocol.v2.schema.json")
    approval = load_json("approval-digest.v2.schema.json")
    receipt = load_json("approval-decision-receipt.v1.schema.json")
    for title, schema in (("protocol", protocol), ("approval", approval), ("receipt", receipt)):
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            record(f"schema.{title}.compiles", False, str(exc))
        else:
            record(f"schema.{title}.compiles", True, "Draft 2020-12 schema valid")

    init_req = json.loads((SCHEMAS / "examples-v2/protocol-initialize.request.json").read_text())
    init_resp = json.loads((SCHEMAS / "examples-v2/protocol-initialize.response.json").read_text())
    tool_resp = json.loads((SCHEMAS / "examples-v2/protocol-tool.response.json").read_text())
    final_ap = json.loads((SCHEMAS / "examples-v2/approval-final-commit.example.json").read_text())
    expect_schema_valid("schema.initialize_request_valid", protocol, init_req, "initializeRequest")
    expect_schema_valid("schema.initialize_response_valid", protocol, init_resp, "initializeResponse")
    expect_schema_valid("schema.tool_response_valid", protocol, tool_resp, "toolResponse")

    wrong = {"jsonrpc": "2.0", "id": "core:1", "result": {"totallyWrong": True}}
    expect_schema_invalid("schema.method_specific_wrong_result_rejected", protocol, wrong, "initializeResponse")
    extra_core = json.loads(json.dumps(init_req)); extra_core["futureField"] = True
    expect_schema_invalid("schema.unknown_core_field_rejected", protocol, extra_core, "initializeRequest")
    extension = json.loads(json.dumps(init_req)); extension["extensions"] = {"com.example.trace": {"enabled": True}}
    expect_schema_valid("schema.namespaced_extension_accepted", protocol, extension, "initializeRequest")

    missing_oid = json.loads(json.dumps(final_ap)); del missing_oid["operation"]["candidateCommitOid"]
    expect_schema_invalid("schema.final_commit_requires_candidate_oid", approval, missing_oid)
    expect_schema_valid("schema.final_commit_example_valid", approval, final_ap)


def write_report() -> None:
    out = ROOT / "validation" / "validation-results.json"
    out.write_text(json.dumps({"checks": [asdict(c) for c in checks]}, indent=2) + "\n", encoding="utf-8")
    md = ["# Validation Results", "", "Generated by `python validation/validate_v3.py`.", "", "| Check | Result | Detail |", "|---|---|---|"]
    for c in checks:
        detail = c.detail.replace("|", "\\|").replace("\n", " ")
        md.append(f"| `{c.name}` | {'PASS' if c.passed else 'FAIL'} | {detail} |")
    passed = sum(c.passed for c in checks)
    md.extend(["", f"**Result:** {passed}/{len(checks)} checks passed.", ""])
    (ROOT / "validation" / "VALIDATION-RESULTS.md").write_text("\n".join(md), encoding="utf-8")


def main() -> int:
    validate_sqlite()
    validate_json_schemas()
    write_report()
    failed = [c for c in checks if not c.passed]
    print(f"\n{len(checks)-len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
