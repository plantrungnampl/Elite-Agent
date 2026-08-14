#!/usr/bin/env python3
"""Adversarial regression suite added during the v3.2 self-review.

These counterexamples were first run against v3.1 and failed. In v3.2 they remain as a permanent regression suite.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_v3 import LATER, NOW, OID_A, SHA_A, SHA_B, seed  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "sqlite-v2.sql"
OID_B = "b" * 40
SHA_C = "sha256:" + "c" * 64


def db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA.read_text(encoding="utf-8"))
    seed(con)
    return con


def blocked(name: str, setup_and_attack: Callable[[sqlite3.Connection], None], contains: str | None = None) -> bool:
    con = db()
    try:
        setup_and_attack(con)
    except sqlite3.IntegrityError as exc:
        ok = contains is None or contains in str(exc)
        print(("PASS" if ok else "FAIL"), name, "-", exc)
        return ok
    else:
        print("FAIL", name, "- unsafe operation succeeded")
        return False
    finally:
        con.close()


def insert_attempt(con: sqlite3.Connection, *, attempt_id: str = "atx", policy_id: str = "pd1", approval_id=None, status="claimed", terminal_at=None, result=None, receipt=None, error=None) -> None:
    con.execute(
        """INSERT INTO operation_attempts(
        id,operation_intent_id,task_id,attempt_no,owner_run_id,fencing_token,
        policy_decision_id,approval_id,status,started_at,terminal_at,
        result_artifact_id,receipt_artifact_id,error_artifact_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (attempt_id, "i1", "t1", 1, "r1", 1, policy_id, approval_id, status, NOW, terminal_at, result, receipt, error),
    )


def insert_tool(con: sqlite3.Connection, *, tool_id="tx", policy_id="pd1", arguments="a1", status="pending", stdout=None, completed_at=None) -> None:
    insert_attempt(con, attempt_id="atx", policy_id="pd1")
    con.execute("UPDATE operation_intents SET current_attempt_no=1,status='started',updated_at=? WHERE id='i1'", (NOW,))
    con.execute(
        """INSERT INTO tool_executions(
        id,task_id,run_id,request_id,tool_name,arguments_artifact_id,policy_decision_id,
        approval_id,operation_intent_id,operation_attempt_id,executor_fencing_token,
        status,started_at,completed_at,stdout_artifact_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (tool_id, "t1", "r1", "req-x", "test", arguments, policy_id, None, "i1", "atx", 1, status, NOW, completed_at, stdout),
    )


def create_final_approval(con: sqlite3.Connection) -> None:
    con.execute(
        "INSERT INTO operation_intents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("ic", "t1", "r1", "git.final_commit", "queryable", "commit-key", "a1", SHA_A, SHA_A, "pending", 0, NOW, NOW),
    )
    con.execute(
        "INSERT INTO final_commit_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("fc1", "t1", "ic", SHA_A, "refs/heads/main", OID_A, OID_A, OID_A, SHA_A, SHA_A, NOW),
    )
    con.execute(
        "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("ap1", "t1", "ic", "final_commit", "approval-digest.v2", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz123456", "pending", NOW, None, LATER, "a1", None),
    )
    con.execute(
        "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("adr1", "ap1", "t1", "ic", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz123456", "granted", "cred", NOW, SHA_A),
    )
    con.execute("UPDATE approvals SET status='granted',resolved_at=? WHERE id='ap1'", (NOW,))


def main() -> int:
    cases: list[bool] = []

    cases.append(blocked("schema_migration_update_forbidden", lambda c: (
        c.execute("INSERT INTO schema_migrations VALUES (1,'v1',?,?,?)", (NOW, "1.0", SHA_A)),
        c.execute("UPDATE schema_migrations SET checksum=? WHERE version=1", (SHA_B,)),
    ), "immutable"))
    cases.append(blocked("schema_migration_delete_forbidden", lambda c: (
        c.execute("INSERT INTO schema_migrations VALUES (1,'v1',?,?,?)", (NOW, "1.0", SHA_A)),
        c.execute("DELETE FROM schema_migrations WHERE version=1"),
    ), "retained"))

    cases.append(blocked("artifact_task_project_mismatch_rejected", lambda c: c.execute(
        "INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("bad-art", "t1", "p2", "context", "bad", SHA_A, "bad", 1, "application/json", "available", "core", "core", NOW, None, "hash_verified"),
    ), "scope"))
    cases.append(blocked("artifact_identity_immutable", lambda c: c.execute("UPDATE artifacts SET content_hash=? WHERE id='a1'", (SHA_B,)), "immutable"))
    cases.append(blocked("available_artifact_direct_delete_rejected", lambda c: (
        c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("loose", None, "p1", "log", "loose", SHA_A, "loose", 1, None, "available", "core", "core", NOW, None, "unverified")),
        c.execute("DELETE FROM artifacts WHERE id='loose'"),
    ), "artifact records are retained"))
    cases.append(blocked("artifact_cross_scope_supersession_rejected", lambda c: c.execute(
        "INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("bad-sup", "t1", "p1", "context", "a1", SHA_B, "bad-sup", 1, "application/json", "available", "core", "core", NOW, "a2", "hash_verified"),
    ), "supersession"))
    cases.append(blocked("artifact_quarantined_cannot_return_available", lambda c: (
        c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("aq", None, "p1", "log", "aq", SHA_A, "aq", 1, None, "quarantined", "core", "core", NOW, None, "hash_verified")),
        c.execute("UPDATE artifacts SET availability='available' WHERE id='aq'"),
    ), "invalid artifact availability transition"))
    cases.append(blocked("artifact_rejected_cannot_be_promoted", lambda c: (
        c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ar", None, "p1", "log", "ar", SHA_A, "ar", 1, None, "available", "core", "core", NOW, None, "rejected")),
        c.execute("UPDATE artifacts SET verification_state='user_approved' WHERE id='ar'"),
    ), "invalid artifact verification transition"))
    cases.append(blocked("quarantined_artifact_metadata_is_retained", lambda c: (
        c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ad", None, "p1", "log", "ad", SHA_A, "ad", 1, None, "quarantined", "core", "core", NOW, None, "rejected")),
        c.execute("DELETE FROM artifacts WHERE id='ad'"),
    ), "artifact records are retained"))
    cases.append(blocked("artifact_replace_cannot_reset_lifecycle", lambda c: (
        c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("arp", None, "p1", "log", "arp", SHA_A, "arp", 1, None, "quarantined", "core", "core", NOW, None, "rejected")),
        c.execute("INSERT OR REPLACE INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("arp", None, "p1", "log", "arp", SHA_A, "arp", 1, None, "available", "core", "core", NOW, None, "user_approved")),
    ), "artifact identity replacement is forbidden"))

    con = db()
    try:
        con.execute("UPDATE artifacts SET availability='quarantined' WHERE id='a1'")
        con.execute("UPDATE artifacts SET verification_state='user_approved' WHERE id='cred'")
    except sqlite3.IntegrityError as exc:
        print("FAIL artifact_supported_transitions_remain_available -", exc)
        cases.append(False)
    else:
        print("PASS artifact_supported_transitions_remain_available - available->quarantined and tool_verified->user_approved")
        cases.append(True)
    finally:
        con.close()

    cases.append(blocked("operation_intent_cross_task_scope_rejected", lambda c: c.execute(
        "INSERT INTO operation_intents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("bad-intent", "t1", "r2", "tool.execute", "queryable", "bad-key", "a2", SHA_B, SHA_A, "pending", 0, NOW, NOW),
    ), "scope"))
    cases.append(blocked("operation_intent_delete_forbidden", lambda c: c.execute("DELETE FROM operation_intents WHERE id='i1'"), "retained"))
    cases.append(blocked("attempt_counter_requires_existing_attempt", lambda c: c.execute("UPDATE operation_intents SET current_attempt_no=1,updated_at=? WHERE id='i1'", (NOW,)), "attempt"))

    cases.append(blocked("policy_decision_update_forbidden", lambda c: c.execute("UPDATE policy_decisions SET effect='deny' WHERE id='pd1'"), "immutable"))
    cases.append(blocked("policy_decision_delete_forbidden", lambda c: c.execute("DELETE FROM policy_decisions WHERE id='pd1'"), "retained"))
    cases.append(blocked("context_policy_cross_task_rejected", lambda c: c.execute("INSERT INTO context_package_policy_decisions VALUES ('cp1','pd2')"), "scope"))

    def require_approval_without_approval(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO policy_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("pd-req", "t1", "{}", SHA_A, "tool.execute", "{}", SHA_A, "test", "Implementation", "require_approval", "[]", SHA_A, SHA_A, NOW, LATER, None),
        )
        insert_attempt(c, policy_id="pd-req")
    cases.append(blocked("required_approval_cannot_be_omitted", require_approval_without_approval, "approval"))

    def expired_policy(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO policy_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("pd-exp", "t1", "{}", SHA_A, "tool.execute", "{}", SHA_A, "test", "Implementation", "allow", "[]", SHA_A, SHA_A, "2026-08-04T06:00:00Z", "2026-08-04T07:00:00Z", None),
        )
        insert_attempt(c, policy_id="pd-exp")
    cases.append(blocked("expired_policy_cannot_authorize_attempt", expired_policy, "expired"))

    cases.append(blocked("attempt_cross_task_evidence_rejected", lambda c: insert_attempt(c, status="succeeded", terminal_at=NOW, receipt="a2"), "evidence"))

    def tool_cross_task_arguments(c: sqlite3.Connection) -> None:
        insert_tool(c, arguments="a2")
    cases.append(blocked("tool_cross_task_arguments_rejected", tool_cross_task_arguments, "scope"))

    def tool_policy_mismatch(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO policy_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("pd-alt", "t1", "{}", SHA_A, "tool.execute", "{}", SHA_A, "test", "Implementation", "allow", "[]", SHA_A, SHA_A, NOW, LATER, None),
        )
        insert_attempt(c, attempt_id="atx", policy_id="pd1")
        c.execute("UPDATE operation_intents SET current_attempt_no=1,status='started',updated_at=? WHERE id='i1'", (NOW,))
        c.execute(
            "INSERT INTO tool_executions(id,task_id,run_id,request_id,tool_name,arguments_artifact_id,policy_decision_id,approval_id,operation_intent_id,operation_attempt_id,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("tx", "t1", "r1", "req", "test", "a1", "pd-alt", None, "i1", "atx", "pending"),
        )
    cases.append(blocked("tool_must_use_attempt_policy", tool_policy_mismatch, "attempt"))

    def tool_terminal_reversal(c: sqlite3.Connection) -> None:
        insert_tool(c, status="succeeded", completed_at=NOW)
        c.execute("UPDATE tool_executions SET status='running' WHERE id='tx'")
    cases.append(blocked("tool_terminal_status_irreversible", tool_terminal_reversal, "irreversible"))

    def tool_output_overwrite(c: sqlite3.Connection) -> None:
        insert_tool(c, stdout="receipt1")
        c.execute("UPDATE tool_executions SET stdout_artifact_id='receipt2' WHERE id='tx'")
    cases.append(blocked("tool_output_evidence_set_once", tool_output_overwrite, "set-once"))

    def tool_delete(c: sqlite3.Connection) -> None:
        insert_tool(c)
        c.execute("DELETE FROM tool_executions WHERE id='tx'")
    cases.append(blocked("tool_execution_delete_forbidden", tool_delete, "retained"))

    cases.append(blocked("protocol_completed_insert_requires_response", lambda c: c.execute(
        "INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("conn", "core:done", "initialize", SHA_A, "t1", "r1", "completed", None, NOW, NOW),
    ), "response"))

    def approval_cross_task_request(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("apx", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz654321", "pending", NOW, None, LATER, "a2", None),
        )
    cases.append(blocked("approval_request_artifact_scope_rejected", approval_cross_task_request, "artifact"))

    def receipt_cross_task_credential(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("apx", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz654321", "pending", NOW, None, LATER, "a1", None),
        )
        c.execute(
            "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("adrx", "apx", "t1", "i1", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz654321", "granted", "a2", NOW, SHA_B),
        )
    cases.append(blocked("approval_credential_artifact_scope_rejected", receipt_cross_task_credential, "credential"))

    def expired_grant(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("apx", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz654321", "pending", "2026-08-04T06:00:00Z", None, "2026-08-04T07:00:00Z", "a1", None),
        )
        c.execute(
            "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("adrx", "apx", "t1", "i1", SHA_A, SHA_A, "nonce_abcdefghijklmnopqrstuvwxyz654321", "granted", "cred", NOW, SHA_B),
        )
    cases.append(blocked("expired_approval_cannot_receive_grant", expired_grant, "expired"))

    def wrong_consumption(c: sqlite3.Connection) -> None:
        create_final_approval(c)
        c.execute(
            "INSERT INTO approval_effect_consumptions VALUES (?,?,?,?,?,?,?,?)",
            ("consume", "adr1", "ic", SHA_A, "refs/heads/other", OID_A, OID_B, NOW),
        )
    cases.append(blocked("final_commit_consumption_exact_tuple_enforced", wrong_consumption, "candidate"))

    def artifact_operation_mutation(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO artifact_operations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ao", "a1", "tmp", SHA_A, 1, "intent", NOW, NOW, None, None))
        c.execute("UPDATE artifact_operations SET expected_hash=? WHERE id='ao'", (SHA_B,))
    cases.append(blocked("artifact_operation_identity_immutable", artifact_operation_mutation, "immutable"))

    def artifact_operation_delete(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO artifact_operations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ao", "a1", "tmp", SHA_A, 1, "intent", NOW, NOW, None, None))
        c.execute("DELETE FROM artifact_operations WHERE id='ao'")
    cases.append(blocked("artifact_operation_delete_forbidden", artifact_operation_delete, "retained"))


    cases.append(blocked("project_repository_identity_immutable", lambda c: c.execute(
        "UPDATE projects SET repository_identity=? WHERE id='p1'", (SHA_C,)
    ), "immutable"))

    def approval_inserted_pregranted(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ap-pre", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A,
             "nonce_pregranted_abcdefghijklmnopqrstuvwxyz", "granted", NOW, NOW, LATER, "a1", None),
        )
    cases.append(blocked("approval_must_start_pending", approval_inserted_pregranted, "pending"))

    def grant_without_resolution_time(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("apx", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A,
             "nonce_resolution_abcdefghijklmnopqrstuvwxyz", "pending", NOW, None, LATER, "a1", None),
        )
        c.execute(
            "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("adrx", "apx", "t1", "i1", SHA_A, SHA_A,
             "nonce_resolution_abcdefghijklmnopqrstuvwxyz", "granted", "cred", NOW, SHA_B),
        )
        c.execute("UPDATE approvals SET status='granted' WHERE id='apx'")
    cases.append(blocked("granted_approval_requires_resolution_time", grant_without_resolution_time, "resolution"))

    cases.append(blocked("successful_attempt_requires_receipt", lambda c: insert_attempt(
        c, status="succeeded", terminal_at=NOW
    ), "receipt"))

    cases.append(blocked("agent_run_terminal_requires_completion_time", lambda c: c.execute(
        "UPDATE agent_runs SET status='succeeded' WHERE id='r1'"
    ), "completion"))

    def interrupted_run_reversal(c: sqlite3.Connection) -> None:
        c.execute("UPDATE agent_runs SET status='interrupted',completed_at=? WHERE id='r1'", (NOW,))
        c.execute("UPDATE agent_runs SET status='running' WHERE id='r1'")
    cases.append(blocked("interrupted_agent_run_is_terminal", interrupted_run_reversal, "irreversible"))

    def message_delete(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)", ("m1", "t1", "r1", "thread", "analysis", None, "a1", "accepted", NOW, None))
        c.execute("DELETE FROM messages WHERE id='m1'")
    cases.append(blocked("message_delete_forbidden", message_delete, "retained"))

    def message_status_reversal(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)", ("m1", "t1", "r1", "thread", "analysis", None, "a1", "accepted", NOW, None))
        c.execute("UPDATE messages SET status='retracted' WHERE id='m1'")
        c.execute("UPDATE messages SET status='accepted' WHERE id='m1'")
    cases.append(blocked("message_terminal_status_irreversible", message_status_reversal, "irreversible"))

    def create_external(c: sqlite3.Connection, *, enabled_after_attestation: bool) -> None:
        c.execute(
            "INSERT INTO agent_descriptors VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("ext", "External", "stdio", "isolated_worker", "{}", SHA_A, SHA_A, None, 0, "healthy", NOW),
        )
        c.execute(
            "INSERT INTO context_packages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("cp-ext", "t1", "ext", "implementer", "Objective", "a1", "a1", SHA_A, SHA_A, "1", "1", NOW),
        )
        if enabled_after_attestation:
            c.execute(
                "INSERT INTO containment_attestations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("att-ext", "ext", SHA_A, SHA_A, SHA_A, SHA_A, "win11", "x64", "1", "cred", "2026-08-04T07:00:00Z", LATER),
            )
            c.execute("UPDATE agent_descriptors SET active_attestation_id='att-ext',enabled=1,updated_at=? WHERE id='ext'", (NOW,))

    def disabled_agent_run(c: sqlite3.Connection) -> None:
        create_external(c, enabled_after_attestation=False)
        c.execute(
            "INSERT INTO agent_runs(id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("rx", "t1", "ext", "implementer", "Implementation", "created", "cp-ext", "ext-run", SHA_A, "a1"),
        )
    cases.append(blocked("disabled_external_agent_cannot_start_run", disabled_agent_run, "disabled"))

    def revoked_agent_run(c: sqlite3.Connection) -> None:
        create_external(c, enabled_after_attestation=True)
        c.execute("INSERT INTO containment_attestation_revocations VALUES (?,?,?,?)", ("rev", "att-ext", "test", NOW))
        c.execute(
            "INSERT INTO agent_runs(id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("rx", "t1", "ext", "implementer", "Implementation", "created", "cp-ext", "ext-run", SHA_A, "a1"),
        )
    cases.append(blocked("revoked_external_agent_cannot_start_run", revoked_agent_run))

    def pending_protocol_cross_task_response(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)", ("conn", "core:x", "initialize", SHA_A, "t1", "r1", "pending", None, NOW, None))
        c.execute("UPDATE protocol_requests SET response_artifact_id='a2' WHERE connection_id='conn' AND request_id='core:x'")
    cases.append(blocked("protocol_response_update_scope_rejected", pending_protocol_cross_task_response, "scope"))

    def protocol_stream_key_reset(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO protocol_stream_heads VALUES (?,?,?,?)", ("conn", "r1", "content", 1))
        c.execute("UPDATE protocol_stream_heads SET connection_id='moved' WHERE connection_id='conn' AND run_id='r1' AND channel='content'")
        c.execute("INSERT INTO protocol_stream_heads VALUES (?,?,?,?)", ("conn", "r1", "content", 1))
    cases.append(blocked("protocol_stream_identity_immutable", protocol_stream_key_reset, "immutable"))

    def lease_expiry_mutation(c: sqlite3.Connection) -> None:
        c.execute("UPDATE tasks SET fencing_epoch=1,row_version=1 WHERE id='t1'")
        c.execute("INSERT INTO executor_leases VALUES (?,?,?,?,?,?,?,?)", ("lease", "t1", "r1", 1, "active", NOW, LATER, None))
        c.execute("UPDATE executor_leases SET expires_at='2026-08-04T10:00:00Z' WHERE id='lease'")
    cases.append(blocked("lease_expiry_identity_immutable", lease_expiry_mutation, "immutable"))

    cases.append(blocked("operation_digest_matches_canonical_artifact", lambda c: c.execute(
        "INSERT INTO operation_intents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("bad-digest", "t1", "r1", "tool.execute", "queryable", "bad-digest-key", "a1", SHA_B, SHA_A, "pending", 0, NOW, NOW),
    ), "digest"))

    def policy_cross_task_approval(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("apx", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A,
             "nonce_policy_scope_abcdefghijklmnopqrstuvwxyz", "pending", NOW, None, LATER, "a1", None),
        )
        c.execute(
            "INSERT INTO policy_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("pd-bad", "t2", "{}", SHA_A, "tool.execute", "{}", SHA_A, "test", "Implementation", "require_approval", "[]", SHA_A, SHA_A, NOW, LATER, "apx"),
        )
    cases.append(blocked("policy_approval_scope_rejected", policy_cross_task_approval, "scope"))

    def tool_terminal_without_time(c: sqlite3.Connection) -> None:
        insert_tool(c, status="succeeded", completed_at=None)
    cases.append(blocked("terminal_tool_requires_completion_time", tool_terminal_without_time, "completion"))

    cases.append(blocked("source_document_task_project_scope_rejected", lambda c: c.execute(
        "INSERT INTO source_documents VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("sd", "p2", "t1", "repo", "x", "rev", SHA_A, "internal", SHA_A, "current", NOW),
    ), "scope"))

    cases.append(blocked("memory_artifact_project_scope_rejected", lambda c: c.execute(
        "INSERT INTO memory_entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("mem", "p1", "fact", "candidate", "a2", "[]", None, None, 500000, None, NOW, None),
    ), "scope"))

    def graph_cross_project(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO source_documents VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("sd1", "p1", None, "repo", "x", "rev", SHA_A, "internal", SHA_A, "current", NOW))
        c.execute("INSERT INTO source_documents VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("sd2", "p2", None, "repo", "y", "rev", SHA_B, "internal", SHA_B, "current", NOW))
        c.execute("INSERT INTO repository_graph_nodes VALUES (?,?,?,?,?,?)", ("n1", "sd1", "symbol", "x", SHA_A, "{}"))
        c.execute("INSERT INTO repository_graph_nodes VALUES (?,?,?,?,?,?)", ("n2", "sd2", "symbol", "y", SHA_B, "{}"))
        c.execute("INSERT INTO repository_graph_edges VALUES (?,?,?,?,?,?,?,?)", ("edge", "p1", "n1", "n2", "calls", "rev", SHA_A, "{}"))
    cases.append(blocked("graph_edge_project_scope_rejected", graph_cross_project, "scope"))

    def update_journal_delete(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO update_journal VALUES (?,?,?,?,?,?,?,?,?,?)", ("u1", "1", "2", 1, 2, "planned", None, NOW, NOW, None))
        c.execute("DELETE FROM update_journal WHERE id='u1'")
    cases.append(blocked("update_journal_delete_forbidden", update_journal_delete, "retained"))


    def interrupted_intent_reversal(c: sqlite3.Connection) -> None:
        insert_attempt(c, status="interrupted", terminal_at=NOW)
        c.execute("UPDATE operation_intents SET current_attempt_no=1,status='interrupted',updated_at=? WHERE id='i1'", (NOW,))
        c.execute("UPDATE operation_intents SET status='pending',updated_at=? WHERE id='i1'", (LATER,))
    cases.append(blocked("interrupted_operation_intent_is_terminal", interrupted_intent_reversal, "irreversible"))

    cases.append(blocked("terminal_intent_requires_matching_attempt", lambda c: c.execute(
        "UPDATE operation_intents SET status='succeeded',updated_at=? WHERE id='i1'", (NOW,)
    ), "attempt"))

    def artifact_completed_without_time(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO artifact_operations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ao", "a1", "tmp", SHA_A, 1, "intent", NOW, NOW, None, None))
        c.execute("UPDATE artifact_operations SET status='completed',updated_at=? WHERE id='ao'", (LATER,))
    cases.append(blocked("completed_artifact_operation_requires_receipt_time", artifact_completed_without_time, "completion"))

    def lease_release_without_time(c: sqlite3.Connection) -> None:
        c.execute("UPDATE tasks SET fencing_epoch=1,row_version=1 WHERE id='t1'")
        c.execute("INSERT INTO executor_leases VALUES (?,?,?,?,?,?,?,?)", ("lease", "t1", "r1", 1, "active", NOW, LATER, None))
        c.execute("UPDATE executor_leases SET status='released' WHERE id='lease'")
    cases.append(blocked("terminal_lease_requires_release_time", lease_release_without_time, "release"))

    def failed_protocol_without_time(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)", ("conn", "core:fail", "initialize", SHA_A, "t1", "r1", "pending", None, NOW, None))
        c.execute("UPDATE protocol_requests SET status='failed' WHERE connection_id='conn' AND request_id='core:fail'")
    cases.append(blocked("failed_protocol_requires_completion_time", failed_protocol_without_time, "completion"))

    def pending_protocol_with_completion(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO protocol_requests VALUES (?,?,?,?,?,?,?,?,?,?)", ("conn", "core:pending", "initialize", SHA_A, "t1", "r1", "pending", None, NOW, None))
        c.execute("UPDATE protocol_requests SET completed_at=? WHERE connection_id='conn' AND request_id='core:pending'", (NOW,))
    cases.append(blocked("pending_protocol_cannot_have_completion_time", pending_protocol_with_completion, "pending"))

    def superseded_message_without_replacement(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)", ("m1", "t1", "r1", "thread", "analysis", None, "a1", "accepted", NOW, None))
        c.execute("UPDATE messages SET status='superseded' WHERE id='m1'")
    cases.append(blocked("superseded_message_requires_replacement", superseded_message_without_replacement, "replacement"))

    def policy_named_approval_mismatch(c: sqlite3.Connection) -> None:
        for aid, atype, nonce, rid, rdigest in (
            ("ap1", "tool", "nonce_policy_one_abcdefghijklmnopqrstuvwxyz", "ar1", SHA_A),
            ("ap2", "policy_exception", "nonce_policy_two_abcdefghijklmnopqrstuvwxyz", "ar2", SHA_B),
        ):
            c.execute(
                "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (aid, "t1", "i1", atype, "approval-digest.v2", SHA_A, SHA_A, nonce, "pending", NOW, None, LATER, "a1", None),
            )
            c.execute(
                "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (rid, aid, "t1", "i1", SHA_A, SHA_A, nonce, "granted", "cred", NOW, rdigest),
            )
            c.execute("UPDATE approvals SET status='granted',resolved_at=? WHERE id=?", (NOW, aid))
        c.execute(
            "INSERT INTO policy_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("pd-linked", "t1", "{}", SHA_A, "tool.execute", "{}", SHA_A, "test", "Implementation", "require_approval", "[]", SHA_A, SHA_A, NOW, LATER, "ap1"),
        )
        insert_attempt(c, policy_id="pd-linked", approval_id="ap2")
    cases.append(blocked("attempt_uses_policy_named_approval", policy_named_approval_mismatch, "policy"))

    def final_commit_wrong_approval_type(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO operation_intents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ic-wrong", "t1", "r1", "git.final_commit", "queryable", "commit-wrong", "a1", SHA_A, SHA_A, "pending", 0, NOW, NOW),
        )
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ap-wrong", "t1", "ic-wrong", "tool", "approval-digest.v2", SHA_A, SHA_A,
             "nonce_wrong_type_abcdefghijklmnopqrstuvwxyz", "pending", NOW, None, LATER, "a1", None),
        )
    cases.append(blocked("final_commit_requires_final_commit_approval_type", final_commit_wrong_approval_type, "final_commit"))

    def resolution_time_mismatch(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("apx", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A,
             "nonce_time_match_abcdefghijklmnopqrstuvwxyz", "pending", NOW, None, LATER, "a1", None),
        )
        c.execute(
            "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("adrx", "apx", "t1", "i1", SHA_A, SHA_A,
             "nonce_time_match_abcdefghijklmnopqrstuvwxyz", "granted", "cred", NOW, SHA_B),
        )
        c.execute("UPDATE approvals SET status='granted',resolved_at=? WHERE id='apx'", (LATER,))
    cases.append(blocked("approval_resolution_time_matches_receipt", resolution_time_mismatch, "receipt"))

    cases.append(blocked("project_repository_identity_requires_digest", lambda c: c.execute(
        "INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?)",
        ("p3", "Project 3", "C:/repo3", "not-a-digest", NOW, NOW, "policy", "application_data", "C:/data/p3"),
    ), "digest"))


    def loose_run_delete(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO agent_runs(id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("r-loose", "t1", "core-agent", "implementer", "Implementation", "created", "cp1", "loose-run-key", SHA_A, "a1"),
        )
        c.execute("DELETE FROM agent_runs WHERE id='r-loose'")
    cases.append(blocked("agent_run_delete_forbidden", loose_run_delete, "retained"))

    def run_usage_overwrite(c: sqlite3.Connection) -> None:
        c.execute("UPDATE agent_runs SET provider_usage_json='{\"tokens\":1}' WHERE id='r1'")
        c.execute("UPDATE agent_runs SET provider_usage_json='{\"tokens\":2}' WHERE id='r1'")
    cases.append(blocked("agent_run_usage_evidence_set_once", run_usage_overwrite, "set-once"))

    def run_completion_overwrite(c: sqlite3.Connection) -> None:
        c.execute("UPDATE agent_runs SET status='succeeded',completed_at=? WHERE id='r1'", (NOW,))
        c.execute("UPDATE agent_runs SET completed_at=? WHERE id='r1'", (LATER,))
    cases.append(blocked("agent_run_completion_evidence_set_once", run_completion_overwrite, "set-once"))

    def message_replacement_overwrite(c: sqlite3.Connection) -> None:
        for mid in ("m2", "m3"):
            c.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)", (mid, "t1", "r1", "thread", "analysis", None, "a1", "accepted", NOW, None))
        c.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)", ("m1", "t1", "r1", "thread", "analysis", None, "a1", "accepted", NOW, None))
        c.execute("UPDATE messages SET status='superseded',superseded_by='m2' WHERE id='m1'")
        c.execute("UPDATE messages SET superseded_by='m3' WHERE id='m1'")
    cases.append(blocked("message_supersession_evidence_set_once", message_replacement_overwrite, "set-once"))

    def invalidation_reason_overwrite(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ap-invalid", "t1", "i1", "tool", "approval-digest.v2", SHA_A, SHA_A,
             "nonce_invalidation_abcdefghijklmnopqrstuvwxyz", "pending", NOW, None, LATER, "a1", None),
        )
        c.execute("UPDATE approvals SET status='invalidated',resolved_at=?,invalidation_reason='reason-1' WHERE id='ap-invalid'", (NOW,))
        c.execute("UPDATE approvals SET invalidation_reason='reason-2' WHERE id='ap-invalid'")
    cases.append(blocked("approval_invalidation_evidence_set_once", invalidation_reason_overwrite, "set-once"))

    passed = sum(cases)
    print(f"\n{passed}/{len(cases)} v3.2 hardening checks passed")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
