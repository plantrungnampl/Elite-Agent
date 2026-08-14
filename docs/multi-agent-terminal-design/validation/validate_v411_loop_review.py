#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Callable

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SC = ROOT / "schemas"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_v3 import SHA_A as SHA, SHA_B as SHA2, seed  # noqa: E402

T0 = "2026-08-06T00:50:00Z"
T1 = "2026-08-06T01:00:00Z"
T2 = "2026-08-06T01:10:00Z"
T3 = "2026-08-06T01:20:00Z"
T4 = "2026-08-06T01:30:00Z"
T5 = "2026-08-06T01:40:00Z"
T6 = "2026-08-06T01:50:00Z"
T7 = "2026-08-06T02:00:00Z"
T8 = "2026-08-06T02:10:00Z"

checks: list[bool] = []


def record(name: str, ok: bool, detail: str) -> None:
    checks.append(ok)
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def blocked(name: str, fn: Callable[[sqlite3.Connection], None], contains: str | tuple[str, ...]) -> None:
    con = db()
    try:
        fn(con)
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        needles = (contains,) if isinstance(contains, str) else contains
        record(name, any(n in str(exc) for n in needles), str(exc))
    else:
        record(name, False, "unsafe operation succeeded")
    finally:
        con.close()


def db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v5.sql").read_text(encoding="utf-8"))
    seed(con)
    return con


def migrated_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v4.sql").read_text(encoding="utf-8"))
    seed(con)
    con.executescript((SC / "migrate-v4-to-v5.sql").read_text(encoding="utf-8"))
    return con


def v4_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v4.sql").read_text(encoding="utf-8"))
    seed(con)
    return con


def insert_state(
    con: sqlite3.Connection,
    state_id: str,
    *,
    rank: int = 600,
    authority: str = "current_instruction",
    value: str = "vi",
    valid_from: str = T1,
    valid_until: str | None = None,
    status: str = "active",
    scope_kind: str = "task",
    scope_id: str = "t1",
    task_id: str | None = "t1",
    supersedes: str | None = None,
    source_artifact_id: str = "a1",
    source_digest: str = SHA,
) -> None:
    con.execute(
        """INSERT INTO state_records(
        id,project_id,task_id,state_key,scope_kind,scope_id,authority_kind,precedence_rank,
        value_json,source_artifact_id,source_digest,status,valid_from,valid_until,
        supersedes_state_id,created_at,status_changed_at,retracted_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            state_id, "p1", task_id, "user.output.language", scope_kind, scope_id, authority, rank,
            json.dumps({"language": value}, separators=(",", ":")), source_artifact_id, source_digest, status, valid_from,
            valid_until, supersedes, T1, T1, T1 if status == "retracted" else None,
        ),
    )


def rules(rule_id: str = "ir1", kind: str = "source_hash_changed") -> str:
    target_expected = {
        "source_hash_changed": ({"sourceId": "a1"}, {"contentHash": SHA}),
        "time_expired": ({}, {"expiresAt": T8}),
    }
    target, expected = target_expected.get(kind, ({"x": "y"}, {"x": "y"}))
    return json.dumps([
        {
            "ruleId": rule_id,
            "kind": kind,
            "target": target,
            "expected": expected,
            "cadence": "before_retrieval",
            "explanation": "Executable review rule",
        }
    ], separators=(",", ":"))


def insert_memory(con: sqlite3.Connection, memory_id: str = "m1", *, scope_kind: str = "project", scope_id: str = "p1") -> None:
    applicability = json.dumps(
        {"summary": "review memory", "scope": {"kind": scope_kind, "id": scope_id}},
        separators=(",", ":"),
    )
    con.execute(
        """INSERT INTO memory_records(
        id,project_id,logical_key,origin_task_id,origin_run_id,memory_type,version,status,
        content_artifact_id,applicability_json,invalidation_conditions_json,confidence_millionths,
        sensitivity,expires_at,created_at,status_changed_at,activated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (memory_id, "p1", f"key.{memory_id}", "t1", "r1", "negative", 1, "candidate", "a1", applicability,
         rules(), 900000, "internal", None, T1, T1, None),
    )


def verify_memory(con: sqlite3.Connection, memory_id: str = "m1") -> None:
    con.execute(
        "INSERT INTO memory_evidence_links VALUES (?,?,?,?,?,?,?,?,?,?)",
        (f"ev-{memory_id}", memory_id, "p1", "artifact", "a1", None, None, SHA, "supports", T1),
    )
    con.execute("UPDATE memory_records SET status='verified',status_changed_at=? WHERE id=?", (T2, memory_id))


def insert_benchmark_runs(con: sqlite3.Connection, memory_id: str = "m1", *, control_arm: str = "control_no_memory", candidate_arm: str = "evidence_plus_experience") -> None:
    con.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs-v411", "p1", 3, "a1", SHA, T1))
    con.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc-v411", "bs-v411", 1, "a1", "loop", SHA, T1))
    con.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-control", "bc-v411", "t1", SHA, SHA, "a1", "completed", T1, T2))
    con.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-candidate", "bc-v411", "t1", SHA, SHA, "a1", "completed", T1, T2))
    for run_id, arm in (("br-control", control_arm), ("br-candidate", candidate_arm)):
        con.execute(
            "INSERT INTO benchmark_run_arms VALUES (?,?,?,?,?,?,?)",
            (f"arm-{run_id}", run_id, arm, SHA, SHA, SHA, T2),
        )
    con.execute(
        "INSERT INTO benchmark_run_memory_bindings VALUES (?,?,?,?,?)",
        ("bind-candidate", "br-candidate", memory_id, "available", T2),
    )


def insert_retrieval(con: sqlite3.Connection, *, task_id: str = "t1", run_id: str = "r1", retrieval_id: str = "rs1") -> None:
    con.execute(
        """INSERT INTO retrieval_sessions(
        id,project_id,task_id,run_id,index_generation_id,query_artifact_id,plan_artifact_id,
        engine_id,engine_version,pipeline_version,status,branch_status_json,trace_artifact_id,
        trace_digest,started_at,completed_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (retrieval_id, "p1", task_id, run_id, None, "a1", "a1", "hybrid", "1", "v4.1.1", "running", "{}", None, None, T7, None),
    )


def insert_origin(
    con: sqlite3.Connection,
    memory_id: str = "m1",
    *,
    origin_kind: str = "model_generated",
    actor_kind: str | None = None,
    actor_id: str = "agent-1",
    actor_binding_digest: str = SHA,
    evidence_artifact_id: str = "a1",
    evidence_digest: str = SHA,
    created_at: str = T1,
) -> None:
    default_actor = {
        "model_generated": "agent",
        "user_explicit": "user",
        "approved_decision": "system",
        "imported_verified": "importer",
        "legacy_unknown": "migration",
    }
    con.execute(
        """INSERT INTO memory_origin_records(
        id,memory_id,project_id,origin_kind,origin_actor_kind,origin_actor_id,origin_actor_binding_digest,
        evidence_artifact_id,evidence_digest,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (f"origin-{memory_id}", memory_id, "p1", origin_kind, actor_kind or default_actor[origin_kind],
         actor_id, actor_binding_digest, evidence_artifact_id, evidence_digest, created_at),
    )


def activate_user_approved(con: sqlite3.Connection, memory_id: str = "m1") -> None:
    insert_origin(con, memory_id)
    verify_memory(con, memory_id)
    con.execute("INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)", (f"pr1-{memory_id}", memory_id, "p1", "user", "u1", "granted", "a1", SHA, T3))
    con.execute("UPDATE memory_records SET status='approved',status_changed_at=? WHERE id=?", (T4, memory_id))
    con.execute("INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)", (f"pr2-{memory_id}", memory_id, "p1", "user", "u1", "granted", "receipt2", SHA2, T5))
    con.execute("UPDATE memory_records SET status='active',status_changed_at=?,activated_at=? WHERE id=?", (T6, T6, memory_id))


def seed_task3(con: sqlite3.Connection) -> None:
    con.execute(
        "INSERT INTO tasks(id,project_id,title,objective,phase,condition,operation_state,risk_level,base_branch,base_commit,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("t3", "p1", "Task 3", "Objective", "Intake", "Active", "None", "medium", "main", "a" * 40, T1, T1),
    )
    con.execute(
        "INSERT INTO artifacts(id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,supersedes,verification_state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("a3", "t3", "p1", "context", "a3", SHA, "a3", 1, "application/json", "available", "core", "core", T1, None, "hash_verified"),
    )
    con.execute("INSERT INTO context_packages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("cp3", "t3", "core-agent", "implementer", "Objective", "a3", "a3", SHA, SHA, "1", "1", T1))
    con.execute(
        "INSERT INTO agent_runs(id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("r3", "t3", "core-agent", "implementer", "Implementation", "running", "cp3", "run-key-3", SHA, "a3"),
    )


def main() -> int:
    required = [SC / "sqlite-v5.sql", SC / "migrate-v4-to-v5.sql", SC / "cognitive-memory.v3.schema.json"]
    missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
    if missing:
        record("files.v411_contracts", False, "missing: " + ", ".join(missing))
        print(f"\n{sum(checks)}/{len(checks)} v4.1.1 loop-review checks passed")
        return 1
    record("files.v411_contracts", True, "all loop-review contracts present")

    schema = json.loads((SC / "cognitive-memory.v3.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    refs = {x.get("$ref") for x in schema.get("oneOf", [])}
    for name in ("stateRecord", "stateResolutionReceipt", "stateResolutionConflict", "invalidationEvaluation", "memoryShadowEvaluation", "memoryUsageEvent", "memoryConsolidationAction", "contextBudgetDecision"):
        record(f"schema.top_level.{name}", f"#/$defs/{name}" in refs, "definition is reachable from top-level oneOf")

    shadow = schema["$defs"]["memoryShadowEvaluation"]
    record("schema.shadow_cross_scope_fields", {"newCrossScopeLeaks", "newStaleMemoryUses"} <= set(shadow["required"]), "shadow pass metrics are machine-readable")
    budget = schema["$defs"]["contextBudgetDecision"]
    record("schema.budget_complete_receipt", {"coverageMillionths", "marginalUtilityThresholdMillionths", "stoppingReason", "policySnapshotDigest", "maxBudgetTokens", "reservedOutputTokens", "reservedVerificationTokens"} <= set(budget["required"]), "budget receipt is complete")
    usage = schema["$defs"]["memoryUsageEvent"]
    record("schema.usage_matches_sql", {"retrieved", "included", "cited", "usedInConclusion", "retrievalCandidateId", "contextPackageItemId"} <= set(usage["properties"]), "usage event carries exact linkage and state")
    origin = schema["$defs"]["memoryOriginRecord"]
    record("schema.origin_has_actor_and_evidence", {"originActorKind", "originActorId", "originActorBindingDigest", "evidence"} <= set(origin["required"]), "origin authority is actor-bound and evidenced")

    con = db()
    record("sqlite.v5_integrity", con.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "clean install integrity_check=ok")
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required_tables = {"state_resolution_conflicts", "memory_origin_records", "benchmark_run_arms", "benchmark_run_memory_bindings"}
    record("sqlite.v5_new_tables", required_tables <= tables, f"{len(required_tables & tables)}/{len(required_tables)} tables present")
    receipt_columns = {r[1] for r in con.execute("PRAGMA table_info(state_resolution_receipts)")}
    record("sqlite.state_receipt_conflict_link", "conflict_id" in receipt_columns, "resolution receipt has an explicit conflict foreign key")
    con.close()

    clean = db(); migrated = migrated_db()
    clean_cols = {t: [tuple(r) for r in clean.execute(f"PRAGMA table_info({t})")] for t in required_tables | {"memory_shadow_evaluations", "memory_usage_events", "context_budget_decisions"}}
    migrated_cols = {t: [tuple(r) for r in migrated.execute(f"PRAGMA table_info({t})")] for t in clean_cols}
    clean_objects = {(r[0], r[1]) for r in clean.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    migrated_objects = {(r[0], r[1]) for r in migrated.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    record("sqlite.v4_to_v5_equivalent", clean_cols == migrated_cols and clean_objects == migrated_objects, f"{len(clean_objects)} clean objects / {len(migrated_objects)} migrated objects")
    clean.close(); migrated.close()

    con = v4_db()
    con.execute(
        """INSERT INTO state_records(id,project_id,task_id,state_key,scope_kind,scope_id,authority_kind,precedence_rank,value_json,source_artifact_id,source_digest,status,valid_from,valid_until,supersedes_state_id,created_at,status_changed_at,retracted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("legacy-expired", "p1", "t1", "legacy.key", "task", "t1", "task_override", 500, '{"value":"old"}', "a1", SHA, "expired", T0, T2, None, T0, T2, None),
    )
    con.executescript((SC / "migrate-v4-to-v5.sql").read_text(encoding="utf-8"))
    record("migration.terminal_state_backfills_ended_at", con.execute("SELECT ended_at FROM state_records WHERE id='legacy-expired'").fetchone()[0] == T2, "legacy terminal state keeps its lifecycle timestamp")
    con.close()

    blocked("state.new_record_must_be_active", lambda c: insert_state(c, "s1", status="expired", valid_until=T2), "new state must start active")
    blocked("state.expired_candidate_rejected", lambda c: (
        insert_state(c, "s1", valid_until=T2),
        c.execute("INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("sr1", "p1", "t1", "user.output.language", "s1", '[\"s1\"]', "v2", "a1", SHA, T3, SHA)),
    ), "state resolution candidate is not valid")
    blocked("state.future_candidate_rejected", lambda c: (
        insert_state(c, "s1", valid_from=T4),
        c.execute("INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("sr1", "p1", "t1", "user.output.language", "s1", '[\"s1\"]', "v2", "a1", SHA, T3, SHA)),
    ), ("state resolution candidate is not valid", "new active state must be valid at creation time"))
    blocked("state.duplicate_candidates_rejected", lambda c: (
        insert_state(c, "s1"),
        c.execute("INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("sr1", "p1", "t1", "user.output.language", "s1", '[\"s1\",\"s1\"]', "v2", "a1", SHA, T2, SHA)),
    ), "candidate state ids must be unique")
    blocked("state.equal_rank_conflict_not_silently_resolved", lambda c: (
        insert_state(c, "s1", value="vi", scope_kind="task", scope_id="t1"),
        insert_state(c, "s2", value="en", scope_kind="communication-surface", scope_id="chat", task_id="t1"),
        c.execute("INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("sr1", "p1", "t1", "user.output.language", "s1", '[\"s1\",\"s2\"]', "v2", "a1", SHA, T2, SHA)),
    ), ("equal-precedence conflict requires conflict receipt", "conflict resolution receipt requires explicit conflict link"))
    blocked("state.conflict_resolution_requires_explicit_link", lambda c: (
        insert_state(c, "s1", value="vi", scope_kind="task", scope_id="t1"),
        insert_state(c, "s2", value="en", scope_kind="communication-surface", scope_id="chat", task_id="t1"),
        c.execute("INSERT INTO state_resolution_conflicts(id,project_id,task_id,state_key,candidate_state_ids_json,precedence_rank,evidence_artifact_id,evidence_digest,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", ("sc1", "p1", "t1", "user.output.language", '["s1","s2"]', 600, "a1", SHA, "open", T2)),
        c.execute("INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("sr-unlinked", "p1", "t1", "user.output.language", "s1", '["s1","s2"]', "v2", "a1", SHA, T3, SHA)),
    ), ("equal-precedence conflict requires conflict receipt", "conflict resolution receipt requires explicit conflict link"))
    blocked("state.conflict_has_single_resolution_receipt", lambda c: (
        insert_state(c, "s1", value="vi", scope_kind="task", scope_id="t1"),
        insert_state(c, "s2", value="en", scope_kind="communication-surface", scope_id="chat", task_id="t1"),
        c.execute("INSERT INTO state_resolution_conflicts(id,project_id,task_id,state_key,candidate_state_ids_json,precedence_rank,evidence_artifact_id,evidence_digest,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", ("sc1", "p1", "t1", "user.output.language", '["s1","s2"]', 600, "a1", SHA, "open", T2)),
        c.execute("INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest,conflict_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("sr-first", "p1", "t1", "user.output.language", "s1", '["s1","s2"]', "v2", "a1", SHA, T3, SHA, "sc1")),
        c.execute("INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest,conflict_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("sr-second", "p1", "t1", "user.output.language", "s2", '["s1","s2"]', "v2", "a1", SHA, T4, SHA, "sc1")),
    ), "UNIQUE constraint failed: state_resolution_receipts.conflict_id")
    con = db(); insert_state(con, "s1", value="vi", scope_kind="task", scope_id="t1"); insert_state(con, "s2", value="en", scope_kind="communication-surface", scope_id="chat", task_id="t1")
    con.execute("INSERT INTO state_resolution_conflicts(id,project_id,task_id,state_key,candidate_state_ids_json,precedence_rank,evidence_artifact_id,evidence_digest,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", ("sc1", "p1", "t1", "user.output.language", '[\"s1\",\"s2\"]', 600, "a1", SHA, "open", T2))
    record("state.conflict_receipt_persists", con.execute("SELECT status FROM state_resolution_conflicts WHERE id='sc1'").fetchone()[0] == "open", "explicit conflict recorded")
    try:
        con.execute("""INSERT INTO state_resolution_receipts(id,project_id,task_id,state_key,winning_state_id,candidate_state_ids_json,resolution_rule_version,result_artifact_id,result_digest,created_at,policy_snapshot_digest,conflict_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", ("sr-resolve", "p1", "t1", "user.output.language", "s1", '["s1","s2"]', "v2", "a1", SHA, T3, SHA, "sc1"))
        con.execute("UPDATE state_resolution_conflicts SET status='resolved',resolution_receipt_id='sr-resolve',resolved_at=? WHERE id='sc1'", (T3,))
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        record("state.recorded_conflict_can_be_resolved", False, str(exc))
    else:
        record("state.recorded_conflict_can_be_resolved", con.execute("SELECT status FROM state_resolution_conflicts WHERE id='sc1'").fetchone()[0] == "resolved", "recorded equal-rank conflict accepts an explicit resolution receipt")
    con.close()
    blocked("state.project_conflict_cannot_mix_task_candidates", lambda c: (
        seed_task3(c),
        insert_state(c, "s1", value="vi", task_id="t1", scope_kind="task", scope_id="t1"),
        insert_state(c, "s3", value="en", task_id="t3", scope_kind="task", scope_id="t3", source_artifact_id="a3"),
        c.execute("INSERT INTO state_resolution_conflicts(id,project_id,task_id,state_key,candidate_state_ids_json,precedence_rank,evidence_artifact_id,evidence_digest,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", ("sc-cross", "p1", None, "user.output.language", '["s1","s3"]', 600, "a1", SHA, "open", T2)),
    ), "state conflict candidates are incoherent")
    blocked("state.lifecycle_time_set_once", lambda c: (insert_state(c, "s1"), c.execute("UPDATE state_records SET status_changed_at=? WHERE id='s1'", (T2,))), "lifecycle fields change only with status")
    blocked("state.terminal_requires_ended_at", lambda c: (insert_state(c, "s1"), c.execute("UPDATE state_records SET status='expired',status_changed_at=? WHERE id='s1'", (T2,))), "terminal state requires ended_at")

    blocked("invalidation.unknown_kind_rejected", lambda c: (
        c.execute("""INSERT INTO memory_records(id,project_id,logical_key,origin_task_id,origin_run_id,memory_type,version,status,content_artifact_id,applicability_json,invalidation_conditions_json,confidence_millionths,sensitivity,expires_at,created_at,status_changed_at,activated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  ("m1", "p1", "k", "t1", "r1", "negative", 1, "candidate", "a1", '{"summary":"x","scope":{"kind":"project","id":"p1"}}', rules(kind="unknown_kind"), 1, "internal", None, T1, T1, None)),
    ), "unsupported invalidation rule kind")
    blocked("invalidation.duplicate_rule_ids_rejected", lambda c: (
        c.execute("""INSERT INTO memory_records(id,project_id,logical_key,origin_task_id,origin_run_id,memory_type,version,status,content_artifact_id,applicability_json,invalidation_conditions_json,confidence_millionths,sensitivity,expires_at,created_at,status_changed_at,activated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  ("m1", "p1", "k", "t1", "r1", "negative", 1, "candidate", "a1", '{"summary":"x","scope":{"kind":"project","id":"p1"}}', '[' + rules()[1:-1] + ',' + rules()[1:-1] + ']', 1, "internal", None, T1, T1, None)),
    ), "invalidation rule ids must be unique")
    blocked("invalidation.kind_shape_rejected", lambda c: (
        c.execute("""INSERT INTO memory_records(id,project_id,logical_key,origin_task_id,origin_run_id,memory_type,version,status,content_artifact_id,applicability_json,invalidation_conditions_json,confidence_millionths,sensitivity,expires_at,created_at,status_changed_at,activated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  ("m1", "p1", "k", "t1", "r1", "negative", 1, "candidate", "a1", '{"summary":"x","scope":{"kind":"project","id":"p1"}}', '[{"ruleId":"ir1","kind":"source_hash_changed","target":{},"expected":{},"cadence":"before_retrieval","explanation":"x"}]', 1, "internal", None, T1, T1, None)),
    ), "invalidation rule payload does not match kind")

    blocked("origin.evidence_required", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_origin_records(id,memory_id,project_id,origin_kind,origin_actor_kind,origin_actor_id,created_at) VALUES (?,?,?,?,?,?,?)", ("origin-bad", "m1", "p1", "model_generated", "agent", "agent-1", T1)),
    ), ("memory origin must be recorded while candidate", "NOT NULL constraint failed"))
    blocked("origin.actor_kind_must_match_origin", lambda c: (
        insert_memory(c),
        insert_origin(c, origin_kind="user_explicit", actor_kind="agent"),
    ), "memory origin actor kind is incoherent")
    blocked("origin.required_before_verification", lambda c: (
        insert_memory(c),
        verify_memory(c),
    ), "verified memory requires immutable origin record")
    blocked("origin.binding_digest_must_be_valid", lambda c: (
        insert_memory(c),
        insert_origin(c, actor_binding_digest="bad"),
    ), ("CHECK constraint failed", "origin actor binding digest"))

    blocked("retrieval.future_evaluation_rejected", lambda c: (
        insert_memory(c), activate_user_approved(c), insert_retrieval(c),
        c.execute("INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ie1", "m1", "p1", "t1", "ir1", "passed", "a1", SHA, T8, None)),
        c.execute("INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("rc1", "rs1", "p1", "memory", None, None, None, "m1", "memory:1", SHA, 1, 900000, '[\"exact\"]', "a1", "current", 1)),
    ), "retrieval memory lacks applicable current passing invalidation evidence")
    blocked("retrieval.task_evaluation_cannot_cross_task", lambda c: (
        insert_memory(c), activate_user_approved(c),
        c.execute("INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ie1", "m1", "p1", "t1", "ir1", "passed", "a1", SHA, T3, T8)),
        seed_task3(c),
        c.execute("INSERT INTO retrieval_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("rs3", "p1", "t3", "r3", None, "a3", "a3", "hybrid", "1", "v5", "running", "{}", None, None, T7, None)),
        c.execute("INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("rc3", "rs3", "p1", "memory", None, None, None, "m1", "memory:1", SHA, 1, 900000, '[\"exact\"]', "a3", "current", 1)),
    ), "retrieval memory lacks applicable current passing invalidation evidence")
    con = db(); insert_memory(con); activate_user_approved(con); seed_task3(con)
    con.execute("INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ie-unrelated", "m1", "p1", "t1", "ir1", "failed", "a1", SHA, T6, T8))
    con.execute("INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ie-task3", "m1", "p1", "t3", "ir1", "passed", "a3", SHA, T5, T8))
    con.execute("INSERT INTO retrieval_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("rs3", "p1", "t3", "r3", None, "a3", "a3", "hybrid", "1", "v5", "running", "{}", None, None, T7, None))
    con.execute("INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("rc3", "rs3", "p1", "memory", None, None, None, "m1", "memory:1", SHA, 1, 900000, '[\"exact\"]', "a3", "current", 1))
    record("retrieval.project_memory_accepts_current_task_evaluation", con.execute("SELECT id FROM retrieval_candidates WHERE id='rc3'").fetchone()[0] == "rc3", "task-specific passing evidence applies without unrelated-task overblocking")
    con.close()
    blocked("context.memory_requires_selected_candidate", lambda c: (
        insert_memory(c), activate_user_approved(c),
        c.execute("INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ie1", "m1", "p1", "t1", "ir1", "passed", "a1", SHA, T3, T8)),
        c.execute("INSERT INTO context_package_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ci1", "cp1", "p1", "t1", None, "experience", "memory", None, None, None, "m1", "memory:1", SHA, "a1", "verified_memory", 10, 0)),
    ), ("experience memory requires selected retrieval candidate", "experience memory candidate must belong to package run"))
    blocked("context.memory_candidate_must_match_package_run", lambda c: (
        insert_memory(c), activate_user_approved(c),
        c.execute("INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ie1", "m1", "p1", "t1", "ir1", "passed", "a1", SHA, T3, T8)),
        insert_retrieval(c),
        c.execute("INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("rc1", "rs1", "p1", "memory", None, None, None, "m1", "memory:1", SHA, 1, 900000, '["exact"]', "a1", "current", 1)),
        c.execute("INSERT INTO artifacts(id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,supersedes,verification_state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("a4", "t1", "p1", "context", "a4", SHA, "a4", 1, "application/json", "available", "core", "core", T1, None, "hash_verified")),
        c.execute("INSERT INTO context_packages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("cp4", "t1", "core-agent", "implementer", "Objective", "a4", "a4", SHA, SHA, "1", "1", T1)),
        c.execute("INSERT INTO agent_runs(id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id) VALUES (?,?,?,?,?,?,?,?,?,?)", ("r4", "t1", "core-agent", "implementer", "Implementation", "running", "cp4", "run-key-4", SHA, "a4")),
        c.execute("INSERT INTO context_package_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ci-cross", "cp4", "p1", "t1", "rc1", "experience", "memory", None, None, None, "m1", "memory:1", SHA, "a4", "verified_memory", 10, 0)),
    ), "experience memory candidate must belong to package run")

    blocked("usage.included_requires_exact_candidate_link", lambda c: (
        insert_memory(c), activate_user_approved(c),
        c.execute("INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)", ("ie1", "m1", "p1", "t1", "ir1", "passed", "a1", SHA, T3, T8)),
        insert_retrieval(c),
        c.execute("INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("rc1", "rs1", "p1", "memory", None, None, None, "m1", "memory:1", SHA, 1, 900000, '["exact"]', "a1", "current", 1)),
        c.execute("INSERT INTO context_package_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ci1", "cp1", "p1", "t1", "rc1", "experience", "memory", None, None, None, "m1", "memory:1", SHA, "a1", "verified_memory", 10, 0)),
        c.execute("INSERT INTO memory_usage_events(id,memory_id,project_id,task_id,run_id,event_type,retrieved,included,cited,used_in_conclusion,helpfulness_millionths,token_cost,evidence_artifact_id,evidence_digest,created_at,position,outcome_delta_millionths,retrieval_candidate_id,context_package_item_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("mu-included", "m1", "p1", "t1", "r1", "included", 1, 1, 0, 0, None, 10, "a1", SHA, T8, 1, None, None, "ci1")),
    ), "included usage requires exact retrieval candidate and context item")

    blocked("shadow.arm_configuration_bound", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bsx", "p1", 3, "a1", SHA, T1)),
        c.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bcx", "bsx", 1, "a1", "x", SHA, T1)),
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("bx", "bcx", "t1", SHA, SHA, "a1", "completed", T1, T2)),
        c.execute("INSERT INTO benchmark_run_arms VALUES (?,?,?,?,?,?,?)", ("ax", "bx", "control_no_memory", SHA2, SHA, SHA, T2)),
    ), "benchmark run arm scope or configuration is incoherent")

    blocked("shadow.arm_binding_required", lambda c: (
        insert_memory(c), insert_origin(c), verify_memory(c),
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs", "p1", 3, "a1", SHA, T1)),
        c.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc", "bs", 1, "a1", "x", SHA, T1)),
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("b1", "bc", "t1", SHA, SHA, "a1", "completed", T1, T2)),
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("b2", "bc", "t1", SHA, SHA, "a1", "completed", T1, T2)),
        c.execute("INSERT INTO memory_shadow_evaluations(id,memory_id,project_id,task_id,control_arm,candidate_arm,control_run_id,candidate_run_id,result,quality_delta_millionths,new_forbidden_mistakes,new_unsupported_claims,new_cross_scope_leaks,new_stale_memory_uses,evidence_artifact_id,evidence_digest,evaluated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("se1", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "b1", "b2", "passed", 1, 0, 0, 0, 0, "a1", SHA, T3)),
    ), "shadow evaluation run arms or memory binding are incoherent")
    blocked("shadow.passed_cross_scope_rejected", lambda c: (
        insert_memory(c), insert_origin(c), verify_memory(c), insert_benchmark_runs(c),
        c.execute("INSERT INTO memory_shadow_evaluations(id,memory_id,project_id,task_id,control_arm,candidate_arm,control_run_id,candidate_run_id,result,quality_delta_millionths,new_forbidden_mistakes,new_unsupported_claims,new_cross_scope_leaks,new_stale_memory_uses,evidence_artifact_id,evidence_digest,evaluated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("se1", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "br-control", "br-candidate", "passed", 1, 0, 0, 1, 0, "a1", SHA, T3)),
    ), "passing shadow evaluation cannot introduce regressions")
    blocked("shadow.evaluated_at_unique_per_memory", lambda c: (
        insert_memory(c), insert_origin(c), verify_memory(c), insert_benchmark_runs(c),
        c.execute("INSERT INTO memory_shadow_evaluations(id,memory_id,project_id,task_id,control_arm,candidate_arm,control_run_id,candidate_run_id,result,quality_delta_millionths,new_forbidden_mistakes,new_unsupported_claims,new_cross_scope_leaks,new_stale_memory_uses,evidence_artifact_id,evidence_digest,evaluated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("se1", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "br-control", "br-candidate", "passed", 1, 0, 0, 0, 0, "a1", SHA, T3)),
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-control-same", "bc-v411", "t1", SHA, SHA, "a1", "completed", T2, T3)),
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-candidate-same", "bc-v411", "t1", SHA, SHA, "a1", "completed", T2, T3)),
        c.execute("INSERT INTO benchmark_run_arms VALUES (?,?,?,?,?,?,?)", ("arm-c-same", "br-control-same", "control_no_memory", SHA, SHA, SHA, T3)),
        c.execute("INSERT INTO benchmark_run_arms VALUES (?,?,?,?,?,?,?)", ("arm-d-same", "br-candidate-same", "evidence_plus_experience", SHA, SHA, SHA, T3)),
        c.execute("INSERT INTO benchmark_run_memory_bindings VALUES (?,?,?,?,?)", ("bind-same", "br-candidate-same", "m1", "available", T3)),
        c.execute("INSERT INTO memory_shadow_evaluations(id,memory_id,project_id,task_id,control_arm,candidate_arm,control_run_id,candidate_run_id,result,quality_delta_millionths,new_forbidden_mistakes,new_unsupported_claims,new_cross_scope_leaks,new_stale_memory_uses,evidence_artifact_id,evidence_digest,evaluated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("se2", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "br-control-same", "br-candidate-same", "failed", -1, 1, 0, 0, 0, "a1", SHA, T3)),
    ), "shadow evaluation time must be unique per memory")
    blocked("shadow.latest_result_controls_promotion", lambda c: (
        insert_memory(c), insert_origin(c), verify_memory(c), insert_benchmark_runs(c),
        c.execute("INSERT INTO memory_shadow_evaluations(id,memory_id,project_id,task_id,control_arm,candidate_arm,control_run_id,candidate_run_id,result,quality_delta_millionths,new_forbidden_mistakes,new_unsupported_claims,new_cross_scope_leaks,new_stale_memory_uses,evidence_artifact_id,evidence_digest,evaluated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("se1", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "br-control", "br-candidate", "passed", 1, 0, 0, 0, 0, "a1", SHA, T3)),
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-control2", "bc-v411", "t1", SHA, SHA, "a1", "completed", T3, T4)),
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-candidate2", "bc-v411", "t1", SHA, SHA, "a1", "completed", T3, T4)),
        c.execute("INSERT INTO benchmark_run_arms VALUES (?,?,?,?,?,?,?)", ("arm-c2", "br-control2", "control_no_memory", SHA, SHA, SHA, T4)),
        c.execute("INSERT INTO benchmark_run_arms VALUES (?,?,?,?,?,?,?)", ("arm-d2", "br-candidate2", "evidence_plus_experience", SHA, SHA, SHA, T4)),
        c.execute("INSERT INTO benchmark_run_memory_bindings VALUES (?,?,?,?,?)", ("bind2", "br-candidate2", "m1", "available", T4)),
        c.execute("INSERT INTO memory_shadow_evaluations(id,memory_id,project_id,task_id,control_arm,candidate_arm,control_run_id,candidate_run_id,result,quality_delta_millionths,new_forbidden_mistakes,new_unsupported_claims,new_cross_scope_leaks,new_stale_memory_uses,evidence_artifact_id,evidence_digest,evaluated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("se2", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "br-control2", "br-candidate2", "failed", -1, 1, 0, 0, 0, "a1", SHA, T5)),
        c.execute("INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)", ("pr1", "m1", "p1", "policy", "p", "granted", "a1", SHA, T6)),
    ), "latest shadow evaluation must pass")
    con = v4_db(); insert_memory(con); verify_memory(con)
    con.executescript((SC / "migrate-v4-to-v5.sql").read_text(encoding="utf-8"))
    try:
        insert_origin(con, origin_kind="user_explicit", actor_id="u1", created_at=T4)
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        record("origin.legacy_verified_memory_cannot_be_reclassified", "memory origin must be recorded while candidate" in str(exc), str(exc))
    else:
        record("origin.legacy_verified_memory_cannot_be_reclassified", False, "legacy verified memory accepted a new origin exemption")
    con.close()

    con = v4_db(); insert_memory(con); verify_memory(con)
    con.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("legacy-bs", "p1", 2, "a1", SHA, T1))
    con.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("legacy-bc", "legacy-bs", 1, "a1", "legacy", SHA, T1))
    con.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("legacy-control", "legacy-bc", "t1", SHA, SHA, "a1", "completed", T1, T2))
    con.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("legacy-candidate", "legacy-bc", "t1", SHA, SHA, "a1", "completed", T1, T2))
    con.execute("INSERT INTO memory_shadow_evaluations(id,memory_id,project_id,task_id,control_arm,candidate_arm,control_run_id,candidate_run_id,result,quality_delta_millionths,new_forbidden_mistakes,new_unsupported_claims,evidence_artifact_id,evidence_digest,evaluated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("legacy-shadow", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "legacy-control", "legacy-candidate", "passed", 1, 0, 0, "a1", SHA, T3))
    con.executescript((SC / "migrate-v4-to-v5.sql").read_text(encoding="utf-8"))
    try:
        con.execute("INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)", ("legacy-pr", "m1", "p1", "policy", "p", "granted", "a1", SHA, T5))
    except sqlite3.IntegrityError as exc:
        record("shadow.legacy_unbound_evaluation_cannot_promote", "latest shadow evaluation must pass" in str(exc), str(exc))
    else:
        record("shadow.legacy_unbound_evaluation_cannot_promote", False, "legacy unbound shadow evaluation was accepted")
    con.close()

    con = db(); insert_memory(con); insert_origin(con, origin_kind="user_explicit", actor_id="u1"); verify_memory(con); con.execute("INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)", ("pr1", "m1", "p1", "policy", "p", "granted", "a1", SHA, T3)); record("shadow.user_explicit_policy_review_no_shadow", con.execute("SELECT decision FROM memory_promotion_reviews WHERE id='pr1'").fetchone()[0] == "granted", "origin-aware gate does not over-require shadow") ; con.close()

    blocked("usage.retrieved_requires_candidate_link", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_usage_events(id,memory_id,project_id,task_id,run_id,event_type,retrieved,included,cited,used_in_conclusion,helpfulness_millionths,token_cost,evidence_artifact_id,evidence_digest,created_at,position,outcome_delta_millionths,retrieval_candidate_id,context_package_item_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("mu1", "m1", "p1", "t1", "r1", "retrieved", 1, 0, 0, 0, None, 10, "a1", SHA, T2, 1, None, None, None)),
    ), "retrieved usage requires matching retrieval candidate")
    blocked("usage.flag_implication_enforced", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_usage_events(id,memory_id,project_id,task_id,run_id,event_type,retrieved,included,cited,used_in_conclusion,helpfulness_millionths,token_cost,evidence_artifact_id,evidence_digest,created_at,position,outcome_delta_millionths,retrieval_candidate_id,context_package_item_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("mu1", "m1", "p1", "t1", "r1", "cited", 0, 0, 1, 0, None, 10, "a1", SHA, T2, 1, None, None, None)),
    ), "memory usage flags are incoherent")

    blocked("usage.helpful_requires_included", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_usage_events(id,memory_id,project_id,task_id,run_id,event_type,retrieved,included,cited,used_in_conclusion,helpfulness_millionths,token_cost,evidence_artifact_id,evidence_digest,created_at,position,outcome_delta_millionths,retrieval_candidate_id,context_package_item_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("mu1", "m1", "p1", "t1", "r1", "helpful", 1, 0, 0, 0, 100, 10, "a1", SHA, T2, 1, None, None, None)),
    ), "memory usage event type does not match flags")

    blocked("consolidation.merge_requires_two_inputs", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_consolidation_actions VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("ca1", "p1", "merge", '[\"m1\"]', None, "proposed", "a1", SHA, "policy", T2, None)),
    ), "consolidation action shape is incoherent")
    blocked("consolidation.split_deferred", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_consolidation_actions VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("ca1", "p1", "split", '[\"m1\"]', None, "proposed", "a1", SHA, "policy", T2, None)),
    ), "consolidation action shape is incoherent")
    blocked("consolidation.applied_effect_required", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_consolidation_actions VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("ca1", "p1", "mark_stale", '[\"m1\"]', None, "proposed", "a1", SHA, "policy", T2, None)),
        c.execute("UPDATE memory_consolidation_actions SET status='approved' WHERE id='ca1'"),
        c.execute("UPDATE memory_consolidation_actions SET status='applied',applied_at=? WHERE id='ca1'", (T3,)),
    ), "mark_stale consolidation effect is not applied")
    blocked("consolidation.applied_at_set_once", lambda c: (
        insert_memory(c),
        c.execute("INSERT INTO memory_consolidation_actions VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("ca1", "p1", "retain", '[\"m1\"]', None, "proposed", "a1", SHA, "policy", T2, None)),
        c.execute("UPDATE memory_consolidation_actions SET status='approved' WHERE id='ca1'"),
        c.execute("UPDATE memory_consolidation_actions SET status='applied',applied_at=? WHERE id='ca1'", (T3,)),
        c.execute("UPDATE memory_consolidation_actions SET applied_at=? WHERE id='ca1'", (T4,)),
    ), "consolidation applied time is set-once")

    budget_sql = """INSERT INTO context_budget_decisions(id,project_id,task_id,run_id,context_package_id,task_class,risk_level,allocations_json,total_allocated_tokens,strategy_version,coverage_millionths,marginal_utility_threshold_millionths,stopping_reason,evidence_artifact_id,evidence_digest,policy_snapshot_digest,created_at,max_budget_tokens,reserved_output_tokens,reserved_verification_tokens) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    blocked(
        "budget.real_allocation_rejected",
        lambda c: c.execute(budget_sql, ("bd1", "p1", "t1", "r1", "cp1", "bug", "medium", '{"evidence":1.5}', 1, "v2", 1, 1, "policy_limit", "a1", SHA, SHA, T2, 100, 10, 10)),
        "context budget allocations must be non-negative integers",
    )
    blocked(
        "budget.reserve_overflow_rejected",
        lambda c: c.execute(budget_sql, ("bd1", "p1", "t1", "r1", "cp1", "bug", "medium", '{"evidence":90}', 90, "v2", 1, 1, "policy_limit", "a1", SHA, SHA, T2, 100, 10, 10)),
        "context budget exceeds declared token budget",
    )

    passed = sum(checks)
    print(f"\n{passed}/{len(checks)} v4.1.1 loop-review checks passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
