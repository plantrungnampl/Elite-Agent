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
from validate_v3 import LATER, NOW, SHA_A as SHA, SHA_B as SHA2, seed  # noqa: E402

T1 = "2026-08-04T08:10:00Z"
T2 = "2026-08-04T08:20:00Z"
T3 = "2026-08-04T08:30:00Z"
T4 = "2026-08-04T08:40:00Z"
T5 = "2026-08-04T08:50:00Z"
T6 = "2026-08-04T09:00:00Z"
T7 = "2026-08-04T09:10:00Z"

checks: list[bool] = []


def record(name: str, ok: bool, detail: str) -> None:
    checks.append(ok)
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v3.sql").read_text(encoding="utf-8"))
    seed(con)
    return con


def blocked(
    name: str,
    fn: Callable[[sqlite3.Connection], None],
    contains: str | tuple[str, ...],
) -> None:
    con = db()
    try:
        fn(con)
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        needles = (contains,) if isinstance(contains, str) else contains
        ok = any(needle in str(exc) for needle in needles)
        record(name, ok, str(exc))
    else:
        record(name, False, "unsafe operation succeeded")
    finally:
        con.close()


def blocked_in(
    name: str,
    connection_factory: Callable[[], sqlite3.Connection],
    fn: Callable[[sqlite3.Connection], None],
    contains: str | tuple[str, ...],
) -> None:
    con = connection_factory()
    try:
        fn(con)
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        needles = (contains,) if isinstance(contains, str) else contains
        ok = any(needle in str(exc) for needle in needles)
        record(name, ok, str(exc))
    else:
        record(name, False, "unsafe operation succeeded")
    finally:
        con.close()


def migrated_db_with_legacy_memory() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v2.sql").read_text(encoding="utf-8"))
    seed(con)
    con.execute(
        "INSERT INTO memory_entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "me1",
            "p1",
            "semantic",
            "rejected",
            "a1",
            "[]",
            "legacy-manual",
            None,
            500000,
            None,
            NOW,
            None,
        ),
    )
    con.executescript((SC / "migrate-v2-to-v3.sql").read_text(encoding="utf-8"))
    return con


def terminal(con: sqlite3.Connection, run_id: str = "r1", status: str = "succeeded") -> None:
    con.execute(
        "UPDATE agent_runs SET status=?,completed_at=? WHERE id=?",
        (status, NOW, run_id),
    )


def insert_memory(
    con: sqlite3.Connection,
    *,
    memory_id: str = "m1",
    project_id: str = "p1",
    logical_key: str = "qrqc.warning.identity",
    task_id: str | None = "t1",
    run_id: str | None = "r1",
    memory_type: str = "negative",
    version: int = 1,
    status: str = "candidate",
    artifact_id: str = "a1",
    expires_at: str | None = None,
    created_at: str = NOW,
    applicability_json: str | None = None,
) -> None:
    applicability = applicability_json or json.dumps({
        "summary": "QRQC warning identity mapping",
        "scope": {"kind": "project", "id": project_id},
        "systems": ["qrqc"],
    }, separators=(",", ":"))
    con.execute(
        """INSERT INTO memory_records(
        id,project_id,logical_key,origin_task_id,origin_run_id,memory_type,version,
        status,content_artifact_id,applicability_json,invalidation_conditions_json,
        confidence_millionths,sensitivity,expires_at,created_at,status_changed_at,activated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            memory_id,
            project_id,
            logical_key,
            task_id,
            run_id,
            memory_type,
            version,
            status,
            artifact_id,
            applicability,
            '["data model changes"]',
            900000,
            "internal-code",
            expires_at,
            created_at,
            created_at,
            None,
        ),
    )


def add_evidence(
    con: sqlite3.Connection,
    memory_id: str = "m1",
    artifact_id: str = "a1",
    digest: str = SHA,
    *,
    evidence_id: str | None = None,
    created_at: str = NOW,
) -> None:
    con.execute(
        """INSERT INTO memory_evidence_links(
        id,memory_id,project_id,evidence_kind,artifact_id,source_document_id,
        source_chunk_id,evidence_digest,relationship,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            evidence_id or f"e-{memory_id}",
            memory_id,
            "p1",
            "artifact",
            artifact_id,
            None,
            None,
            digest,
            "verifies",
            created_at,
        ),
    )


def grant_review(
    con: sqlite3.Connection,
    memory_id: str = "m1",
    *,
    review_id: str | None = None,
    decided_at: str = T2,
) -> None:
    con.execute(
        """INSERT INTO memory_promotion_reviews(
        id,memory_id,project_id,reviewer_kind,reviewer_id,decision,
        evidence_artifact_id,decision_digest,decided_at
        ) VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            review_id or f"pr-{memory_id}",
            memory_id,
            "p1",
            "deterministic",
            "validator",
            "granted",
            "a1",
            SHA,
            decided_at,
        ),
    )


def transition_memory(
    con: sqlite3.Connection,
    memory_id: str,
    status: str,
    changed_at: str,
    *,
    activated_at: str | None = None,
) -> None:
    if activated_at is None:
        con.execute(
            "UPDATE memory_records SET status=?,status_changed_at=? WHERE id=?",
            (status, changed_at, memory_id),
        )
    else:
        con.execute(
            "UPDATE memory_records SET status=?,status_changed_at=?,activated_at=? WHERE id=?",
            (status, changed_at, activated_at, memory_id),
        )


def activate_memory(
    con: sqlite3.Connection,
    memory_id: str = "m1",
    *,
    evidence_at: str = NOW,
    verified_at: str = T1,
    review_at: str = T2,
    active_at: str = T3,
) -> None:
    add_evidence(con, memory_id, created_at=evidence_at)
    transition_memory(con, memory_id, "verified", verified_at)
    grant_review(con, memory_id, decided_at=review_at)
    transition_memory(con, memory_id, "approved", review_at)
    transition_memory(con, memory_id, "active", active_at, activated_at=active_at)


def start_retrieval(con: sqlite3.Connection, session_id: str = "rs1") -> None:
    con.execute(
        """INSERT INTO retrieval_sessions(
        id,project_id,task_id,run_id,index_generation_id,query_artifact_id,
        plan_artifact_id,engine_id,engine_version,pipeline_version,status,
        branch_status_json,trace_artifact_id,trace_digest,started_at,completed_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (session_id, "p1", "t1", "r1", None, "a1", "a1", "embedded", "1", "v1", "running", "{}", None, None, NOW, None),
    )


def add_artifact_candidate(con: sqlite3.Connection, candidate_id: str = "rc1", artifact_id: str = "a1") -> None:
    con.execute(
        """INSERT INTO retrieval_candidates(
        id,retrieval_session_id,project_id,source_kind,artifact_id,source_document_id,
        source_chunk_id,memory_id,source_revision,source_hash,rank_position,
        score_millionths,methods_json,reason_artifact_id,freshness,selected
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (candidate_id, "rs1", "p1", "artifact", artifact_id, None, None, None, "artifact:v1", SHA, 1, 900000, '["exact"]', "a1", "current", 1),
    )


def add_context_item(con: sqlite3.Connection, *, item_id: str = "ci1", candidate_id: str | None = None, artifact_id: str = "a1") -> None:
    con.execute(
        """INSERT INTO context_package_items(
        id,context_package_id,project_id,task_id,retrieval_candidate_id,category,
        source_kind,source_artifact_id,source_document_id,source_chunk_id,memory_id,
        source_revision,source_hash,inclusion_reason_artifact_id,authority_state,
        token_count,redacted
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (item_id, "cp1", "p1", "t1", candidate_id, "repository-evidence", "artifact", artifact_id, None, None, None, "artifact:v1", SHA, "a1", "authoritative", 20, 0),
    )


def schema_examples() -> None:
    cognitive = json.loads((SC / "cognitive-memory.v1.schema.json").read_text(encoding="utf-8"))
    benchmark = json.loads((SC / "agent-quality-benchmark.v1.schema.json").read_text(encoding="utf-8"))
    mapping = {
        "retrieval-request.example.json": "retrievalRequest",
        "memory-proposal.example.json": "memoryProposal",
        "context-package.example.json": "contextPackage",
        "run-evaluation.example.json": "runEvaluation",
        "context-supplement-request.example.json": "contextSupplementRequest",
        "working-memory-event.example.json": "workingMemoryEvent",
        "run-reflection.example.json": "runReflection",
    }
    for filename, definition in mapping.items():
        instance = json.loads((SC / "examples-v4" / filename).read_text(encoding="utf-8"))
        target = {
            "$schema": cognitive["$schema"],
            "$defs": cognitive["$defs"],
            "$ref": f"#/$defs/{definition}",
        }
        errors = list(Draft202012Validator(target).iter_errors(instance))
        record(f"schema.{filename}", not errors, "valid" if not errors else errors[0].message)
    def expect_invalid(name: str, definition: str, instance: dict, contains: str) -> None:
        target = {
            "$schema": cognitive["$schema"],
            "$defs": cognitive["$defs"],
            "$ref": f"#/$defs/{definition}",
        }
        errors = list(Draft202012Validator(target).iter_errors(instance))
        messages = " | ".join(error.message for error in errors)
        record(name, bool(errors) and contains in messages, messages or "invalid fixture was accepted")

    invalid_preference = json.loads((SC / "examples-v4" / "memory-proposal.example.json").read_text(encoding="utf-8"))
    invalid_preference["memoryType"] = "preference"
    invalid_preference.pop("subject", None)
    expect_invalid("schema.preference_requires_subject", "memoryProposal", invalid_preference, "subject")

    invalid_fact = json.loads((SC / "examples-v4" / "working-memory-event.example.json").read_text(encoding="utf-8"))
    invalid_fact.pop("evidence", None)
    expect_invalid("schema.fact_requires_evidence", "workingMemoryEvent", invalid_fact, "evidence")

    invalid_source_request = json.loads((SC / "examples-v4" / "context-supplement-request.example.json").read_text(encoding="utf-8"))
    invalid_source_request["kind"] = "source"
    invalid_source_request.pop("sourceId", None)
    expect_invalid("schema.source_supplement_requires_source", "contextSupplementRequest", invalid_source_request, "sourceId")

    invalid_package = json.loads((SC / "examples-v4" / "context-package.example.json").read_text(encoding="utf-8"))
    invalid_package.pop("budget", None)
    expect_invalid("schema.context_package_requires_budget", "contextPackage", invalid_package, "budget")

    instance = json.loads((SC / "examples-v4" / "benchmark-suite.example.json").read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(benchmark).iter_errors(instance))
    record("schema.benchmark", not errors, "valid" if not errors else errors[0].message)


def main() -> int:
    con = db()
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    required = {
        "memory_records",
        "memory_evidence_links",
        "memory_relations",
        "memory_promotion_reviews",
        "working_memory_snapshots",
        "episodes",
        "episode_steps",
        "index_generations",
        "retrieval_sessions",
        "retrieval_candidates",
        "context_package_items",
        "context_item_feedback",
        "run_reflections",
        "run_evaluations",
        "benchmark_suites",
        "benchmark_cases",
        "benchmark_runs",
        "benchmark_comparisons",
    }
    record("sqlite.v4_tables", required <= tables, f"{len(required & tables)}/{len(required)} required tables")

    migrated = sqlite3.connect(":memory:")
    migrated.execute("PRAGMA foreign_keys=ON")
    migrated.executescript((SC / "sqlite-v2.sql").read_text(encoding="utf-8"))
    seed(migrated)
    before_tasks = migrated.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    migrated.executescript((SC / "migrate-v2-to-v3.sql").read_text(encoding="utf-8"))
    after_tasks = migrated.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    migrated_ok = (
        before_tasks == after_tasks == 2
        and migrated.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_records'").fetchone()[0] == 1
        and migrated.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    )
    record("sqlite.v2_to_v3_migration", migrated_ok, "legacy rows preserved and v4 tables installed")

    clean = sqlite3.connect(":memory:")
    clean.execute("PRAGMA foreign_keys=ON")
    clean.executescript((SC / "sqlite-v3.sql").read_text(encoding="utf-8"))
    clean_objects = {
        (row[0], row[1]): " ".join(row[2].split())
        for row in clean.execute(
            "SELECT type,name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL"
        )
    }
    migrated_objects = {
        (row[0], row[1]): " ".join(row[2].split())
        for row in migrated.execute(
            "SELECT type,name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL"
        )
    }
    record(
        "sqlite.clean_and_migrated_equivalent",
        clean_objects == migrated_objects,
        f"{len(clean_objects)} clean objects equal {len(migrated_objects)} migrated objects",
    )
    clean.close()
    migrated.close()

    schema_examples()

    blocked(
        "legacy_memory.insert_forbidden_after_cutover",
        lambda c: c.execute(
            "INSERT INTO memory_entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "me-new", "p1", "semantic", "candidate", "a1", "[]",
                None, None, 500000, None, NOW, None,
            ),
        ),
        "legacy memory entries are read-only",
    )

    legacy = migrated_db_with_legacy_memory()
    readable = legacy.execute(
        "SELECT status FROM memory_entries WHERE id='me1'"
    ).fetchone()
    record(
        "legacy_memory.remains_readable_after_cutover",
        readable == ("rejected",),
        "legacy row remains readable without becoming writable",
    )
    legacy.close()

    blocked(
        "artifact.quarantined_cannot_return_available",
        lambda c: (
            c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("aq", None, "p1", "log", "aq", SHA, "aq", 1, None, "quarantined", "core", "core", NOW, None, "hash_verified")),
            c.execute("UPDATE artifacts SET availability='available' WHERE id='aq'"),
        ),
        "invalid artifact availability transition",
    )
    blocked(
        "artifact.rejected_cannot_be_promoted",
        lambda c: (
            c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ar", None, "p1", "log", "ar", SHA, "ar", 1, None, "available", "core", "core", NOW, None, "rejected")),
            c.execute("UPDATE artifacts SET verification_state='user_approved' WHERE id='ar'"),
        ),
        "invalid artifact verification transition",
    )
    blocked(
        "artifact.quarantined_metadata_is_retained",
        lambda c: (
            c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ad", None, "p1", "log", "ad", SHA, "ad", 1, None, "quarantined", "core", "core", NOW, None, "rejected")),
            c.execute("DELETE FROM artifacts WHERE id='ad'"),
        ),
        "artifact records are retained",
    )
    blocked(
        "artifact.replace_cannot_reset_lifecycle",
        lambda c: (
            c.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("arp", None, "p1", "log", "arp", SHA, "arp", 1, None, "quarantined", "core", "core", NOW, None, "rejected")),
            c.execute("INSERT OR REPLACE INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("arp", None, "p1", "log", "arp", SHA, "arp", 1, None, "available", "core", "core", NOW, None, "user_approved")),
        ),
        "artifact identity replacement is forbidden",
    )
    artifact_con = db()
    try:
        artifact_con.execute("UPDATE artifacts SET availability='quarantined' WHERE id='a1'")
        artifact_con.execute("UPDATE artifacts SET verification_state='user_approved' WHERE id='cred'")
    except sqlite3.IntegrityError as exc:
        record("artifact.supported_transitions", False, str(exc))
    else:
        record("artifact.supported_transitions", True, "available->quarantined and tool_verified->user_approved")
    finally:
        artifact_con.close()

    blocked_in(
        "legacy_memory.update_forbidden_after_cutover",
        migrated_db_with_legacy_memory,
        lambda c: c.execute(
            "UPDATE memory_entries SET status='active' WHERE id='me1'"
        ),
        "legacy memory entries are read-only",
    )

    blocked_in(
        "legacy_memory.delete_forbidden_after_cutover",
        migrated_db_with_legacy_memory,
        lambda c: c.execute("DELETE FROM memory_entries WHERE id='me1'"),
        "legacy memory entries are retained",
    )

    blocked(
        "memory.cross_project_artifact",
        lambda c: insert_memory(c, artifact_id="a2"),
        "scope",
    )
    blocked(
        "memory.non_candidate_insert",
        lambda c: insert_memory(c, status="verified"),
        "start as candidate",
    )

    blocked(
        "memory.working_not_durable_record",
        lambda c: insert_memory(c, memory_type="working"),
        "CHECK constraint failed",
    )

    bad_project_scope = json.dumps({
        "summary": "wrong project scope",
        "scope": {"kind": "project", "id": "p2"},
        "systems": ["qrqc"],
    }, separators=(",", ":"))
    blocked(
        "memory.applicability_project_scope",
        lambda c: insert_memory(c, applicability_json=bad_project_scope),
        "applicability project scope",
    )

    missing_subject = json.dumps({
        "summary": "preferred report wording",
        "scope": {"kind": "project", "id": "p1"},
    }, separators=(",", ":"))
    blocked(
        "memory.preference_requires_subject",
        lambda c: insert_memory(c, memory_type="preference", applicability_json=missing_subject),
        "explicit subject",
    )

    con = db()
    scoped_preference = json.dumps({
        "summary": "use exact system names in reports",
        "scope": {"kind": "project", "id": "p1"},
        "subject": {"kind": "user", "id": "user-1"},
    }, separators=(",", ":"))
    insert_memory(con, memory_type="preference", applicability_json=scoped_preference)
    record(
        "memory.valid_scoped_preference",
        con.execute("SELECT COUNT(*) FROM memory_records WHERE id='m1' AND memory_type='preference'").fetchone()[0] == 1,
        "explicit subject and project scope accepted",
    )
    con.close()

    def invalid_direct_activation(c: sqlite3.Connection) -> None:
        insert_memory(c)
        transition_memory(c, "m1", "active", T1, activated_at=T1)

    blocked(
        "memory.direct_activation",
        invalid_direct_activation,
        ("invalid memory lifecycle", "promotion", "approved-to-active transition"),
    )

    def active_without_review(c: sqlite3.Connection) -> None:
        insert_memory(c)
        add_evidence(c)
        transition_memory(c, "m1", "verified", T1)
        transition_memory(c, "m1", "approved", T2)

    blocked(
        "memory.active_without_review",
        active_without_review,
        "granted promotion review",
    )

    def verified_without_evidence(c: sqlite3.Connection) -> None:
        insert_memory(c)
        transition_memory(c, "m1", "verified", T1)

    blocked(
        "memory.verified_without_evidence",
        verified_without_evidence,
        "current supporting",
    )

    def non_monotonic_status_time(c: sqlite3.Connection) -> None:
        insert_memory(c)
        transition_memory(c, "m1", "stale", NOW)

    blocked(
        "memory.status_time_monotonic",
        non_monotonic_status_time,
        "newer lifecycle time",
    )

    con = db()
    insert_memory(con)
    activate_memory(con)
    ok = con.execute("SELECT status FROM memory_records WHERE id='m1'").fetchone()[0] == "active"
    record("memory.valid_activation", ok, "verified evidence and granted review produce active memory")
    con.close()

    def preload_activation(c: sqlite3.Connection) -> None:
        insert_memory(c)
        c.execute("UPDATE memory_records SET activated_at=? WHERE id='m1'", (T1,))

    blocked(
        "memory.activation_cannot_preload",
        preload_activation,
        "only set during approved-to-active transition",
    )

    def mismatched_activation_time(c: sqlite3.Connection) -> None:
        insert_memory(c)
        add_evidence(c)
        transition_memory(c, "m1", "verified", T1)
        grant_review(c, decided_at=T2)
        transition_memory(c, "m1", "approved", T2)
        transition_memory(c, "m1", "active", T3, activated_at=T4)

    blocked(
        "memory.activation_time_matches_transition",
        mismatched_activation_time,
        "equal to lifecycle transition time",
    )

    def activate_expired_memory(c: sqlite3.Connection) -> None:
        insert_memory(c, expires_at=T2)
        add_evidence(c)
        transition_memory(c, "m1", "verified", T1)
        grant_review(c, decided_at=T2)
        transition_memory(c, "m1", "approved", T2)
        transition_memory(c, "m1", "active", T3, activated_at=T3)

    blocked(
        "memory.expired_cannot_activate",
        activate_expired_memory,
        "expired memory cannot become active",
    )

    def activate_second_version_while_first_active(c: sqlite3.Connection) -> None:
        insert_memory(c, memory_id="m1", version=1)
        activate_memory(c, "m1")
        insert_memory(c, memory_id="m2", version=2, created_at=T3)
        add_evidence(c, "m2", evidence_id="e-m2", created_at=T3)
        transition_memory(c, "m2", "verified", T4)
        grant_review(c, "m2", review_id="pr-m2", decided_at=T5)
        transition_memory(c, "m2", "approved", T5)
        transition_memory(c, "m2", "active", T6, activated_at=T6)

    blocked(
        "memory.one_active_version_per_logical_key",
        activate_second_version_while_first_active,
        "UNIQUE constraint failed",
    )

    def overwrite_activation(c: sqlite3.Connection) -> None:
        insert_memory(c)
        activate_memory(c)
        c.execute("UPDATE memory_records SET activated_at=? WHERE id='m1'", (T4,))

    blocked(
        "memory.activation_set_once",
        overwrite_activation,
        "activation evidence is set-once",
    )

    def stale_reverification(c: sqlite3.Connection) -> None:
        insert_memory(c)
        activate_memory(c)
        transition_memory(c, "m1", "stale", T4)
        add_evidence(c, evidence_id="e-m1-refresh", created_at=T5)
        transition_memory(c, "m1", "verified", T5)

    blocked(
        "memory.stale_cannot_reverify_in_place",
        stale_reverification,
        "invalid memory lifecycle",
    )

    con = db()
    insert_memory(con)
    activate_memory(con)
    transition_memory(con, "m1", "stale", T4)
    insert_memory(con, memory_id="m2", version=2, created_at=T4)
    activate_memory(
        con,
        "m2",
        evidence_at=T4,
        verified_at=T5,
        review_at=T6,
        active_at=T7,
    )
    con.execute(
        "INSERT INTO memory_relations VALUES (?,?,?,?,?,?,?)",
        ("rel-refresh", "p1", "m2", "m1", "supersedes", "a1", T7),
    )
    transition_memory(con, "m1", "superseded", T7)
    statuses = dict(con.execute("SELECT id,status FROM memory_records WHERE id IN ('m1','m2')"))
    relation_count = con.execute(
        "SELECT COUNT(*) FROM memory_relations "
        "WHERE from_memory_id='m2' AND to_memory_id='m1' AND relation_kind='supersedes'"
    ).fetchone()[0]
    record(
        "memory.stale_reuse_requires_new_version",
        statuses == {"m1": "superseded", "m2": "active"} and relation_count == 1,
        "fresh version activated and linked to retained stale predecessor",
    )
    con.close()

    def mutate_content(c: sqlite3.Connection) -> None:
        insert_memory(c)
        c.execute("UPDATE memory_records SET confidence_millionths=1 WHERE id='m1'")

    blocked("memory.content_immutable", mutate_content, "immutable")

    def relation_cross(c: sqlite3.Connection) -> None:
        insert_memory(c, memory_id="m1")
        insert_memory(c, memory_id="m2", project_id="p2", logical_key="other", task_id="t2", run_id="r2", artifact_id="a2")
        c.execute("INSERT INTO memory_relations VALUES (?,?,?,?,?,?,?)", ("rel", "p1", "m1", "m2", "contradicts", None, NOW))

    blocked("memory.cross_project_relation", relation_cross, "scope")

    def invalid_supersession(c: sqlite3.Connection) -> None:
        insert_memory(c, memory_id="m1", logical_key="key-a", version=1)
        insert_memory(c, memory_id="m2", logical_key="key-b", version=2)
        c.execute("INSERT INTO memory_relations VALUES (?,?,?,?,?,?,?)", ("rel", "p1", "m2", "m1", "supersedes", "a1", NOW))

    blocked("memory.invalid_supersession", invalid_supersession, "same logical key")

    def supersede_without_relation(c: sqlite3.Connection) -> None:
        insert_memory(c)
        transition_memory(c, "m1", "superseded", T1)

    blocked(
        "memory.superseded_requires_newer_relation",
        supersede_without_relation,
        "newer linked version",
    )

    def evidence_cross(c: sqlite3.Connection) -> None:
        insert_memory(c)
        c.execute(
            "INSERT INTO memory_evidence_links VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("e1", "m1", "p1", "artifact", "a2", None, None, SHA2, "supports", NOW),
        )

    blocked("memory.cross_project_evidence", evidence_cross, "scope")

    def evidence_hash_mismatch(c: sqlite3.Connection) -> None:
        insert_memory(c)
        add_evidence(c, digest=SHA2)

    blocked("memory.evidence_hash_mismatch", evidence_hash_mismatch, "digest")

    def review_before_verified(c: sqlite3.Connection) -> None:
        insert_memory(c)
        grant_review(c)

    blocked("memory.review_before_verified", review_before_verified, "verified")

    def working_snapshot_hash_mismatch(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO working_memory_snapshots VALUES (?,?,?,?,?,?,?,?)",
            ("wm1", "p1", "t1", "r1", 1, "a1", SHA2, NOW),
        )

    blocked(
        "working_memory.digest_matches_artifact",
        working_snapshot_hash_mismatch,
        "digest does not match artifact",
    )

    def evaluation_running_run(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO run_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("ev", "p1", "t1", "r1", "v1", SHA, "{}", "pass", "a1", NOW),
        )

    blocked("evaluation.requires_terminal_run", evaluation_running_run, "terminal")

    def evaluation_overwrite(c: sqlite3.Connection) -> None:
        terminal(c)
        c.execute(
            "INSERT INTO run_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("ev", "p1", "t1", "r1", "v1", SHA, "{}", "pass", "a1", NOW),
        )
        c.execute("UPDATE run_evaluations SET gate_decision='repair' WHERE id='ev'")

    blocked("evaluation.immutable", evaluation_overwrite, "immutable")

    def reflection_running_run(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO run_reflections VALUES (?,?,?,?,?,?,?)", ("rf", "p1", "t1", "r1", "a1", SHA, NOW))

    blocked("reflection.requires_terminal_run", reflection_running_run, "terminal")

    def reflection_hash_mismatch(c: sqlite3.Connection) -> None:
        terminal(c)
        c.execute("INSERT INTO run_reflections VALUES (?,?,?,?,?,?,?)", ("rf", "p1", "t1", "r1", "a1", SHA2, NOW))

    blocked(
        "reflection.digest_matches_artifact",
        reflection_hash_mismatch,
        "digest does not match artifact",
    )

    def reflection_delete(c: sqlite3.Connection) -> None:
        terminal(c)
        c.execute("INSERT INTO run_reflections VALUES (?,?,?,?,?,?,?)", ("rf", "p1", "t1", "r1", "a1", SHA, NOW))
        c.execute("DELETE FROM run_reflections WHERE id='rf'")

    blocked("reflection.retained", reflection_delete, "retained")

    def successful_episode_without_verification(c: sqlite3.Connection) -> None:
        terminal(c)
        c.execute(
            "INSERT INTO episodes VALUES (?,?,?,?,?,?,?,?,?)",
            ("ep", "p1", "t1", "r1", "succeeded", "a1", None, "abc", NOW),
        )

    blocked("episode.success_requires_verification", successful_episode_without_verification, "verification")

    def retrieval_inactive(c: sqlite3.Connection) -> None:
        insert_memory(c)
        start_retrieval(c)
        c.execute(
            """INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("rc", "rs1", "p1", "memory", None, None, None, "m1", "memory:1", SHA, 1, 900000, '["negative"]', "a1", "current", 1),
        )

    blocked("retrieval.inactive_memory", retrieval_inactive, "active")

    def retrieval_hash_mismatch(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute(
            "INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("rc", "rs1", "p1", "artifact", "a1", None, None, None, "artifact:v1", SHA2, 1, 900000, '["exact"]', "a1", "current", 1),
        )

    blocked("retrieval.hash_mismatch", retrieval_hash_mismatch, "hash")

    def retrieval_terminal_without_time(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute("UPDATE retrieval_sessions SET status='succeeded' WHERE id='rs1'")

    blocked("retrieval.terminal_requires_time", retrieval_terminal_without_time, "completion")

    def retrieval_terminal_without_trace(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute("UPDATE retrieval_sessions SET status='succeeded',completed_at=? WHERE id='rs1'", (LATER,))

    blocked(
        "retrieval.terminal_requires_exact_trace",
        retrieval_terminal_without_trace,
        "exact trace artifact",
    )

    def retrieval_trace_hash_mismatch(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute(
            "UPDATE retrieval_sessions SET status='succeeded',completed_at=?,trace_artifact_id=?,trace_digest=? WHERE id='rs1'",
            (LATER, "a1", SHA2),
        )

    blocked(
        "retrieval.trace_digest_matches_artifact",
        retrieval_trace_hash_mismatch,
        "trace artifact scope or digest",
    )

    def retrieval_terminal_branch_mutation(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute(
            "UPDATE retrieval_sessions SET status='succeeded',completed_at=?,trace_artifact_id=?,trace_digest=? WHERE id='rs1'",
            (LATER, "a1", SHA),
        )
        c.execute("UPDATE retrieval_sessions SET branch_status_json=? WHERE id='rs1'", ('{"exact":"changed"}',))

    blocked(
        "retrieval.terminal_branch_status_immutable",
        retrieval_terminal_branch_mutation,
        "branch status is immutable",
    )

    def retrieval_trace_overwrite(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute("UPDATE retrieval_sessions SET status='succeeded',completed_at=?,trace_artifact_id=?,trace_digest=? WHERE id='rs1'", (LATER, "a1", SHA))
        c.execute("UPDATE retrieval_sessions SET trace_artifact_id=?,trace_digest=? WHERE id='rs1'", ("receipt2", SHA2))

    blocked("retrieval.trace_set_once", retrieval_trace_overwrite, "set-once")

    retrieval_con = db()
    try:
        start_retrieval(retrieval_con)
        retrieval_con.execute(
            "UPDATE retrieval_sessions SET status='indeterminate',completed_at=?,trace_artifact_id=?,trace_digest=? WHERE id='rs1'",
            (LATER, "a1", SHA),
        )
    except sqlite3.IntegrityError as exc:
        record("retrieval.crash_can_be_recorded_indeterminate", False, str(exc))
    else:
        status = retrieval_con.execute("SELECT status FROM retrieval_sessions WHERE id='rs1'").fetchone()
        record("retrieval.crash_can_be_recorded_indeterminate", status == ("indeterminate",), str(status))
    finally:
        retrieval_con.close()

    def retrieval_indeterminate_without_trace(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute("UPDATE retrieval_sessions SET status='indeterminate',completed_at=? WHERE id='rs1'", (LATER,))

    blocked(
        "retrieval.indeterminate_requires_exact_trace",
        retrieval_indeterminate_without_trace,
        "exact trace artifact",
    )

    def retrieval_indeterminate_reopen(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        c.execute(
            "UPDATE retrieval_sessions SET status='indeterminate',completed_at=?,trace_artifact_id=?,trace_digest=? WHERE id='rs1'",
            (LATER, "a1", SHA),
        )
        c.execute("UPDATE retrieval_sessions SET status='failed' WHERE id='rs1'")

    blocked(
        "retrieval.indeterminate_receipt_is_terminal",
        retrieval_indeterminate_reopen,
        "retrieval terminal state is irreversible",
    )

    def second_current_generation(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO index_generations VALUES (?,?,?,?,?,?,?,?,?)", ("g1", "p1", "embedded", "1", SHA, "building", "a1", NOW, None))
        c.execute("UPDATE index_generations SET status='current',completed_at=? WHERE id='g1'", (LATER,))
        c.execute("INSERT INTO index_generations VALUES (?,?,?,?,?,?,?,?,?)", ("g2", "p1", "embedded", "2", SHA2, "building", "a1", NOW, None))
        c.execute("UPDATE index_generations SET status='current',completed_at=? WHERE id='g2'", (LATER,))

    blocked("index.one_current_generation", second_current_generation, "UNIQUE")

    def overwrite_index_completion(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO index_generations VALUES (?,?,?,?,?,?,?,?,?)",
            ("g1", "p1", "embedded", "1", SHA, "building", "a1", NOW, None),
        )
        c.execute(
            "UPDATE index_generations SET status='current',completed_at=? WHERE id='g1'",
            (T1,),
        )
        c.execute("UPDATE index_generations SET completed_at=? WHERE id='g1'", (T2,))

    blocked(
        "index.completion_set_once",
        overwrite_index_completion,
        "completion evidence is set-once",
    )

    def context_cross(c: sqlite3.Connection) -> None:
        c.execute(
            """INSERT INTO context_package_items(
            id,context_package_id,project_id,task_id,retrieval_candidate_id,category,source_kind,
            source_artifact_id,source_document_id,source_chunk_id,memory_id,source_revision,
            source_hash,inclusion_reason_artifact_id,authority_state,token_count,redacted
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("ci", "cp1", "p2", "t2", None, "knowledge", "artifact", "a2", None, None, None, "artifact:v1", SHA2, "a2", "authoritative", 10, 0),
        )

    blocked("context_item.cross_scope", context_cross, "scope")

    def context_hash_mismatch(c: sqlite3.Connection) -> None:
        c.execute(
            """INSERT INTO context_package_items(
            id,context_package_id,project_id,task_id,retrieval_candidate_id,category,source_kind,
            source_artifact_id,source_document_id,source_chunk_id,memory_id,source_revision,
            source_hash,inclusion_reason_artifact_id,authority_state,token_count,redacted
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("ci", "cp1", "p1", "t1", None, "knowledge", "artifact", "a1", None, None, None, "artifact:v1", SHA2, "a1", "authoritative", 10, 0),
        )

    blocked("context_item.hash_mismatch", context_hash_mismatch, "hash")

    def context_candidate_mismatch(c: sqlite3.Connection) -> None:
        start_retrieval(c)
        add_artifact_candidate(c)
        add_context_item(c, candidate_id="rc1", artifact_id="receipt1")

    blocked("context_item.candidate_mismatch", context_candidate_mismatch, "does not match")

    def reuse_context_package(c: sqlite3.Connection) -> None:
        c.execute(
            "INSERT INTO agent_runs("
            "id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,"
            "connection_binding_digest,run_config_artifact_id"
            ") VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("r3", "t1", "core-agent", "implementer", "Implementation", "created", "cp1", "run-key-3", SHA, "a1"),
        )

    blocked("context.package_single_run", reuse_context_package, "UNIQUE")

    def feedback_cross_run(c: sqlite3.Connection) -> None:
        add_context_item(c)
        c.execute(
            "INSERT INTO context_item_feedback VALUES (?,?,?,?,?,?,?,?,?)",
            ("fb", "ci1", "p1", "t1", "r2", "useful", 1, None, NOW),
        )

    blocked("context_feedback.cross_run", feedback_cross_run, "scope")

    def benchmark_manifest_hash_mismatch(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs", "p1", 1, "a1", SHA2, NOW))

    blocked(
        "benchmark.manifest_digest_matches_artifact",
        benchmark_manifest_hash_mismatch,
        "manifest digest does not match artifact",
    )

    def benchmark_system_configuration_mismatch(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs", "p1", 1, "a1", SHA, NOW))
        c.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc", "bs", 1, "a1", "abc", SHA, NOW))
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br1", "bc", "t1", SHA, SHA, "a1", "completed", NOW, LATER))
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br2", "bc", "t1", SHA2, SHA, "receipt1", "completed", NOW, LATER))
        c.execute("INSERT INTO benchmark_comparisons VALUES (?,?,?,?,?,?)", ("cmp", "br1", "br2", "a1", "improved", NOW))

    blocked(
        "benchmark.mismatched_system_configuration",
        benchmark_system_configuration_mismatch,
        "not comparable",
    )

    def benchmark_cross_project_result_on_update(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs", "p1", 1, "a1", SHA, NOW))
        c.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc", "bs", 1, "a1", "abc", SHA, NOW))
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br", "bc", "t1", SHA, SHA, None, "planned", None, None))
        c.execute("UPDATE benchmark_runs SET status='running',started_at=? WHERE id='br'", (T1,))
        c.execute("UPDATE benchmark_runs SET status='completed',result_artifact_id='a2',completed_at=? WHERE id='br'", (T2,))

    blocked(
        "benchmark.result_scope_rechecked_on_update",
        benchmark_cross_project_result_on_update,
        "result scope is incoherent",
    )

    def benchmark_bad_comparison(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs", "p1", 1, "a1", SHA, NOW))
        c.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc", "bs", 1, "a1", "abc", SHA, NOW))
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br1", "bc", "t1", SHA, SHA, "a1", "completed", NOW, LATER))
        c.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br2", "bc", "t1", SHA2, SHA2, "receipt1", "completed", NOW, LATER))
        c.execute("INSERT INTO benchmark_comparisons VALUES (?,?,?,?,?,?)", ("cmp", "br1", "br2", "a1", "improved", NOW))

    blocked("benchmark.mismatched_evaluator", benchmark_bad_comparison, "not comparable")

    def benchmark_terminal_reopen(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs", "p1", 1, "a1", SHA, NOW))
        c.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc", "bs", 1, "a1", "abc", SHA, NOW))
        c.execute(
            "INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)",
            ("br", "bc", "t1", SHA, SHA, None, "planned", None, None),
        )
        c.execute("UPDATE benchmark_runs SET status='running',started_at=? WHERE id='br'", (T1,))
        c.execute(
            "UPDATE benchmark_runs SET status='completed',result_artifact_id='a1',completed_at=? WHERE id='br'",
            (T2,),
        )
        c.execute("UPDATE benchmark_runs SET status='running',completed_at=NULL WHERE id='br'")

    blocked(
        "benchmark.terminal_irreversible",
        benchmark_terminal_reopen,
        "invalid benchmark run lifecycle",
    )

    def benchmark_result_overwrite(c: sqlite3.Connection) -> None:
        c.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs", "p1", 1, "a1", SHA, NOW))
        c.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc", "bs", 1, "a1", "abc", SHA, NOW))
        c.execute(
            "INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)",
            ("br", "bc", "t1", SHA, SHA, None, "planned", None, None),
        )
        c.execute("UPDATE benchmark_runs SET status='running',started_at=? WHERE id='br'", (T1,))
        c.execute(
            "UPDATE benchmark_runs SET status='completed',result_artifact_id='a1',completed_at=? WHERE id='br'",
            (T2,),
        )
        c.execute("UPDATE benchmark_runs SET result_artifact_id='receipt1' WHERE id='br'")

    blocked(
        "benchmark.result_set_once",
        benchmark_result_overwrite,
        "result evidence is set-once",
    )

    passed = sum(checks)
    print(f"\n{passed}/{len(checks)} v4 cognitive checks passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
