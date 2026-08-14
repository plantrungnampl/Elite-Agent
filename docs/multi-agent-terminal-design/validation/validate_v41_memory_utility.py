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
from validate_v3 import NOW, SHA_A as SHA, SHA_B as SHA2, seed  # noqa: E402

T1 = "2026-08-06T01:00:00Z"
T2 = "2026-08-06T01:10:00Z"
T3 = "2026-08-06T01:20:00Z"
T4 = "2026-08-06T01:30:00Z"
T5 = "2026-08-06T01:40:00Z"
T6 = "2026-08-06T01:50:00Z"
T7 = "2026-08-06T02:00:00Z"

checks: list[bool] = []


def record(name: str, ok: bool, detail: str) -> None:
    checks.append(ok)
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v4.sql").read_text(encoding="utf-8"))
    seed(con)
    return con


def migrated_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v3.sql").read_text(encoding="utf-8"))
    seed(con)
    con.executescript((SC / "migrate-v3-to-v4.sql").read_text(encoding="utf-8"))
    return con


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


def insert_state(
    con: sqlite3.Connection,
    *,
    state_id: str = "s1",
    project_id: str = "p1",
    task_id: str | None = "t1",
    state_key: str = "user.output.language",
    scope_kind: str = "task",
    scope_id: str = "t1",
    authority_kind: str = "current_instruction",
    precedence_rank: int = 600,
    source_artifact_id: str = "a1",
    source_digest: str = SHA,
    status: str = "active",
    supersedes_state_id: str | None = None,
) -> None:
    con.execute(
        "INSERT INTO state_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            state_id,
            project_id,
            task_id,
            state_key,
            scope_kind,
            scope_id,
            authority_kind,
            precedence_rank,
            json.dumps({"language": "vi"}, separators=(",", ":")),
            source_artifact_id,
            source_digest,
            status,
            T1,
            None,
            supersedes_state_id,
            T1,
            T1,
            None,
        ),
    )


def insert_memory_candidate(con: sqlite3.Connection, memory_id: str = "m1") -> None:
    applicability = json.dumps(
        {"summary": "avoid direct activation", "scope": {"kind": "project", "id": "p1"}},
        separators=(",", ":"),
    )
    rules = json.dumps(
        [
            {
                "ruleId": "ir1",
                "kind": "source_hash_changed",
                "target": {"sourceId": "a1"},
                "expected": {"contentHash": SHA},
                "cadence": "before_retrieval",
                "explanation": "Revalidate when the evidence artifact changes",
            }
        ],
        separators=(",", ":"),
    )
    con.execute(
        "INSERT INTO memory_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            memory_id,
            "p1",
            "memory.activation.guard",
            "t1",
            "r1",
            "negative",
            1,
            "candidate",
            "a1",
            applicability,
            rules,
            900000,
            "internal",
            None,
            T1,
            T1,
            None,
        ),
    )



def insert_comparable_benchmark_runs(con: sqlite3.Connection) -> None:
    con.execute("INSERT INTO benchmark_suites VALUES (?,?,?,?,?,?)", ("bs-v41", "p1", 2, "a1", SHA, T1))
    con.execute("INSERT INTO benchmark_cases VALUES (?,?,?,?,?,?,?)", ("bc-v41", "bs-v41", 1, "a1", "bootstrap", SHA, T1))
    con.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-control", "bc-v41", "t1", SHA, SHA, "a1", "completed", T1, T2))
    con.execute("INSERT INTO benchmark_runs VALUES (?,?,?,?,?,?,?,?,?)", ("br-candidate", "bc-v41", "t1", SHA, SHA, "a1", "completed", T1, T2))


def schema_objects(con: sqlite3.Connection) -> dict[tuple[str, str], str]:
    rows = con.execute(
        "SELECT type,name,COALESCE(sql,'') FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','trigger','view')"
    )
    return {(kind, name): " ".join(sql.split()) for kind, name, sql in rows}


def activate_memory_without_invalidation(con: sqlite3.Connection) -> None:
    insert_memory_candidate(con)
    con.execute(
        "INSERT INTO memory_evidence_links VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("e1", "m1", "p1", "artifact", "a1", None, None, SHA, "supports", T1),
    )
    con.execute("UPDATE memory_records SET status='verified',status_changed_at=? WHERE id='m1'", (T2,))
    con.execute(
        "INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)",
        ("pr1", "m1", "p1", "user", "user-1", "granted", "a1", SHA, T3),
    )
    con.execute("UPDATE memory_records SET status='approved',status_changed_at=? WHERE id='m1'", (T4,))
    con.execute(
        "INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)",
        ("pr2", "m1", "p1", "user", "user-1", "granted", "receipt2", SHA2, T5),
    )
    con.execute(
        "UPDATE memory_records SET status='active',status_changed_at=?,activated_at=? WHERE id='m1'",
        (T6, T6),
    )


def insert_retrieval_session(con: sqlite3.Connection) -> None:
    con.execute(
        "INSERT INTO retrieval_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("rs1", "p1", "t1", "r1", None, "a1", "a1", "hybrid", "1", "v4.1", "running", "{}", None, None, T7, None),
    )


def main() -> int:
    required = [
        SC / "sqlite-v4.sql",
        SC / "migrate-v3-to-v4.sql",
        SC / "cognitive-memory.v2.schema.json",
        SC / "agent-quality-benchmark.v2.schema.json",
    ]
    missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
    if missing:
        record("files.v41_contracts", False, "missing: " + ", ".join(missing))
        print(f"\n0/{len(checks)} v4.1 memory utility checks passed")
        return 1
    record("files.v41_contracts", True, "all v4.1 contracts present")

    schema = load_json(SC / "cognitive-memory.v2.schema.json")
    benchmark_schema = load_json(SC / "agent-quality-benchmark.v2.schema.json")
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator.check_schema(benchmark_schema)
    except Exception as exc:
        record("schema.v41_compiles", False, str(exc))
    else:
        record("schema.v41_compiles", True, "both v2 schemas compile")

    required_defs = {
        "stateRecord",
        "stateResolutionReceipt",
        "invalidationRule",
        "invalidationEvaluation",
        "memoryShadowEvaluation",
        "memoryUsageEvent",
        "memoryConsolidationAction",
        "contextBudgetDecision",
        "memoryProposal",
        "contextPackage",
    }
    defs = set(schema.get("$defs", {}))
    record(
        "schema.v41_definitions",
        required_defs <= defs,
        f"{len(required_defs & defs)}/{len(required_defs)} required definitions",
    )

    typed_rule = {
        "ruleId": "ir1",
        "kind": "source_hash_changed",
        "target": {"sourceId": "a1"},
        "expected": {"contentHash": SHA},
        "cadence": "before_retrieval",
        "explanation": "Revalidate when the source changes",
    }
    rule_validator = Draft202012Validator(
        {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": "#/$defs/invalidationRule"}
    )
    record("schema.typed_invalidation_valid", not list(rule_validator.iter_errors(typed_rule)), "typed rule accepted")
    bad_rule = {"ruleId": "ir1", "kind": "source_hash_changed", "explanation": "plain prose only"}
    record(
        "schema.typed_invalidation_rejects_prose_only",
        bool(list(rule_validator.iter_errors(bad_rule))),
        "non-executable rule rejected",
    )

    state_validator = Draft202012Validator(
        {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": "#/$defs/stateRecord"}
    )
    state = {
        "stateId": "s1",
        "projectId": "p1",
        "taskId": "t1",
        "key": "user.output.language",
        "value": {"language": "vi"},
        "scope": {"kind": "task", "id": "t1"},
        "authorityKind": "current_instruction",
        "precedenceRank": 600,
        "status": "active",
        "sources": [
            {"sourceId": "a1", "sourceRevision": "artifact:v1", "contentHash": SHA, "sourceKind": "artifact"}
        ],
        "validFrom": T1,
        "createdAt": T1,
        "statusChangedAt": T1,
    }
    record("schema.state_record_valid", not list(state_validator.iter_errors(state)), "structured current state accepted")

    con = db()
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    expected_tables = {
        "state_records",
        "state_evidence_links",
        "state_resolution_receipts",
        "memory_invalidation_evaluations",
        "memory_shadow_evaluations",
        "memory_usage_events",
        "memory_utility_snapshots",
        "memory_consolidation_actions",
        "context_budget_decisions",
    }
    record("sqlite.v41_tables", expected_tables <= tables, f"{len(expected_tables & tables)}/{len(expected_tables)} required tables")
    integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    record("sqlite.v41_clean_install", integrity == "ok", integrity)
    con.close()

    migrated = migrated_db()
    migrated_tables = {row[0] for row in migrated.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    record("sqlite.v3_to_v4_migration", expected_tables <= migrated_tables, "v3 rows retained and v4.1 tables installed")
    record("sqlite.v3_rows_preserved", migrated.execute("SELECT COUNT(*) FROM projects WHERE id='p1'").fetchone()[0] == 1, "seed project preserved")
    clean_for_equivalence = db()
    clean_objects = schema_objects(clean_for_equivalence)
    migrated_objects = schema_objects(migrated)
    record(
        "sqlite.clean_and_migrated_equivalent",
        clean_objects == migrated_objects,
        f"{len(clean_objects)} clean objects and {len(migrated_objects)} migrated objects",
    )
    clean_for_equivalence.close()
    migrated.close()

    blocked(
        "state.precedence_mapping",
        lambda c: insert_state(c, precedence_rank=200),
        "precedence rank does not match authority kind",
    )
    blocked(
        "state.cross_project_artifact",
        lambda c: insert_state(c, source_artifact_id="a2", source_digest=SHA2),
        "state source scope is incoherent",
    )
    blocked(
        "state.task_scope_matches_task",
        lambda c: insert_state(c, scope_id="t2"),
        "state task scope is incoherent",
    )
    blocked(
        "state.digest_matches_artifact",
        lambda c: insert_state(c, source_digest=SHA2),
        "state source digest does not match artifact",
    )

    con = db()
    insert_state(con)
    con.execute(
        "INSERT INTO state_resolution_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            "sr1",
            "p1",
            "t1",
            "user.output.language",
            "s1",
            json.dumps(["s1"], separators=(",", ":")),
            "state-precedence.v1",
            "a1",
            SHA,
            T2,
            SHA,
        ),
    )
    record("state.valid_resolution", con.execute("SELECT winning_state_id FROM state_resolution_receipts WHERE id='sr1'").fetchone()[0] == "s1", "winning state persisted")
    con.close()

    blocked(
        "state.resolution_requires_highest_precedence",
        lambda c: (
            insert_state(c, state_id="s-low", authority_kind="explicit_user_preference", precedence_rank=200),
            insert_state(c, state_id="s-high", authority_kind="current_instruction", precedence_rank=600),
            c.execute(
                "INSERT INTO state_resolution_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("sr1", "p1", "t1", "user.output.language", "s-low", '[\"s-low\",\"s-high\"]', "state-precedence.v1", "a1", SHA, T2, SHA),
            ),
        ),
        "state resolution winner is not highest precedence",
    )

    blocked(
        "state.authority_immutable",
        lambda c: (insert_state(c), c.execute("UPDATE state_records SET value_json='{}' WHERE id='s1'")),
        "state identity and value are immutable",
    )

    blocked(
        "invalidation.requires_memory_scope",
        lambda c: (
            insert_memory_candidate(c),
            c.execute(
                "INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("ie1", "m1", "p2", "t1", "ir1", "passed", "a2", SHA2, T2, T3),
            ),
        ),
        "invalidation evaluation scope is incoherent",
    )

    con = db()
    insert_memory_candidate(con)
    con.execute(
        "INSERT INTO memory_invalidation_evaluations VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("ie1", "m1", "p1", "t1", "ir1", "passed", "a1", SHA, T2, T3),
    )
    record("invalidation.valid_evaluation", con.execute("SELECT result FROM memory_invalidation_evaluations WHERE id='ie1'").fetchone()[0] == "passed", "typed rule evaluation persisted")
    con.close()

    blocked(
        "retrieval.requires_current_invalidation_evidence",
        lambda c: (
            activate_memory_without_invalidation(c),
            insert_retrieval_session(c),
            c.execute(
                "INSERT INTO retrieval_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("rc1", "rs1", "p1", "memory", None, None, None, "m1", "memory:1", SHA, 1, 900000, '["vector"]', "a1", "fresh", 1),
            ),
        ),
        "retrieval memory lacks current passing invalidation evidence",
    )

    blocked(
        "shadow.passed_result_rejects_regression",
        lambda c: (
            insert_memory_candidate(c),
            insert_comparable_benchmark_runs(c),
            c.execute(
                "INSERT INTO memory_shadow_evaluations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("se1", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "br-control", "br-candidate", "passed", -1, 0, 0, "a1", SHA, T3),
            ),
        ),
        "passing shadow evaluation cannot introduce regressions",
    )

    blocked(
        "shadow.policy_approval_requires_pass",
        lambda c: (
            insert_memory_candidate(c),
            c.execute("INSERT INTO memory_evidence_links VALUES (?,?,?,?,?,?,?,?,?,?)", ("e1", "m1", "p1", "artifact", "a1", None, None, SHA, "supports", T1)),
            c.execute("UPDATE memory_records SET status='verified',status_changed_at=? WHERE id='m1'", (T2,)),
            c.execute("INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)", ("pr1", "m1", "p1", "policy", "policy-1", "granted", "a1", SHA, T3)),
        ),
        "policy promotion requires passing shadow evaluation",
    )

    con = db()
    insert_memory_candidate(con)
    con.execute("INSERT INTO memory_evidence_links VALUES (?,?,?,?,?,?,?,?,?,?)", ("e1", "m1", "p1", "artifact", "a1", None, None, SHA, "supports", T1))
    con.execute("UPDATE memory_records SET status='verified',status_changed_at=? WHERE id='m1'", (T2,))
    insert_comparable_benchmark_runs(con)
    con.execute(
        "INSERT INTO memory_shadow_evaluations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "se1", "m1", "p1", "t1", "control_no_memory", "evidence_plus_experience", "br-control", "br-candidate",
            "passed", 100000, 0, 0, "a1", SHA, T3,
        ),
    )
    con.execute("INSERT INTO memory_promotion_reviews VALUES (?,?,?,?,?,?,?,?,?)", ("pr1", "m1", "p1", "policy", "policy-1", "granted", "a1", SHA, T4))
    record("shadow.valid_policy_promotion", con.execute("SELECT decision FROM memory_promotion_reviews WHERE id='pr1'").fetchone()[0] == "granted", "passing shadow evaluation authorizes policy review")
    con.close()

    blocked(
        "usage.cross_project",
        lambda c: (
            insert_memory_candidate(c),
            c.execute(
                "INSERT INTO memory_usage_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("mu1", "m1", "p2", "t1", "r1", "retrieved", 1, 0, 0, 0, None, 100, "a2", SHA2, T2),
            ),
        ),
        "memory usage scope is incoherent",
    )

    blocked(
        "utility.immutable_projection",
        lambda c: (
            insert_memory_candidate(c),
            c.execute(
                "INSERT INTO memory_utility_snapshots VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("us1", "m1", "p1", 1, 1, 0, 1, 0, 100, 0, 500000, "a1", SHA, T2),
            ),
            c.execute("UPDATE memory_utility_snapshots SET utility_millionths=1 WHERE id='us1'"),
        ),
        "immutable derived projections",
    )

    blocked(
        "consolidation.retains_inputs",
        lambda c: (
            insert_memory_candidate(c),
            c.execute(
                "INSERT INTO memory_consolidation_actions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("ca1", "p1", "merge", '[\"m1\"]', None, "proposed", "a1", SHA, "policy", T2, None),
            ),
            c.execute("DELETE FROM memory_records WHERE id='m1'"),
        ),
        ("memory records are retained", "FOREIGN KEY constraint failed"),
    )

    blocked(
        "budget.cross_task_package",
        lambda c: c.execute(
            "INSERT INTO context_budget_decisions (id,project_id,task_id,run_id,context_package_id,task_class,risk_level,allocations_json,total_allocated_tokens,strategy_version,coverage_millionths,marginal_utility_threshold_millionths,stopping_reason,evidence_artifact_id,evidence_digest,policy_snapshot_digest,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("bd1", "p1", "t2", "r1", "cp1", "bug-diagnosis", "medium", '{"objective":100}', 100, "adaptive-budget.v1", 500000, 100000, "policy_limit", "a1", SHA, SHA, T2),
        ),
        "context budget scope is incoherent",
    )

    blocked(
        "budget.allocations_sum_exactly",
        lambda c: c.execute(
            "INSERT INTO context_budget_decisions (id,project_id,task_id,run_id,context_package_id,task_class,risk_level,allocations_json,total_allocated_tokens,strategy_version,coverage_millionths,marginal_utility_threshold_millionths,stopping_reason,evidence_artifact_id,evidence_digest,policy_snapshot_digest,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("bd1", "p1", "t1", "r1", "cp1", "bug-diagnosis", "medium", '{"objective":1000,"evidence":4000}', 6001, "adaptive-budget.v1", 850000, 100000, "sufficient_coverage", "a1", SHA, SHA, T2),
        ),
        "context budget allocations do not sum to total",
    )

    con = db()
    con.execute(
        "INSERT INTO context_budget_decisions (id,project_id,task_id,run_id,context_package_id,task_class,risk_level,allocations_json,total_allocated_tokens,strategy_version,coverage_millionths,marginal_utility_threshold_millionths,stopping_reason,evidence_artifact_id,evidence_digest,policy_snapshot_digest,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("bd1", "p1", "t1", "r1", "cp1", "bug-diagnosis", "medium", '{"objective":1000,"evidence":4000,"experience":1000}', 6000, "adaptive-budget.v1", 850000, 100000, "sufficient_coverage", "a1", SHA, SHA, T2),
    )
    record("budget.valid_decision", con.execute("SELECT total_allocated_tokens FROM context_budget_decisions WHERE id='bd1'").fetchone()[0] == 6000, "adaptive allocation persisted")
    con.close()

    passed = sum(checks)
    print(f"\n{passed}/{len(checks)} v4.1 memory utility checks passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
