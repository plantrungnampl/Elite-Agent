#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Callable

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SC = ROOT / "schemas"
VAL = ROOT / "validation"
sys.path.insert(0, str(VAL))
from validate_v3 import OID_A, SHA_A as SHA, SHA_B as SHA2, NOW, LATER, seed  # noqa: E402

checks: list[bool] = []


def record(name: str, ok: bool, detail: str) -> None:
    checks.append(ok)
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def expect_blocked(name: str, fn: Callable[[], None], needle: str | tuple[str, ...] = "") -> None:
    try:
        fn()
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        needles = (needle,) if isinstance(needle, str) else needle
        ok = not needles or any(part in str(exc) for part in needles)
        record(name, ok, str(exc))
    else:
        record(name, False, "unsafe operation succeeded")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_instance(schema_name: str, instance_name: str, definition: str | None = None) -> None:
    schema = load(SC / schema_name)
    instance = load(SC / instance_name)
    target = schema if definition is None else {
        "$schema": schema["$schema"],
        "$defs": schema["$defs"],
        "$ref": f"#/$defs/{definition}",
    }
    errors = list(Draft202012Validator(target).iter_errors(instance))
    record(
        f"schema.example.{instance_name}",
        not errors,
        "valid" if not errors else errors[0].message,
    )


def object_names(con: sqlite3.Connection) -> set[tuple[str, str]]:
    return set(con.execute(
        "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall())


def table_signatures(con: sqlite3.Connection) -> dict[str, tuple[tuple, ...]]:
    tables = [row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    return {name: tuple(tuple(row) for row in con.execute(f'PRAGMA table_info("{name}")')) for name in tables}


def foreign_key_signatures(con: sqlite3.Connection) -> dict[str, tuple[tuple, ...]]:
    tables = [row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    return {name: tuple(tuple(row) for row in con.execute(f'PRAGMA foreign_key_list("{name}")')) for name in tables}


def index_signatures(con: sqlite3.Connection) -> dict[str, tuple[tuple, ...]]:
    indexes = [row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    return {name: tuple(tuple(row) for row in con.execute(f'PRAGMA index_xinfo("{name}")')) for name in indexes}


def normalized_object_sql(con: sqlite3.Connection, names: set[str]) -> dict[str, str]:
    rows = con.execute(
        "SELECT name,COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return {name: re.sub(r"\s+", "", sql).lower() for name, sql in rows if name in names}


def clean_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v6.sql").read_text(encoding="utf-8"))
    seed(con)
    return con


def migrated_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((SC / "sqlite-v5.sql").read_text(encoding="utf-8"))
    seed(con)
    con.executescript((SC / "migrate-v5-to-v6.sql").read_text(encoding="utf-8"))
    return con


def add_artifact(con: sqlite3.Connection, artifact_id: str, digest: str = SHA, task_id: str | None = "t1", artifact_type: str = "receipt") -> None:
    con.execute(
        """INSERT INTO artifacts(id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,supersedes,verification_state)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (artifact_id, task_id, "p1", artifact_type, artifact_id, digest, artifact_id, 1, "application/json", "available", "core", "core", NOW, None, "hash_verified"),
    )



def digest(ch: str) -> str:
    return "sha256:" + ch * 64


def advance_workflow(con: sqlite3.Connection, phases: list[str], start_second: int = 1) -> None:
    for offset, phase in enumerate(phases, start=start_second):
        timestamp = f"2026-08-04T08:00:{offset:02d}Z"
        completed_at = timestamp if phase in {"Completed", "Cancelled", "Failed"} else None
        con.execute(
            "UPDATE task_workflow_authority SET phase=?, updated_at=?, completed_at=? WHERE task_id='t1'",
            (phase, timestamp, completed_at),
        )

def insert_run(con: sqlite3.Connection, run_id: str, status: str, suffix: str) -> None:
    cp_id = f"cp-{suffix}"
    con.execute(
        """INSERT INTO context_packages(id,task_id,agent_id,role,objective,manifest_artifact_id,effective_content_artifact_id,content_hash,policy_snapshot_digest,prompt_template_version,retrieval_pipeline_version,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cp_id, "t1", "core-agent", "reviewer", "Objective", "a1", "a1", SHA, SHA, "1", "1", NOW),
    )
    con.execute(
        """INSERT INTO agent_runs(id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id,completed_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (run_id, "t1", "core-agent", "reviewer", "CrossReview", status, cp_id, f"key-{suffix}", SHA, "a1", NOW if status not in {"created", "accepted", "running"} else None),
    )


def validate_contract_files() -> None:
    required = [
        "workflow-transitions.v2.json",
        "cognitive-memory.v4.schema.json",
        "benchmark-suite.v3.schema.json",
        "benchmark-run-receipt.v1.schema.json",
        "benchmark-case-result.v1.schema.json",
        "benchmark-comparison-report.v1.schema.json",
        "quality-release-decision.v1.schema.json",
        "actor-binding.v1.schema.json",
        "credential-challenge.v1.schema.json",
        "sqlite-v6.sql",
        "migrate-v5-to-v6.sql",
    ]
    for name in required:
        record(f"file.{name}", (SC / name).exists(), "present" if (SC / name).exists() else "missing")


def validate_workflow() -> None:
    path = SC / "workflow-transitions.v2.json"
    if not path.exists():
        record("workflow.v2", False, "missing")
        return
    wf = load(path)
    profiles = set(wf.get("workflowProfiles", []))
    modes = set(wf.get("taskOutcomeModes", []))
    record("workflow.profiles", profiles == {"Quick", "Standard", "HighAssurance", "ReadOnlyResearch"}, str(sorted(profiles)))
    record("workflow.outcome_modes", modes == {"ReadOnlyDeliverable", "WorkspaceChange", "LocalCommit"}, str(sorted(modes)))
    transitions = wf.get("phaseTransitions", [])

    def has(frm: str, event: str, to: str, effect: str | None = None, guard_part: str | None = None) -> bool:
        for tr in transitions:
            if tr.get("from") == frm and tr.get("event") == event and tr.get("to") == to:
                if effect is not None and effect not in tr.get("effects", []):
                    continue
                if guard_part is not None and guard_part not in tr.get("guard", ""):
                    continue
                return True
        return False

    record("workflow.read_only_approval", has("FinalObjection", "deliverable.review.ready", "AwaitingDeliverableApproval", "create_deliverable_approval_request", "ReadOnlyDeliverable"), "read-only review path")
    record("workflow.read_only_completed", has("AwaitingDeliverableApproval", "deliverable.approved", "Completed", "create_read_only_completion_package", "ReadOnlyDeliverable"), "read-only terminal path")
    record("workflow.workspace_completed", has("AwaitingWorkspaceApproval", "workspace.approved", "Completed", "create_workspace_completion_package", "WorkspaceChange"), "workspace terminal path")
    record("workflow.candidate_complete_commit", has("Implementation", "candidate.prepared", "Verification", "create_complete_candidate_commit"), "implementation creates exact commit")
    record("workflow.repair_complete_commit", has("Repair", "candidate.prepared", "Verification", "create_complete_candidate_commit"), "repair creates exact commit")
    record("workflow.final_review_exact_oid", has("FinalReview", "review.accepted", "AwaitingCommitApproval", "create_final_commit_approval_request", "candidate_commit_oid"), "review cites tree and commit")
    record("workflow.ref_promotion", has("AwaitingCommitApproval", "commit.approved", "RefPromotion", "persist_final_commit_approval", "candidate_commit_oid"), "approval enters ref promotion")
    record("workflow.ref_cas_completion", has("RefPromotion", "ref.cas.succeeded", "Completed", "create_local_commit_completion_package", "candidate_commit_oid"), "CAS attaches exact OID")
    repair_effects = [set(t.get("effects", [])) for t in transitions if t.get("to") == "Repair"]
    record("workflow.repair_invalidates_tree_and_commit", bool(repair_effects) and all({"discard_candidate_tree", "discard_candidate_commit"}.issubset(e) for e in repair_effects), str(repair_effects))
    record("workflow.localcommit_removed", "LocalCommit" not in wf.get("phases", []), "RefPromotion is the only Git attachment phase")

    transition_pairs = {(t.get("from"), t.get("to")) for t in transitions}
    shared_tail = ["PrePlanVerification", "Synthesis", "FinalObjection"]
    analysis_prefix = {
        "Quick": ["Intake", "ContextBuild"],
        "Standard": ["Intake", "ContextBuild", "ParallelAnalysis", "CrossReview"],
        "HighAssurance": ["Intake", "ContextBuild", "ParallelAnalysis", "CrossReview"],
        "ReadOnlyResearch": ["Intake", "ContextBuild", "ParallelAnalysis", "CrossReview"],
    }
    outcome_tail = {
        "ReadOnlyDeliverable": ["AwaitingDeliverableApproval", "Completed"],
        "WorkspaceChange": ["AwaitingPlanApproval", "Implementation", "Verification", "FinalReview", "AwaitingWorkspaceApproval", "Completed"],
        "LocalCommit": ["AwaitingPlanApproval", "Implementation", "Verification", "FinalReview", "AwaitingCommitApproval", "RefPromotion", "Completed"],
    }
    supported = {
        "Quick": tuple(outcome_tail),
        "Standard": tuple(outcome_tail),
        "HighAssurance": tuple(outcome_tail),
        "ReadOnlyResearch": ("ReadOnlyDeliverable",),
    }
    for profile, modes_for_profile in supported.items():
        for mode in modes_for_profile:
            route = analysis_prefix[profile] + shared_tail + outcome_tail[mode]
            missing = [(a, b) for a, b in zip(route, route[1:]) if (a, b) not in transition_pairs]
            record(f"workflow.route.{profile}.{mode}", not missing, f"route={route} missing={missing}")


def validate_schema_examples() -> None:
    schema_names = [
        "cognitive-memory.v4.schema.json",
        "benchmark-suite.v3.schema.json",
        "benchmark-run-receipt.v1.schema.json",
        "benchmark-case-result.v1.schema.json",
        "benchmark-comparison-report.v1.schema.json",
        "quality-release-decision.v1.schema.json",
        "actor-binding.v1.schema.json",
        "credential-challenge.v1.schema.json",
    ]
    for name in schema_names:
        path = SC / name
        if not path.exists():
            record(f"schema.compile.{name}", False, "missing")
            continue
        try:
            Draft202012Validator.check_schema(load(path))
        except Exception as exc:
            record(f"schema.compile.{name}", False, str(exc))
        else:
            record(f"schema.compile.{name}", True, "valid Draft 2020-12")

    examples = [
        ("cognitive-memory.v4.schema.json", "examples-v42/retrieval-indeterminate.example.json", "retrievalResult"),
        ("cognitive-memory.v4.schema.json", "examples-v42/preference-memory-proposal.example.json", "memoryProposal"),
        ("benchmark-suite.v3.schema.json", "examples-v42/benchmark-suite.example.json", None),
        ("benchmark-run-receipt.v1.schema.json", "examples-v42/benchmark-run-receipt.example.json", None),
        ("benchmark-case-result.v1.schema.json", "examples-v42/benchmark-case-result.example.json", None),
        ("benchmark-comparison-report.v1.schema.json", "examples-v42/benchmark-comparison-report.example.json", None),
        ("quality-release-decision.v1.schema.json", "examples-v42/quality-release-decision.example.json", None),
        ("actor-binding.v1.schema.json", "examples-v42/actor-binding.example.json", None),
        ("credential-challenge.v1.schema.json", "examples-v42/credential-challenge.example.json", None),
    ]
    for schema_name, example_name, definition in examples:
        if (SC / schema_name).exists() and (SC / example_name).exists():
            validate_instance(schema_name, example_name, definition)
        else:
            record(f"schema.example.{example_name}", False, "schema or example missing")


def validate_sql_install_and_migration() -> None:
    try:
        clean = clean_db()
    except Exception as exc:
        record("sqlite.v6.clean_install", False, str(exc))
        return
    record("sqlite.v6.clean_install", clean.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "integrity_check=ok")
    try:
        migrated = migrated_db()
    except Exception as exc:
        record("sqlite.v6.migration", False, str(exc))
        clean.close()
        return
    record("sqlite.v6.migration", migrated.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "v5->v6 integrity_check=ok")
    c_objs = object_names(clean)
    m_objs = object_names(migrated)
    record("sqlite.v6.object_parity", c_objs == m_objs, f"clean={len(c_objs)} migrated={len(m_objs)} only_clean={sorted(c_objs-m_objs)[:5]} only_migrated={sorted(m_objs-c_objs)[:5]}")
    c_columns = table_signatures(clean)
    m_columns = table_signatures(migrated)
    column_diff = sorted(name for name in set(c_columns) | set(m_columns) if c_columns.get(name) != m_columns.get(name))
    record("sqlite.v6.column_parity", not column_diff, f"tables={len(c_columns)} differing={column_diff[:5]}")
    c_fks = foreign_key_signatures(clean)
    m_fks = foreign_key_signatures(migrated)
    fk_diff = sorted(name for name in set(c_fks) | set(m_fks) if c_fks.get(name) != m_fks.get(name))
    record("sqlite.v6.foreign_key_parity", not fk_diff, f"tables={len(c_fks)} differing={fk_diff[:5]}")
    c_indexes = index_signatures(clean)
    m_indexes = index_signatures(migrated)
    index_diff = sorted(name for name in set(c_indexes) | set(m_indexes) if c_indexes.get(name) != m_indexes.get(name))
    record("sqlite.v6.index_column_parity", not index_diff, f"indexes={len(c_indexes)} differing={index_diff[:5]}")
    appendix_text = (SC / "sqlite-v6.sql").read_text(encoding="utf-8").split("-- v4.2 end-to-end contract correction authority.", 1)[1]
    v42_names = set(re.findall(r"CREATE\s+(?:UNIQUE\s+)?(?:TABLE|TRIGGER|INDEX)\s+([A-Za-z0-9_]+)", appendix_text, re.IGNORECASE))
    v42_names.update({"agent_runs_terminal_irreversible", "episode_scope_insert", "run_reflection_scope_insert", "run_evaluation_scope_insert"})
    c_sql = normalized_object_sql(clean, v42_names)
    m_sql = normalized_object_sql(migrated, v42_names)
    sql_diff = sorted(name for name in v42_names if c_sql.get(name) != m_sql.get(name))
    record("sqlite.v6.v42_sql_parity", not sql_diff, f"objects={len(v42_names)} differing={sql_diff[:5]}")
    clean.close()
    migrated.close()


def validate_terminal_status_matrix() -> None:
    terminal = ["succeeded", "failed", "cancelled_cleanly", "terminated", "interrupted", "indeterminate"]
    for status in terminal:
        con = clean_db()
        suffix = status.replace("_", "-")
        add_artifact(con, f"sum-{suffix}")
        add_artifact(con, f"ref-{suffix}")
        add_artifact(con, f"eval-{suffix}")
        add_artifact(con, f"verify-{suffix}")
        insert_run(con, f"run-{suffix}", status, suffix)
        try:
            con.execute(
                "INSERT INTO episodes(id,project_id,task_id,run_id,outcome,summary_artifact_id,verification_artifact_id,repository_revision,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (f"ep-{suffix}", "p1", "t1", f"run-{suffix}", "cancelled" if status in {"cancelled_cleanly", "terminated", "interrupted"} else (status if status in {"succeeded", "failed", "indeterminate"} else "blocked"), f"sum-{suffix}", f"verify-{suffix}" if status == "succeeded" else None, OID_A, NOW),
            )
            con.execute(
                "INSERT INTO run_reflections(id,project_id,task_id,run_id,reflection_artifact_id,reflection_digest,created_at) VALUES (?,?,?,?,?,?,?)",
                (f"rf-{suffix}", "p1", "t1", f"run-{suffix}", f"ref-{suffix}", SHA, NOW),
            )
            con.execute(
                "INSERT INTO run_evaluations(id,project_id,task_id,run_id,evaluator_version,configuration_digest,scores_json,gate_decision,evaluation_artifact_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (f"ev-{suffix}", "p1", "t1", f"run-{suffix}", "v1", SHA, "{}", "indeterminate" if status == "indeterminate" else "pass", f"eval-{suffix}", NOW),
            )
        except Exception as exc:
            record(f"terminal.{status}", False, str(exc))
        else:
            record(f"terminal.{status}", True, "episode/reflection/evaluation accepted")
        con.close()

    for status in ["created", "accepted", "running"]:
        con = clean_db()
        suffix = status
        add_artifact(con, f"sum-{suffix}")
        insert_run(con, f"run-{suffix}", status, suffix)
        expect_blocked(
            f"nonterminal.{status}.episode_rejected",
            lambda con=con, status=status, suffix=suffix: con.execute(
                "INSERT INTO episodes(id,project_id,task_id,run_id,outcome,summary_artifact_id,repository_revision,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (f"ep-{suffix}", "p1", "t1", f"run-{suffix}", "blocked", f"sum-{suffix}", OID_A, NOW),
            ),
            "terminal run",
        )
        con.close()

    # The migration path must preserve the same terminal/nonterminal behavior, not only object names.
    for status in terminal:
        con = migrated_db()
        suffix = f"migrated-{status.replace('_', '-')}"
        add_artifact(con, f"sum-{suffix}")
        add_artifact(con, f"ref-{suffix}")
        add_artifact(con, f"eval-{suffix}")
        add_artifact(con, f"verify-{suffix}")
        insert_run(con, f"run-{suffix}", status, suffix)
        try:
            con.execute(
                "INSERT INTO episodes(id,project_id,task_id,run_id,outcome,summary_artifact_id,verification_artifact_id,repository_revision,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (f"ep-{suffix}", "p1", "t1", f"run-{suffix}", "cancelled" if status in {"cancelled_cleanly", "terminated", "interrupted"} else status, f"sum-{suffix}", f"verify-{suffix}" if status == "succeeded" else None, OID_A, NOW),
            )
            con.execute(
                "INSERT INTO run_reflections(id,project_id,task_id,run_id,reflection_artifact_id,reflection_digest,created_at) VALUES (?,?,?,?,?,?,?)",
                (f"rf-{suffix}", "p1", "t1", f"run-{suffix}", f"ref-{suffix}", SHA, NOW),
            )
            con.execute(
                "INSERT INTO run_evaluations(id,project_id,task_id,run_id,evaluator_version,configuration_digest,scores_json,gate_decision,evaluation_artifact_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (f"ev-{suffix}", "p1", "t1", f"run-{suffix}", "v1", SHA, "{}", "indeterminate" if status == "indeterminate" else "pass", f"eval-{suffix}", NOW),
            )
        except Exception as exc:
            record(f"migration.terminal.{status}", False, str(exc))
        else:
            record(f"migration.terminal.{status}", True, "migrated episode/reflection/evaluation accepted")
        con.close()

    for status in ["created", "accepted", "running"]:
        con = migrated_db()
        suffix = f"migrated-{status}"
        add_artifact(con, f"sum-{suffix}")
        insert_run(con, f"run-{suffix}", status, suffix)
        expect_blocked(
            f"migration.nonterminal.{status}.episode_rejected",
            lambda con=con, status=status, suffix=suffix: con.execute(
                "INSERT INTO episodes(id,project_id,task_id,run_id,outcome,summary_artifact_id,repository_revision,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (f"ep-{suffix}", "p1", "t1", f"run-{suffix}", "blocked", f"sum-{suffix}", OID_A, NOW),
            ),
            "terminal run",
        )
        con.close()


def validate_preference_roundtrip() -> None:
    con = clean_db()
    add_artifact(con, "mem-content")
    applicability = {"summary": "Use Vietnamese", "scope": {"kind": "task", "id": "t1"}}
    # Legacy projection remains explicit and non-authoritative; canonical wire values live in v2 bindings.
    legacy_projection = {**applicability, "subject": {"kind": "user", "id": "u1"}}
    rules = [{"ruleId": "r1", "kind": "time_expired", "target": {}, "expected": {"expiresAt": LATER}, "cadence": "before_retrieval", "explanation": "Expiry"}]
    try:
        con.execute(
            """INSERT INTO memory_records(id,project_id,logical_key,origin_task_id,origin_run_id,memory_type,version,status,content_artifact_id,applicability_json,invalidation_conditions_json,confidence_millionths,sensitivity,expires_at,created_at,status_changed_at,activated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("m-pref", "p1", "preference.output.language", "t1", "r1", "preference", 1, "candidate", "mem-content", json.dumps(legacy_projection), json.dumps(rules), 900000, "normal", None, NOW, NOW, None),
        )
        con.execute(
            "INSERT INTO memory_wire_contracts_v2(memory_id,project_id,logical_key,applicability_json,wire_schema_version,created_at) VALUES (?,?,?,?,?,?)",
            ("m-pref", "p1", "preference.output.language", json.dumps(applicability), "cognitive-memory.v4", NOW),
        )
        con.execute(
            "INSERT INTO memory_subject_bindings(memory_id,project_id,subject_kind,subject_id,created_at) VALUES (?,?,?,?,?)",
            ("m-pref", "p1", "user", "u1", NOW),
        )
        row = con.execute(
            """SELECT w.logical_key,w.applicability_json,s.subject_kind,s.subject_id
            FROM memory_wire_contracts_v2 w JOIN memory_subject_bindings s ON s.memory_id=w.memory_id
            WHERE w.memory_id='m-pref'"""
        ).fetchone()
        reconstructed = {
            "logicalKey": row[0],
            "applicability": json.loads(row[1]),
            "subject": {"kind": row[2], "id": row[3]},
        }
        ok = reconstructed == {
            "logicalKey": "preference.output.language",
            "applicability": applicability,
            "subject": {"kind": "user", "id": "u1"},
        }
        record("memory.preference_roundtrip", ok, json.dumps(reconstructed, sort_keys=True))
    except Exception as exc:
        record("memory.preference_roundtrip", False, str(exc))
    con.close()


def validate_benchmark_authority() -> None:
    con = clean_db()
    for artifact in ["suite-manifest", "case-art", "run-base", "run-cand", "comparison-art"]:
        add_artifact(con, artifact, task_id=None if artifact == "suite-manifest" else "t1", artifact_type="benchmark")
    try:
        con.execute(
            "INSERT INTO benchmark_suite_versions(row_id,project_id,logical_suite_id,version,manifest_artifact_id,manifest_digest,created_at) VALUES (?,?,?,?,?,?,?)",
            ("sv1", "p1", "quality-core", 1, "suite-manifest", SHA, NOW),
        )
        con.execute(
            "INSERT INTO benchmark_suite_versions(row_id,project_id,logical_suite_id,version,manifest_artifact_id,manifest_digest,created_at) VALUES (?,?,?,?,?,?,?)",
            ("sv2", "p1", "quality-core", 2, "suite-manifest", SHA, NOW),
        )
        record("benchmark.logical_suite_versioning", True, "same logical ID retained across versions")
    except Exception as exc:
        record("benchmark.logical_suite_versioning", False, str(exc))
        con.close()
        return

    case_values = (
        "cv1", "sv1", "case-a", 1, "case-art", SHA, OID_A, SHA, SHA, SHA, SHA, SHA, SHA, NOW
    )
    con.execute(
        """INSERT INTO benchmark_case_versions(row_id,suite_row_id,logical_case_id,case_version,case_artifact_id,case_artifact_digest,repository_revision,fixture_manifest_digest,objective_digest,budget_profile_digest,policy_digest,tool_permissions_digest,acceptance_rules_digest,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        case_values,
    )

    def run(run_id: str, arm: str, treatment: dict[str, str], artifact: str, revision: str = OID_A, budget: str = SHA, model: str = SHA, prompt: str = SHA, evaluator: str = SHA, policy: str = SHA, tools: str = SHA) -> None:
        con.execute(
            """INSERT INTO benchmark_run_receipts_v2(
            id,case_row_id,task_id,arm,controlled_configuration_digest,treatment_configuration_json,treatment_configuration_digest,
            actual_repository_revision,fixture_manifest_digest,objective_digest,budget_profile_digest,actual_usage_digest,
            policy_digest,tool_permissions_digest,model_digest,prompt_digest,evaluator_digest,acceptance_rules_digest,
            result_artifact_id,status,started_at,completed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run_id, "cv1", "t1", arm, SHA, json.dumps(treatment, sort_keys=True, separators=(",", ":")), SHA2 if run_id == "br-cand" else SHA, revision, SHA, SHA, budget, SHA2, policy, tools, model, prompt, evaluator, SHA, artifact, "completed", NOW, LATER),
        )

    base_treatment = {"retrievalPipeline": "v3.2", "contextCompiler": "v3.2", "memoryPolicy": "none"}
    candidate_treatment = {"retrievalPipeline": "v4.2", "contextCompiler": "v4.2", "memoryPolicy": "verified"}
    try:
        run("br-base", "control_no_memory", base_treatment, "run-base")
        run("br-cand", "evidence_plus_experience", candidate_treatment, "run-cand")
        con.execute(
            "INSERT INTO benchmark_comparison_receipts_v2(id,baseline_run_id,candidate_run_id,comparison_artifact_id,declared_treatment_dimensions_json,result,created_at) VALUES (?,?,?,?,?,?,?)",
            ("bc-ok", "br-base", "br-cand", "comparison-art", json.dumps(["retrievalPipeline", "contextCompiler", "memoryPolicy"]), "improved", NOW),
        )
        record("benchmark.declared_treatment_accepted", True, "controlled fields equal; declared treatment differs")
    except Exception as exc:
        record("benchmark.declared_treatment_accepted", False, str(exc))

    # A separate database avoids uniqueness interactions and proves revision mismatch is rejected at run admission.
    bad = clean_db()
    for artifact in ["suite-manifest", "case-art", "run-bad"]:
        add_artifact(bad, artifact, task_id=None if artifact == "suite-manifest" else "t1", artifact_type="benchmark")
    bad.execute("INSERT INTO benchmark_suite_versions VALUES (?,?,?,?,?,?,?)", ("sv1", "p1", "quality-core", 1, "suite-manifest", SHA, NOW))
    bad.execute(
        "INSERT INTO benchmark_case_versions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        case_values,
    )
    expect_blocked(
        "benchmark.revision_mismatch_rejected",
        lambda: bad.execute(
            """INSERT INTO benchmark_run_receipts_v2(id,case_row_id,task_id,arm,controlled_configuration_digest,treatment_configuration_json,treatment_configuration_digest,actual_repository_revision,fixture_manifest_digest,objective_digest,budget_profile_digest,actual_usage_digest,policy_digest,tool_permissions_digest,model_digest,prompt_digest,evaluator_digest,acceptance_rules_digest,result_artifact_id,status,started_at,completed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("br-bad", "cv1", "t1", "control_no_memory", SHA, json.dumps(base_treatment), SHA, "b" * 40, SHA, SHA, SHA, SHA, SHA, SHA, SHA, SHA, SHA, SHA, "run-bad", "completed", NOW, LATER),
        ),
        "revision",
    )
    bad.close()

    # Comparison must reject an undeclared difference.
    con2 = clean_db()
    for artifact in ["suite-manifest", "case-art", "run-base", "run-cand", "comparison-art"]:
        add_artifact(con2, artifact, task_id=None if artifact == "suite-manifest" else "t1", artifact_type="benchmark")
    con2.execute("INSERT INTO benchmark_suite_versions VALUES (?,?,?,?,?,?,?)", ("sv1", "p1", "quality-core", 1, "suite-manifest", SHA, NOW))
    con2.execute("INSERT INTO benchmark_case_versions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", case_values)
    def insert_con2(run_id: str, treatment: dict[str, str], artifact: str) -> None:
        con2.execute(
            """INSERT INTO benchmark_run_receipts_v2 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run_id, "cv1", "t1", "control_no_memory" if run_id.endswith("1") else "evidence_retrieval", SHA, json.dumps(treatment, sort_keys=True, separators=(",", ":")), SHA if run_id.endswith("1") else SHA2, OID_A, SHA, SHA, SHA, SHA2, SHA, SHA, SHA, SHA, SHA, SHA, artifact, "completed", NOW, LATER),
        )
    insert_con2("r1x1", base_treatment, "run-base")
    insert_con2("r2x2", {**base_treatment, "memoryPolicy": "verified"}, "run-cand")
    expect_blocked(
        "benchmark.undeclared_treatment_rejected",
        lambda: con2.execute(
            "INSERT INTO benchmark_comparison_receipts_v2 VALUES (?,?,?,?,?,?,?)",
            ("cmp-bad", "r1x1", "r2x2", "comparison-art", json.dumps(["retrievalPipeline"]), "equivalent", NOW),
        ),
        "undeclared treatment",
    )
    con2.close()
    con.close()


def validate_actor_proof() -> None:
    con = clean_db()
    add_artifact(con, "challenge-proof", artifact_type="credential_evidence")
    try:
        con.execute(
            "INSERT INTO actor_bindings(id,actor_kind,actor_id,session_id,proof_type,binding_digest,issued_at,expires_at,revoked_at,session_epoch) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("ab1", "user", "u1", "session-1", "local_authenticated_session", SHA, NOW, LATER, None, 1),
        )
        con.execute(
            "INSERT INTO credential_challenges(id,actor_binding_id,purpose,operation_digest,nonce,challenge_digest,issued_at,expires_at) VALUES (?,?,?,?,?,?,?,?)",
            ("ch1", "ab1", "deliverable.approval", SHA, "nonce-v42-abcdefghijklmnopqrstuvwxyz", SHA2, NOW, LATER),
        )
        con.execute(
            "INSERT INTO credential_challenge_receipts(id,challenge_id,actor_binding_id,proof_type,proof_artifact_id,verified_at,receipt_digest) VALUES (?,?,?,?,?,?,?)",
            ("chr1", "ch1", "ab1", "local_authenticated_session", "challenge-proof", NOW, SHA),
        )
        record("actor.challenge_valid", True, "current binding and one-time challenge accepted")
    except Exception as exc:
        record("actor.challenge_valid", False, str(exc))
    expect_blocked(
        "actor.challenge_replay_rejected",
        lambda: con.execute(
            "INSERT INTO credential_challenge_receipts(id,challenge_id,actor_binding_id,proof_type,proof_artifact_id,verified_at,receipt_digest) VALUES (?,?,?,?,?,?,?)",
            ("chr2", "ch1", "ab1", "local_authenticated_session", "challenge-proof", NOW, SHA2),
        ),
        ("UNIQUE", "consumed"),
    )
    con.close()



def validate_workflow_sql_journeys() -> None:
    # Journey 1: a read-only research task completes with an exact deliverable approval, no write phase.
    con = clean_db()
    add_artifact(con, "ro-deliverable", digest("1"), artifact_type="deliverable")
    add_artifact(con, "ro-evidence", digest("2"), artifact_type="evidence_set")
    add_artifact(con, "ro-objections", digest("3"), artifact_type="objection_set")
    add_artifact(con, "ro-evaluator", digest("4"), artifact_type="evaluation_receipt")
    add_artifact(con, "ro-proof", digest("5"), artifact_type="credential_evidence")
    actor_digest = digest("6")
    operation_digest = digest("7")
    con.execute(
        "INSERT INTO actor_bindings VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("ab-ro", "user", "u1", "session-ro", "local_authenticated_session", actor_digest, NOW, LATER, None, 1),
    )
    con.execute(
        "INSERT INTO credential_challenges VALUES (?,?,?,?,?,?,?,?)",
        ("ch-ro", "ab-ro", "deliverable.approval", operation_digest, "read-only-approval-nonce-0001", digest("8"), NOW, LATER),
    )
    con.execute(
        "INSERT INTO credential_challenge_receipts VALUES (?,?,?,?,?,?,?)",
        ("chr-ro", "ch-ro", "ab-ro", "local_authenticated_session", "ro-proof", "2026-08-04T08:00:01Z", digest("9")),
    )
    con.execute(
        "INSERT INTO task_workflow_authority VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("t1", "ReadOnlyResearch", "ReadOnlyDeliverable", "Intake", "core", None, digest("a"), NOW, NOW, None),
    )
    expect_blocked(
        "workflow.sql.arbitrary_jump_rejected",
        lambda: con.execute(
            "UPDATE task_workflow_authority SET phase='Completed',updated_at='2026-08-04T08:00:01Z',completed_at='2026-08-04T08:00:01Z' WHERE task_id='t1'"
        ),
        "invalid v4.2 workflow phase transition",
    )
    advance_workflow(
        con,
        [
            "ContextBuild", "ParallelAnalysis", "CrossReview", "PrePlanVerification",
            "Synthesis", "FinalObjection", "AwaitingDeliverableApproval",
        ],
        2,
    )
    con.execute(
        "INSERT INTO task_acceptance_receipts VALUES (?,?,?,?,?,?,?,?,?)",
        ("accept-ro", "t1", "deliverable", operation_digest, "ro-deliverable", "ab-ro", "chr-ro", "2026-08-04T08:00:20Z", digest("b")),
    )
    con.execute(
        "UPDATE task_workflow_authority SET phase='Completed',updated_at='2026-08-04T08:00:21Z',completed_at='2026-08-04T08:00:21Z' WHERE task_id='t1'"
    )
    con.execute("SAVEPOINT wrong_deliverable")
    try:
        con.execute(
            "INSERT INTO task_completion_packages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "complete-ro-bad", "t1", "ReadOnlyDeliverable", "ro-evidence", "ro-evidence",
                "ro-objections", "ro-evaluator", "accept-ro", None, None, None, None,
                "2026-08-04T08:00:22Z",
            ),
        )
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        record("workflow.sql.read_only_exact_acceptance", "deliverable acceptance" in str(exc), str(exc))
    else:
        record("workflow.sql.read_only_exact_acceptance", False, "mismatched accepted deliverable succeeded")
    finally:
        con.execute("ROLLBACK TO wrong_deliverable")
        con.execute("RELEASE wrong_deliverable")
    try:
        con.execute(
            "INSERT INTO task_completion_packages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "complete-ro", "t1", "ReadOnlyDeliverable", "ro-deliverable", "ro-evidence",
                "ro-objections", "ro-evaluator", "accept-ro", None, None, None, None,
                "2026-08-04T08:00:22Z",
            ),
        )
    except Exception as exc:
        record("workflow.sql.read_only_completion", False, str(exc))
    else:
        row = con.execute(
            "SELECT outcome_mode,deliverable_artifact_id,candidate_commit_oid FROM task_completion_packages WHERE id='complete-ro'"
        ).fetchone()
        record("workflow.sql.read_only_completion", row == ("ReadOnlyDeliverable", "ro-deliverable", None), str(row))
    con.close()

    # Journey 2: one exact immutable commit OID is prepared, verified, approved, consumed, and completed.
    con = clean_db()
    for artifact_id, artifact_type, ch in [
        ("git-verify", "verification_receipt", "c"),
        ("git-proof", "credential_evidence", "d"),
        ("git-evidence", "evidence_set", "e"),
        ("git-objections", "objection_set", "f"),
        ("git-evaluator", "evaluation_receipt", "0"),
        ("git-ref-promotion", "ref_promotion_receipt", "1"),
    ]:
        add_artifact(con, artifact_id, digest(ch), artifact_type=artifact_type)
    actor_digest = digest("2")
    operation_digest = SHA
    tree_oid = "c" * 40
    commit_oid = "d" * 40
    con.execute(
        "INSERT INTO actor_bindings VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("ab-git", "user", "u1", "session-git", "local_authenticated_session", actor_digest, NOW, LATER, None, 1),
    )
    con.execute(
        """INSERT INTO operation_intents(
          id,task_id,run_id,operation_kind,idempotency_class,idempotency_key,
          canonical_request_artifact_id,operation_digest,actor_binding_digest,status,
          current_attempt_no,created_at,updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("intent-git", "t1", "r1", "git.final_commit", "queryable", "intent-key-git", "a1", operation_digest, actor_digest, "pending", 0, NOW, NOW),
    )
    con.execute(
        "INSERT INTO final_commit_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("candidate-git", "t1", "intent-git", SHA, "refs/heads/main", OID_A, tree_oid, commit_oid, digest("4"), digest("5"), NOW),
    )
    con.execute(
        "INSERT INTO final_commit_verification_receipts VALUES (?,?,?,?,?,?,?,?,?)",
        ("verify-git", "candidate-git", "t1", tree_oid, commit_oid, digest("5"), "git-verify", "2026-08-04T08:00:01Z", digest("6")),
    )
    con.execute(
        "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("approval-git", "t1", "intent-git", "final_commit", "v4.2", operation_digest, actor_digest, "approval-git-nonce-00000001", "pending", NOW, None, LATER, "a1", None),
    )
    con.execute(
        "INSERT INTO credential_challenges VALUES (?,?,?,?,?,?,?,?)",
        ("ch-git", "ab-git", "final_commit.approval", operation_digest, "final-commit-challenge-000001", digest("7"), NOW, LATER),
    )
    con.execute(
        "INSERT INTO credential_challenge_receipts VALUES (?,?,?,?,?,?,?)",
        ("chr-git", "ch-git", "ab-git", "local_authenticated_session", "git-proof", "2026-08-04T08:00:02Z", digest("8")),
    )
    con.execute(
        "INSERT INTO approval_decision_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("receipt-git", "approval-git", "t1", "intent-git", operation_digest, actor_digest, "approval-git-nonce-00000001", "granted", "git-proof", "2026-08-04T08:00:03Z", digest("9")),
    )
    con.execute(
        "INSERT INTO approval_actor_proof_bindings VALUES (?,?,?,?)",
        ("receipt-git", "ab-git", "chr-git", "2026-08-04T08:00:04Z"),
    )
    con.execute(
        "UPDATE approvals SET status='granted',resolved_at='2026-08-04T08:00:03Z' WHERE id='approval-git'"
    )
    expect_blocked(
        "workflow.sql.commit_oid_substitution_rejected",
        lambda: con.execute(
            "INSERT INTO approval_effect_consumptions VALUES (?,?,?,?,?,?,?,?)",
            ("consume-bad", "receipt-git", "intent-git", SHA, "refs/heads/main", OID_A, "e" * 40, "2026-08-04T08:00:06Z"),
        ),
        "exact candidate tuple",
    )
    con.execute(
        "INSERT INTO approval_effect_consumptions VALUES (?,?,?,?,?,?,?,?)",
        ("consume-git", "receipt-git", "intent-git", SHA, "refs/heads/main", OID_A, commit_oid, "2026-08-04T08:00:07Z"),
    )
    con.execute(
        "INSERT INTO task_workflow_authority VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("t1", "Standard", "LocalCommit", "Intake", "core", None, digest("a"), NOW, NOW, None),
    )
    advance_workflow(
        con,
        [
            "ContextBuild", "ParallelAnalysis", "CrossReview", "PrePlanVerification",
            "Synthesis", "FinalObjection", "AwaitingPlanApproval", "Implementation",
            "Verification", "FinalReview", "AwaitingCommitApproval", "RefPromotion",
        ],
        8,
    )
    con.execute("SAVEPOINT missing_ref_receipt")
    try:
        con.execute(
            "UPDATE task_workflow_authority SET phase='Completed',updated_at='2026-08-04T08:00:30Z',completed_at='2026-08-04T08:00:30Z' WHERE task_id='t1'"
        )
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        record("workflow.sql.ref_completion_without_receipt_rejected", "successful ref promotion" in str(exc), str(exc))
    else:
        record("workflow.sql.ref_completion_without_receipt_rejected", False, "workflow completed without a ref-promotion receipt")
    finally:
        con.execute("ROLLBACK TO missing_ref_receipt")
        con.execute("RELEASE missing_ref_receipt")
    expect_blocked(
        "workflow.sql.ref_promotion_oid_substitution_rejected",
        lambda: con.execute(
            "INSERT INTO ref_promotion_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("ref-bad", "t1", "candidate-git", "consume-git", SHA, "refs/heads/main", OID_A, "e" * 40, "git-ref-promotion", "2026-08-04T08:00:29Z", digest("1")),
        ),
        "exact approved candidate tuple",
    )
    con.execute(
        "INSERT INTO ref_promotion_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("ref-git", "t1", "candidate-git", "consume-git", SHA, "refs/heads/main", OID_A, commit_oid, "git-ref-promotion", "2026-08-04T08:00:29Z", digest("1")),
    )
    con.execute(
        "UPDATE task_workflow_authority SET phase='Completed',updated_at='2026-08-04T08:00:30Z',completed_at='2026-08-04T08:00:30Z' WHERE task_id='t1'"
    )
    try:
        con.execute(
            "INSERT INTO task_completion_packages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "complete-git", "t1", "LocalCommit", None, "git-evidence", "git-objections",
                "git-evaluator", None, "receipt-git", tree_oid, commit_oid,
                "git-ref-promotion", "2026-08-04T08:00:31Z",
            ),
        )
    except Exception as exc:
        record("workflow.sql.exact_commit_completion", False, str(exc))
    else:
        row = con.execute(
            "SELECT candidate_tree_oid,candidate_commit_oid,final_approval_receipt_id FROM task_completion_packages WHERE id='complete-git'"
        ).fetchone()
        record("workflow.sql.exact_commit_completion", row == (tree_oid, commit_oid, "receipt-git"), str(row))
    con.close()

def validate_traceability_and_docs() -> None:
    trace = ROOT / "36-v4.2-product-traceability-matrix.md"
    if not trace.exists():
        record("traceability.full_product", False, "missing")
    else:
        text = trace.read_text(encoding="utf-8")
        prd = (ROOT / "01-product-requirements.md").read_text(encoding="utf-8")
        ids = sorted(set(re.findall(r"\b(?:FR|NFR)-\d{3}\b", prd)))
        missing = [i for i in ids if i not in text]
        record("traceability.full_product", not missing, f"mapped={len(ids)-len(missing)}/{len(ids)} missing={missing}")
    gates = (ROOT / "19-assurance-release-gates.md").read_text(encoding="utf-8")
    for phrase in ["typed memory/retrieval/context compiler", "verified learning", "quality dashboard/comparison", "public improvement claim"]:
        record(f"gates.{phrase.replace(' ','_')}", phrase in gates and "G11" in gates and "G12" in gates, phrase)
    roadmap = (ROOT / "11-mvp-roadmap.md").read_text(encoding="utf-8")
    record("roadmap.sqlite_v6_authority", "SQLite v6" in roadmap and "SQLite v2 baseline" not in roadmap, "current authority stated")
    readme = (ROOT / "00-README.md").read_text(encoding="utf-8")
    record("readme.v42_authority", "workflow-transitions.v2.json" in readme and "sqlite-v6.sql" in readme, "v4.2 authority map")


def main() -> int:
    validate_contract_files()
    validate_workflow()
    validate_schema_examples()
    validate_sql_install_and_migration()
    validate_terminal_status_matrix()
    validate_preference_roundtrip()
    validate_benchmark_authority()
    validate_actor_proof()
    validate_workflow_sql_journeys()
    validate_traceability_and_docs()
    passed = sum(checks)
    print(f"\n{passed}/{len(checks)} v4.2 end-to-end checks passed")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
