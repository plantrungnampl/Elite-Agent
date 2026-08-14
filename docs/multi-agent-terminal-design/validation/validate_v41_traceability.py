#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SC = ROOT / "schemas"
checks: list[bool] = []


def record(name: str, ok: bool, detail: str) -> None:
    checks.append(ok)
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def contains(path: str, terms: list[str]) -> bool:
    text = (ROOT / path).read_text(encoding="utf-8")
    return all(term in text for term in terms)


def main() -> int:
    required_files = [
        "28-v4.1-context-memory-hardening.md",
        "29-v4.1-self-review-report.md",
        "30-v4.1-traceability-matrix.md",
        "31-v4.0-to-v4.1-migration-contract.md",
        "V4.1-CHANGELOG.md",
        "schemas/sqlite-v4.sql",
        "schemas/migrate-v3-to-v4.sql",
        "schemas/cognitive-memory.v2.schema.json",
        "schemas/agent-quality-benchmark.v2.schema.json",
        "benchmarks/context-memory-bootstrap-v1.json",
    ]
    missing = [p for p in required_files if not (ROOT / p).exists()]
    record("files.v41_normative_set", not missing, "all present" if not missing else ", ".join(missing))

    memory_terms = [
        "Authoritative State Store",
        "Evidence Store",
        "Experience Memory Store",
        "Typed invalidation",
        "Shadow evaluation",
        "Adaptive context budgeting",
        "Contribution measurement",
        "Consolidation and retirement",
    ]
    record("docs.memory_architecture", contains("04-context-memory.md", memory_terms), "all v4.1 cognitive concepts present")
    record(
        "docs.quality_ablation",
        contains("24-cognitive-memory-agent-quality.md", ["control_no_memory", "compaction_only", "evidence_retrieval", "evidence_plus_experience"]),
        "four experiment arms present",
    )
    record(
        "docs.roadmap_state_first",
        contains("11-mvp-roadmap.md", ["MQ1 — Authoritative state foundation", "MQ3 — Minimal experience memory", "MQ5 — Contribution and shadow learning"]),
        "measurement and state precede memory breadth",
    )

    cognitive = json.loads((SC / "cognitive-memory.v2.schema.json").read_text(encoding="utf-8"))
    defs = cognitive["$defs"]
    required_defs = {
        "stateRecord",
        "stateResolutionReceipt",
        "invalidationRule",
        "invalidationEvaluation",
        "memoryShadowEvaluation",
        "memoryUsageEvent",
        "memoryConsolidationAction",
        "contextBudgetDecision",
    }
    record("schema.v2_defs", required_defs <= set(defs), f"{len(required_defs & set(defs))}/{len(required_defs)} definitions")
    record(
        "schema.memory_proposal_typed_rules",
        "invalidationRules" in defs["memoryProposal"]["required"] and "invalidationConditions" not in defs["memoryProposal"]["properties"],
        "v2 proposals require typed rules",
    )
    record(
        "schema.context_package_v2",
        defs["contextPackage"]["properties"]["schemaVersion"].get("const") == "cognitive-context.v2"
        and all(x in defs["contextPackage"]["required"] for x in ["resolvedState", "budgetDecision", "informationNeeds", "stoppingReason"]),
        "state, needs, budget, and stopping evidence required",
    )

    benchmark = json.loads((SC / "agent-quality-benchmark.v2.schema.json").read_text(encoding="utf-8"))
    arms = set(benchmark["properties"]["experimentArms"]["items"]["enum"])
    expected_arms = {"control_no_memory", "compaction_only", "evidence_retrieval", "evidence_plus_experience"}
    record("schema.benchmark_arms", arms == expected_arms, "exact four controlled arms")
    corpus = json.loads((ROOT / "benchmarks/context-memory-bootstrap-v1.json").read_text(encoding="utf-8"))
    record("benchmark.bootstrap_cases", len(corpus.get("cases", [])) >= 8, f"{len(corpus.get('cases', []))} cases")
    record("benchmark.equal_input_rules", all(corpus["comparisonRules"].values()), "all equal-input comparison rules enabled")

    sql = (SC / "sqlite-v4.sql").read_text(encoding="utf-8")
    tables = [
        "state_records",
        "state_evidence_links",
        "state_resolution_receipts",
        "memory_invalidation_evaluations",
        "memory_shadow_evaluations",
        "memory_usage_events",
        "memory_utility_snapshots",
        "memory_consolidation_actions",
        "context_budget_decisions",
    ]
    record("schema.sqlite_v41_tables", all(f"CREATE TABLE {t}" in sql for t in tables), "all nine tables present")
    trigger_terms = [
        "state_records_precedence_insert",
        "state_resolution_scope_insert",
        "memory_records_v41_typed_invalidation_insert",
        "retrieval_candidate_v41_memory_eligibility",
        "memory_promotion_v41_shadow_gate",
        "memory_utility_update_forbidden",
        "context_budget_scope_insert",
    ]
    record("schema.sqlite_v41_guards", all(t in sql for t in trigger_terms), "all critical guards present")

    migration = (SC / "migrate-v3-to-v4.sql").read_text(encoding="utf-8")
    record("schema.additive_migration", all(f"CREATE TABLE {t}" in migration for t in tables) and "DROP TABLE" not in migration, "additive tables, no destructive drop")

    record("readme.v41_title", contains("00-README.md", ["Design Baseline v4.1", "sqlite-v4.sql", "cognitive-memory.v2.schema.json"]), "README selects v4.1 normative contracts")
    record("storage.v41_normative", contains("07-storage-data-model.md", ["sqlite-v4.sql", "migrate-v3-to-v4.sql", "state_resolution_receipts"]), "storage document selects SQLite v4")
    record("release.v41_gates", contains("19-assurance-release-gates.md", ["Authoritative state", "typed invalidation", "shadow", "memory contribution"]), "release evidence covers v4.1")
    record("invariants.v41", contains("20-invariant-registry.md", ["COG-019", "COG-020", "COG-021", "COG-022", "COG-023"]), "new invariants registered")
    record("migration.v41", contains("31-v4.0-to-v4.1-migration-contract.md", ["typed invalidation", "Preference migration", "Benchmark reset", "Rollback boundary"]), "migration boundaries explicit")
    record("traceability.v41", contains("30-v4.1-traceability-matrix.md", ["State precedence", "Policy promotion", "Context allocation", "Benchmark isolates"]), "requirements mapped to contracts and checks")

    passed = sum(checks)
    print(f"\n{passed}/{len(checks)} v4.1 traceability checks passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
