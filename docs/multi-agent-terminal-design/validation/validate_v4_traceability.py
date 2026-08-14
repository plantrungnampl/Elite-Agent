#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
checks: list[bool] = []


def record(name: str, ok: bool, detail: str) -> None:
    checks.append(ok)
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def contains_all(name: str, path: str, values: list[str]) -> None:
    body = text(path)
    missing = [v for v in values if v not in body]
    record(name, not missing, "all present" if not missing else "missing: " + ", ".join(missing))


def main() -> int:
    required_files = [
        "24-cognitive-memory-agent-quality.md",
        "25-v4-self-review-report.md",
        "26-v3.2-to-v4-migration-contract.md",
        "27-v4-traceability-matrix.md",
        "V4-CHANGELOG.md",
        "schemas/sqlite-v3.sql",
        "schemas/migrate-v2-to-v3.sql",
        "schemas/cognitive-memory.v1.schema.json",
        "schemas/agent-quality-benchmark.v1.schema.json",
        "validation/validate_v4_memory.py",
        "docs/superpowers/specs/2026-08-04-cognitive-memory-agent-quality-design.md",
        "docs/superpowers/plans/2026-08-04-cognitive-memory-agent-quality.md",
    ]
    missing = [p for p in required_files if not (ROOT / p).exists()]
    record("files.v4_normative_set", not missing, "all present" if not missing else "missing: " + ", ".join(missing))

    contains_all("requirements.functional", "01-product-requirements.md", [f"FR-{n:03d}" for n in range(29, 38)])
    contains_all("requirements.nonfunctional", "01-product-requirements.md", [f"NFR-{n:03d}" for n in range(11, 15)])
    contains_all("architecture.ports", "02-system-architecture.md", ["trait RetrievalEngine", "trait MemoryRepository", "trait ContextCompiler", "trait RunEvaluator", "trait LearningEngine"])
    record("architecture.no_public_vector_port", "pub trait VectorStore" not in text("02-system-architecture.md"), "VectorStore is adapter-private")
    contains_all("protocol.cognitive_methods", "03-agent-protocol.md", ["context.request_more", "context.request_source", "agent.fact.record", "context.feedback", "agent.run.reflect"])
    contains_all("memory.taxonomy", "04-context-memory.md", ["Working", "Episodic", "Semantic", "Procedural", "Negative", "Preference"])
    contains_all("memory.barriers", "04-context-memory.md", ["retrieval results are candidates", "agent reflection produces proposals", "Model agreement and self-reported success are never sufficient"])
    contains_all("security.cognitive_threats", "06-security-threat-model.md", ["Memory poisoning", "Cross-project memory leakage", "Retrieval manipulation", "Reflection self-approval"])
    contains_all("ux.cognitive_surfaces", "08-desktop-ux.md", ["Context debugger", "Memory explorer", "Learning review queue", "Agent quality dashboard", "Degraded-state UX"])
    contains_all("testing.quality", "09-testing-reliability.md", ["Locked benchmark corpus", "Memory conformance tests", "Learning-loop tests", "Agent quality metrics"])
    contains_all("roadmap.mq", "11-mvp-roadmap.md", [f"MQ{n}" for n in range(0, 7)])
    contains_all("adr.cognitive", "12-architecture-decisions.md", [f"ADR-{n:03d}" for n in range(29, 37)])
    contains_all("release.cognitive_gates", "19-assurance-release-gates.md", ["G11", "G12"])
    contains_all("trust.retrieval_sidecar_tier", "13-trust-sandbox-model.md", ["Retrieval sidecar classification", "MUST run as `brokered_process`", "no repository or user-profile ACL", "exact executable, manifest, policy, and network tuple"])
    contains_all("recovery.retrieval_sessions", "15-crash-consistency-recovery.md", ["open `retrieval_sessions`", "status = 'indeterminate'", "retry creates a new retrieval session"])
    contains_all("invariants.cognitive", "20-invariant-registry.md", [f"COG-{n:03d}" for n in range(1, 19)])
    contains_all("migration.sequence", "26-v3.2-to-v4-migration-contract.md", ["Deterministic legacy analysis", "Backfill write sequence", "Derived state rebuild", "Quarantine", "Acceptance evidence", "clean-install and migrated databases have identical normalized schema objects"])
    contains_all("traceability.requirements", "27-v4-traceability-matrix.md", [f"FR-{n:03d}" for n in range(29, 38)] + [f"NFR-{n:03d}" for n in range(11, 15)])

    sql = text("schemas/sqlite-v3.sql")
    tables = [
        "memory_records", "memory_evidence_links", "memory_relations", "memory_promotion_reviews",
        "working_memory_snapshots", "episodes", "episode_steps", "index_generations",
        "retrieval_sessions", "retrieval_candidates", "context_package_items", "context_item_feedback",
        "run_reflections", "run_evaluations", "benchmark_suites", "benchmark_cases",
        "benchmark_runs", "benchmark_comparisons",
    ]
    missing_tables = [t for t in tables if f"CREATE TABLE {t}" not in sql]
    record("schema.sqlite_tables", not missing_tables, "all present" if not missing_tables else "missing: " + ", ".join(missing_tables))
    contains_all("schema.sqlite_lifecycle_guards", "schemas/sqlite-v3.sql", ["artifact identity replacement is forbidden", "artifact records are retained", "invalid artifact availability transition", "invalid artifact verification transition", "verified memory requires current supporting evidence", "approved memory requires a current granted promotion review", "OLD.status='stale' AND NEW.status IN ('superseded','retracted')", "superseded memory requires a newer linked version", "idx_memory_records_one_active_version", "active memory requires activation time equal to lifecycle transition time", "status IN ('running','succeeded','degraded','failed','indeterminate')", "terminal retrieval requires completion time and exact trace artifact", "terminal retrieval branch status is immutable", "idx_agent_runs_context_package_once", "memory records are retained", "legacy memory entries are read-only after v4 schema installation", "legacy memory entries are retained after v4 schema installation", "run evaluations are immutable", "b.system_configuration_digest=c.system_configuration_digest", "benchmark comparison inputs are not comparable"])
    contains_all("schema.incremental_migration", "schemas/migrate-v2-to-v3.sql", ["Incremental migration", "artifacts_replacement_forbidden", "artifacts_delete_forbidden", "artifacts_availability_transition", "artifacts_verification_transition", "memory_entries_insert_forbidden", "memory_entries_update_forbidden", "memory_entries_delete_forbidden", "status IN ('running','succeeded','degraded','failed','indeterminate')", "CREATE TABLE memory_records", "COMMIT;"])

    cognitive = json.loads(text("schemas/cognitive-memory.v1.schema.json"))
    defs = cognitive.get("$defs", {})
    expected_defs = {
        "sourceReference", "retrievalRequest", "retrievalCandidate", "retrievalResult",
        "memoryScope", "memoryProposal", "contextItem", "contextBudget", "taskState",
        "workingMemoryState", "permissionEnvelope", "redactionReceipt", "contextPackage",
        "contextSupplementRequest", "contextSupplement", "workingMemoryEvent",
        "contextFeedback", "runReflection", "runEvaluation",
    }
    record("schema.cognitive_defs", expected_defs == set(defs), f"{len(expected_defs & set(defs))}/{len(expected_defs)} definitions")
    package_required = set(defs["contextPackage"].get("required", []))
    record(
        "schema.context_package_complete",
        {"successCriteria", "budget", "taskState", "workingMemory", "requiredChecks", "permissions", "provenance", "redactions", "promptTemplateVersion"} <= package_required,
        "role context, budget, permissions, provenance, and redaction receipts are mandatory",
    )
    record(
        "schema.preference_scope_complete",
        "subject" in defs["memoryProposal"].get("properties", {}) and "memoryScope" in defs,
        "preference subject and structured scope are machine-readable",
    )
    proposal_types = set(defs["memoryProposal"]["properties"]["memoryType"]["enum"])
    durable_memory_ddl = sql[sql.index("CREATE TABLE memory_records"):sql.index("CREATE TABLE memory_evidence_links")]
    record(
        "schema.no_working_memory_promotion",
        "working" not in proposal_types and "'working'" not in durable_memory_ddl,
        "working memory is snapshot-only and cannot enter durable memory authority",
    )

    plan = text("docs/superpowers/plans/2026-08-04-cognitive-memory-agent-quality.md")
    tasks = set(re.findall(r"^### Task (\d+):", plan, re.M))
    record("plan.tasks", tasks == {str(i) for i in range(1, 13)}, f"{len(tasks)}/12 implementation tasks")
    record("readme.sqlite_v3_normative", "schemas/sqlite-v3.sql" in text("00-README.md"), "README references SQLite v3")
    record("storage.sqlite_v3_normative", "normative v4.0 clean-install DDL" in text("07-storage-data-model.md") and "sqlite-v3.sql" in text("07-storage-data-model.md"), "storage document selects SQLite v3")
    record("contracts.sqlite_v3_normative", "`sqlite-v3.sql` — authoritative v4.0" in text("schemas/README.md"), "machine contracts select SQLite v3")

    passed = sum(checks)
    print(f"\n{passed}/{len(checks)} v4 traceability checks passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
