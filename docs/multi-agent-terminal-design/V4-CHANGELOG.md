# v4.0 Changelog

## Cognitive Memory and Agent Quality Revamp

- Replaced static context retrieval design with a verified cognitive lifecycle.
- Added working, episodic, semantic, procedural, negative, and scoped preference memory.
- Added Retrieval Planner, replaceable Hybrid Retrieval Engine, Context Compiler, Working Memory Manager, Learning Engine, and Run Evaluator boundaries.
- Made retrieval/index engines non-authoritative and retained policy, redaction, exact model-input serialization, promotion, and provenance in the trusted core.
- Added progressive context, contradiction retrieval, evidence expansion, context feedback, and repeated-error prevention.
- Added immutable run reflection/evaluation and evidence-backed memory promotion.
- Made stale memory terminal for activation; reuse requires a fresh version and `supersedes` relation.
- Separated context manifests from effective model-input byte artifacts and bound each package to exactly one run.
- Added structured fact/inference/unknown/hypothesis working memory with evidence requirements.
- Added benchmark corpus and strict equal-configuration quality comparison requirements with per-case regression disclosure.
- Added cognitive memory UX, threat controls, operations, roadmap, release gates, ADRs, and invariants.
- Added SQLite v3 authority schema with 18 cognitive tables, a deterministic v2-to-v3 migration, cognitive JSON Schema, quality benchmark schema, and examples.
- Added clean-install versus migrated-schema equivalence validation and quarantine rules for ambiguous legacy data.
- Froze legacy `memory_entries` at v4 schema installation with database-level insert/update/delete guards while preserving read-only migration access.
- Added database-enforced artifact availability and verification transition graphs; artifact metadata is retained, identity replacement is blocked, and quarantined/rejected artifacts cannot be resurrected or promoted in place.
- Added terminal `indeterminate` retrieval sessions with exact trace evidence and startup reconciliation that creates a new session for retry.
- Classified the optional external retrieval sidecar as `brokered_process` by default, with explicit `isolated_worker` escalation and exact-tuple containment gates.
- Added a 12-task test-first implementation plan and full requirement/design/schema/test/delivery traceability.
- Repeatedly self-reviewed and hardened lifecycle, provenance, cross-project isolation, SQLite NULL semantics, single-active-version rules, atomic activation, exact terminal retrieval traces, artifact/digest binding, feedback binding, benchmark update scope/comparability, index/benchmark immutability, and package status language.
