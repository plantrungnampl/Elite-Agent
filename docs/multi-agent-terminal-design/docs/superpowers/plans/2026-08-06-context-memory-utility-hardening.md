# Context and Memory Utility Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the v4.0 cognitive-memory design package to a v4.1 contract that separates authoritative state from experience memory and adds executable invalidation, shadow evaluation, utility measurement, adaptive budgeting, and controlled benchmark arms.

**Architecture:** Preserve all v3.2 and v4.0 authority contracts as historical baselines. Add versioned v4.1 JSON and SQLite contracts, additive migration, examples, validators, and updated normative documents. The implementation is contract-first: new negative tests fail before the new contracts are added.

**Tech Stack:** Markdown, JSON Schema Draft 2020-12, SQLite STRICT tables/triggers, Python 3 validation, SHA-256 package manifest.

## Global Constraints

- Existing v3.2 and v4.0 validation suites must remain green.
- New durable memory never starts active.
- Current authoritative state outranks experience memory.
- Model-generated semantic, procedural, and negative memory requires shadow evidence for deterministic or policy approval.
- Invalidation rules must be machine-readable and evaluable.
- Derived utility projections cannot mutate authority records.
- Historical records are retained; consolidation creates new authority events or versions.
- No quality-improvement claim is allowed without controlled benchmark evidence.

---

### Task 1: Add failing v4.1 contract validator

**Files:**
- Create: `validation/validate_v41_memory_utility.py`

**Interfaces:**
- Consumes: `schemas/sqlite-v4.sql`, `schemas/migrate-v3-to-v4.sql`, `schemas/cognitive-memory.v2.schema.json`, `schemas/agent-quality-benchmark.v2.schema.json`.
- Produces: executable negative and positive checks with a stable summary line.

- [ ] Write tests that require the nine new SQLite tables, v2 schema definitions, typed invalidation, state precedence guards, shadow-promotion guards, immutable usage evidence, and adaptive budget receipts.
- [ ] Run `python validation/validate_v41_memory_utility.py` and verify it fails because the v4.1 contracts do not exist.
- [ ] Keep the validator independent of runtime implementation and deterministic.

### Task 2: Add versioned JSON contracts and examples

**Files:**
- Create: `schemas/cognitive-memory.v2.schema.json`
- Create: `schemas/agent-quality-benchmark.v2.schema.json`
- Create: `schemas/examples-v41/state-record.example.json`
- Create: `schemas/examples-v41/memory-proposal.example.json`
- Create: `schemas/examples-v41/memory-shadow-evaluation.example.json`
- Create: `schemas/examples-v41/context-budget-decision.example.json`
- Create: `schemas/examples-v41/benchmark-suite.example.json`

**Interfaces:**
- Produces definitions `stateRecord`, `stateResolutionReceipt`, `invalidationRule`, `invalidationEvaluation`, `memoryShadowEvaluation`, `memoryUsageEvent`, `memoryConsolidationAction`, `contextBudgetDecision`, and updated `memoryProposal`/`contextPackage`.

- [ ] Define closed, typed invalidation rules with conditional required fields.
- [ ] Define state scope, authority kind, precedence, validity, evidence, and supersession.
- [ ] Define shadow and contribution evidence without allowing authority mutation.
- [ ] Define benchmark experiment arms and equal-input comparison requirements.
- [ ] Validate all examples against their exact definitions.

### Task 3: Add SQLite v4 clean-install and migration contracts

**Files:**
- Create: `schemas/sqlite-v4.sql`
- Create: `schemas/migrate-v3-to-v4.sql`

**Interfaces:**
- Consumes: complete `schemas/sqlite-v3.sql` authority baseline.
- Produces: additive schema v4 and migration with equivalent database objects.

- [ ] Copy the v3 clean-install contract and append the nine v4.1 tables.
- [ ] Add scope, immutability, lifecycle, shadow-promotion, digest, and cross-record guards.
- [ ] Add indexes for state resolution, invalidation due work, utility lookup, and benchmark analysis.
- [ ] Create an additive migration that installs the same objects without modifying retained v3 rows.
- [ ] Run clean-install and migration-equivalence checks.

### Task 4: Update cognitive architecture and quality proof documents

**Files:**
- Modify: `04-context-memory.md`
- Modify: `24-cognitive-memory-agent-quality.md`
- Modify: `11-mvp-roadmap.md`
- Modify: `07-storage-data-model.md`
- Modify: `09-testing-reliability.md`

**Interfaces:**
- Consumes: approved design spec.
- Produces: normative explanation aligned with v2 JSON and SQLite v4.

- [ ] Replace the single memory-centric model with State, Evidence, and Experience stores.
- [ ] Document precedence, typed invalidation, shadow evaluation, contribution scoring, consolidation, adaptive budget, and stopping rules.
- [ ] Reduce MVP scope and move optional breadth to later milestones.
- [ ] Add tests and metrics for controlled cognitive ablations.

### Task 5: Add v4.1 migration, traceability, self-review, and changelog documents

**Files:**
- Create: `28-v4.1-context-memory-hardening.md`
- Create: `29-v4.1-self-review-report.md`
- Create: `30-v4.1-traceability-matrix.md`
- Create: `31-v4.0-to-v4.1-migration-contract.md`
- Create: `V4.1-CHANGELOG.md`

**Interfaces:**
- Produces: explicit delta, known limits, requirement-to-contract mapping, and upgrade sequence.

- [ ] State what v4.1 improves and what remains unproven.
- [ ] Map each cognitive requirement to docs, JSON, SQL, and validation checks.
- [ ] Describe additive migration, rollback boundary, reindex behavior, and benchmark reset rules.

### Task 6: Add bootstrap benchmark corpus

**Files:**
- Create: `benchmarks/README.md`
- Create: `benchmarks/context-memory-bootstrap-v1.json`
- Create: `benchmarks/fixtures/state-records.json`
- Create: `benchmarks/fixtures/memory-records.json`

**Interfaces:**
- Consumes: benchmark v2 schema.
- Produces: controlled cases covering precedence, stale memory, negative memory, contradiction, and token-cost trade-offs.

- [ ] Add at least eight cases across the four experiment arms.
- [ ] Ensure each case has required facts, evidence, forbidden mistakes, and acceptance rules.
- [ ] Mark the corpus as a bootstrap contract corpus, not proof of production quality.

### Task 7: Integrate package validation and normative references

**Files:**
- Modify: `validation/validate_package.py`
- Create: `validation/validate_v41_traceability.py`
- Modify: `schemas/README.md`
- Modify: `00-README.md`
- Modify: `19-assurance-release-gates.md`
- Modify: `20-invariant-registry.md`

**Interfaces:**
- Produces: package-wide validation that runs v3, v3.2, v4.0, and v4.1 suites.

- [ ] Register v2 schema examples and bootstrap benchmark validation.
- [ ] Make SQLite v4 the normative clean-install contract while retaining v3 historical references.
- [ ] Add v4.1 release gates and invariants.
- [ ] Run package validation and fix every broken link, schema error, or traceability gap.

### Task 8: Final verification and package manifest

**Files:**
- Modify: `SHA256SUMS.txt`
- Modify: `validation/PACKAGE-VALIDATION-RESULTS.md`
- Modify: `validation/package-validation-results.json`

**Interfaces:**
- Produces: reproducible zip package with verified checksums.

- [ ] Run all validators independently.
- [ ] Run `python validation/validate_package.py` and require all checks to pass.
- [ ] Regenerate SHA-256 sums after all generated validation reports are stable.
- [ ] Re-run checksum verification and package validation.
- [ ] Create the final zip archive.
