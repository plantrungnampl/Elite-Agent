# Context and Memory Utility Hardening Design

**Status:** Approved for implementation by the user's request to improve the existing v4.0 package directly.

## 1. Problem

The v4.0 package has strong authority, provenance, lifecycle, and anti-poisoning controls, but its cognitive usefulness is under-specified. In particular:

- current authoritative state, durable experience, and retrieval evidence share overlapping abstractions;
- memory invalidation conditions are natural-language strings rather than executable rules;
- the package records retrieval feedback but does not measure per-memory contribution, utility, duplication, or token cost;
- machine-generated memory can be approved without a controlled shadow comparison;
- context budgets are expressed as static defaults rather than an auditable adaptive decision;
- benchmark contracts define cases but not controlled experiment arms that isolate the value of compaction, evidence retrieval, and experience memory.

The result is a system that is safe to store memory but not yet rigorous about what should be remembered, when it should be retrieved, and when it should be consolidated or retired.

## 2. Goals

1. Preserve the v4.0 authority and safety invariants.
2. Separate authoritative current state from experience memory.
3. Make invalidation conditions typed, executable, and auditable.
4. Make context allocation adaptive while retaining deterministic receipts.
5. Measure whether each memory item contributed positively, negatively, or not at all.
6. Require shadow evidence before deterministic or policy promotion of model-generated durable memory.
7. Add consolidation and pruning without deleting authority history.
8. Add benchmark experiment arms that isolate the effect of each cognitive subsystem.
9. Keep the first implementation slice smaller than the full v4.0 cognitive surface.

## 3. Non-goals

- autonomous cross-project memory federation;
- deletion of historical authority records;
- model-controlled activation of durable memory;
- a general-purpose knowledge graph platform;
- replacing repository, artifact, event, receipt, or user-approved decision authority;
- proving runtime quality gains from design validation alone.

## 4. Architecture

The cognitive subsystem is divided into three stores.

### 4.1 Authoritative State Store

Stores current, structured, scoped values needed to resolve the present task. Examples include current user instruction, task override, approved architecture decision, project setting, and explicit preference.

Resolution precedence is fixed:

1. current explicit instruction;
2. task override;
3. approved decision;
4. project setting;
5. explicit user preference;
6. inferred preference.

A state record includes a typed key, JSON value, scope, authority kind, precedence rank, evidence, validity window, status, and optional supersession link. State resolution emits an immutable receipt identifying all candidates, the winner, the rule version, and the resulting digest.

### 4.2 Evidence Store

Uses the existing authoritative artifacts, repository sources, immutable events, tool receipts, decisions, and verified outputs. Retrieval candidates remain non-authoritative until source reread and freshness checks complete.

### 4.3 Experience Memory Store

Stores verified historical experience: episodes, semantic lessons that are not current state, procedures, negative memory, and retained preference history. New current preferences are written to the State Store first. Experience memory never overrides a higher-precedence active state record.

## 5. Executable invalidation

Every new durable memory proposal uses one or more typed invalidation rules. Supported initial rule kinds are:

- `source_hash_changed`;
- `source_revision_outside_range`;
- `path_modified`;
- `dependency_version_changed`;
- `schema_version_changed`;
- `test_result_changed`;
- `policy_changed`;
- `time_expired`;
- `manual_revoke`.

Each rule contains a stable rule identifier, rule kind, target, expected condition, evaluation cadence, and human-readable explanation. Evaluations are immutable receipts. A failed current evaluation makes the memory ineligible for retrieval and requires a new memory version for reuse.

## 6. Promotion and shadow evaluation

The authority lifecycle remains candidate, verified, approved, active, rejected, stale, superseded, and retracted.

For model-generated semantic, procedural, or negative memory:

- deterministic or policy approval requires at least one passing shadow evaluation;
- a shadow evaluation compares an equal-input control run against a run where the candidate memory is available;
- the candidate must not increase forbidden mistakes, unsupported claims, stale-memory use, or cross-scope leakage;
- explicit user approval may override the shadow requirement, and the override remains auditable.

Preference memory sourced from an explicit user instruction is represented as current state and does not require shadow evaluation.

## 7. Memory contribution and utility

Immutable usage events record whether a memory was retrieved, included, cited, used in a conclusion, judged helpful, judged misleading, and its token cost. A rebuildable utility projection calculates:

- successful-use count;
- harmful-use count;
- repeated-error reduction;
- evaluator helpfulness;
- recency and freshness;
- token cost;
- redundancy penalty;
- final utility score.

The utility projection is advisory. It may change ranking and trigger review, consolidation, or retirement proposals, but cannot directly mutate memory authority status.

## 8. Consolidation and retirement

A consolidation action may propose `merge`, `split`, `retain`, `supersede`, `mark_stale`, or `retract`. It references all input memories, a resulting memory version where applicable, evidence, and reviewer decision. Historical records are retained. Duplicate active memories with overlapping scope must be surfaced for review.

## 9. Adaptive context compilation

Context compilation follows this order:

1. resolve authoritative state;
2. decompose the objective into information needs;
3. retrieve repository and evidence sources;
4. retrieve eligible experience memory;
5. run contradiction and invalidation checks;
6. allocate layer budgets from task class, risk, coverage, unresolved questions, and expected marginal utility;
7. compile the smallest sufficient package;
8. request progressive supplements only when the expected value exceeds token and latency cost.

Every budget decision is persisted as an immutable receipt. Static percentages remain fallback profiles only.

## 10. Benchmark design

Benchmark v2 defines controlled experiment arms:

- `control_no_memory`;
- `compaction_only`;
- `evidence_retrieval`;
- `evidence_plus_experience`.

Each case binds repository revision, fixtures, budget, required facts, required evidence, forbidden mistakes, expected information needs, and acceptance rules. Comparisons use equal inputs, model configuration, evaluator configuration, repository revision, and budget profile.

Primary metrics include first-pass verifier acceptance, repeated known-error rate, unsupported-claim rate, stale-memory use, cross-scope leakage, token cost, latency, and per-memory contribution.

## 11. Storage changes

SQLite v4 extends v3 with:

- `state_records`;
- `state_evidence_links`;
- `state_resolution_receipts`;
- `memory_invalidation_evaluations`;
- `memory_shadow_evaluations`;
- `memory_usage_events`;
- `memory_utility_snapshots`;
- `memory_consolidation_actions`;
- `context_budget_decisions`.

The migration is additive and preserves all v3 rows. Legacy v4.0 cognitive contracts remain historical inputs.

## 12. Compatibility

- `cognitive-memory.v1.schema.json` remains unchanged as the v4.0 historical contract.
- `cognitive-memory.v2.schema.json` is the v4.1 normative cognitive contract.
- `agent-quality-benchmark.v2.schema.json` is the v4.1 normative benchmark contract.
- `sqlite-v3.sql` remains the historical v4.0 clean-install contract.
- `sqlite-v4.sql` and `migrate-v3-to-v4.sql` become normative for v4.1.

## 13. Validation

The implementation must prove:

- clean-install SQLite v4 succeeds;
- v3-to-v4 migration preserves existing rows and installs an equivalent schema;
- invalidation rules reject malformed or non-executable forms;
- state resolution cannot cross project/task scope and obeys precedence;
- deterministic/policy promotion cannot bypass required shadow evidence;
- usage and utility records cannot mutate memory authority;
- consolidation cannot delete or silently rewrite source memories;
- budget decisions bind the exact context package and policy digest;
- v2 schemas compile and all examples validate;
- all v3.2 and v4.0 regressions remain green.

## 14. MVP reduction

The runtime MVP implements only:

1. authoritative state;
2. evidence retrieval;
3. negative and procedural experience memory;
4. typed invalidation;
5. immutable context packages;
6. contribution logging;
7. benchmark experiment arms.

Full semantic auto-extraction, preference inference, autonomous consolidation, remote retrieval, and cross-project memory remain deferred.
