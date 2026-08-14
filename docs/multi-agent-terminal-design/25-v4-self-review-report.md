# v4.0 Self-Review Report

## 1. Verdict

The v4.0 package is complete as a **self-reviewed architecture, machine-contract, migration, validation, traceability, and implementation-plan baseline** for the Cognitive Memory and Agent Quality revamp.

It is suitable for implementation to begin. It is not a completed Tauri/Rust product and it does not prove that agent memory or task quality has improved in runtime. Those claims remain gated by the locked benchmark, implementation tests, migration rehearsal, performance measurements, privacy tests, and release gates defined in this package.

Final package validation:

| Suite | Result |
|---|---:|
| Historical core regression | 39/39 passed |
| v3.2 adversarial hardening | 68/68 passed |
| v4 cognitive memory and quality | 79/79 passed |
| v4 traceability | 30/30 passed |
| Full package validation | 56/56 passed |

## 2. Review scope

The self-review covered:

- requirements and non-functional requirements;
- cognitive architecture and authority boundaries;
- agent protocol extensions;
- memory lifecycle and provenance;
- hybrid retrieval and degraded operation;
- immutable context compilation and progressive context;
- working memory, reflection, evaluation, and verified learning;
- negative-memory repeated-error prevention;
- SQLite v3 clean-install and v2-to-v3 migration equivalence;
- JSON Schemas and examples;
- UX, security, operations, roadmap, assurance gates, and invariants;
- requirement-to-design-to-schema-to-test-to-delivery traceability;
- implementation task boundaries, interfaces, test commands, and completion evidence;
- regression compatibility with the v3.2 safety baseline.

The review intentionally did not treat document consistency as proof of runtime properties. Model quality, retrieval quality, latency, containment, crash behavior, migration against real user data, and usability still require implementation evidence.

## 3. Final architecture outcome

v4.0 replaces static retrieval-centered memory design with this verified lifecycle:

```text
Observe
  → Retrieve
  → Compile immutable context
  → Agent act
  → Verify outcome
  → Evaluate quality
  → Reflect and propose lessons
  → Verify/review memory
  → Activate a new memory version
```

The final design establishes these boundaries:

1. **SQLite and the Artifact Store remain authoritative.** FTS, vector, graph, reranking, and external Hybrid Memory Engines are disposable projections.
2. **Retrieval returns candidate references only.** It cannot grant permission, activate memory, or decide the final model input.
3. **The Context Compiler owns final disclosure.** It re-reads authoritative sources, verifies revision/hash, applies policy/redaction, budgets tokens, serializes exact effective bytes, and records an immutable manifest.
4. **Working memory is recoverable but unverified.** Facts require evidence; inference and hypothesis require supporting fact IDs and confidence.
5. **Learning produces proposals only.** Reflection and optional model judges cannot directly create active long-term memory.
6. **Promotion is evidence- and review-backed.** A memory follows controlled lifecycle transitions and every active version is reconstructible.
7. **Stale versions never reactivate in place.** Reuse requires a new candidate, fresh evidence and review, and a `supersedes` relation.
8. **Quality claims require equal-input comparison.** Aggregate gains may not hide per-case regressions or changed budgets/configuration.

## 4. Review rounds and repaired findings

### Round 1 — Cognitive contract completeness

The first pass added the memory taxonomy, cognitive ports, protocol payloads, lifecycle storage, quality benchmark contract, UX surfaces, security threats, roadmap, and release gates.

The first validator execution exposed an error in its own SQLite fixtures: several test `INSERT` statements did not match the evolved column lists. The fixtures were corrected before any schema verdict was accepted.

### Round 2 — Promotion authority and provenance

Automated tests were initially green while manual inspection found paths that were still too weak:

- direct updates could attempt to activate memory without the complete lifecycle;
- `verified` did not yet require current supporting evidence at transition time;
- `approved` and `active` did not yet require a current granted review;
- provenance needed stronger same-project and hash binding;
- context feedback could be associated with a run that had not consumed that package;
- protocol schema coverage did not yet include all reflection, progressive-context, and structured working-memory payloads.

The schema and validators were strengthened so these paths fail at the authority boundary, not merely in application convention.

### Round 3 — Migration equivalence and terminal evidence

The migration was rewritten from a conceptual note into an executable contract:

- clean install and migrated databases must have equal normalized `sqlite_master` definitions;
- deterministic destination IDs, logical keys, and version chains are required;
- every imported record starts as `candidate`;
- legacy status is replayed only through controlled transitions;
- ambiguous data is quarantined rather than guessed;
- vector values, ranks, inferred graph state, and caches are rebuilt rather than imported as authority;
- index and benchmark completion evidence is write-once.

The migration validator now constructs both databases and confirms **294/294 normalized schema objects are equivalent**.

### Round 4 — Stale-memory replay attack

Manual lifecycle review found that a stale record could theoretically reuse old evidence and review data if reactivation were permitted. Rather than adding increasingly complex “fresh-after-stale” timestamp rules, the design chose the safer invariant:

> A stale memory version is terminal for activation. A corrected or revalidated lesson must be a new version with new evidence/review and an explicit `supersedes` relation.

This removes ambiguous evidence reuse and preserves history.

### Round 5 — SQLite NULL semantics and structured scope

SQLite `CHECK` expressions can pass when an expression evaluates to `NULL`. Structured JSON checks were therefore changed to use explicit `COALESCE`/presence validation so missing applicability or preference subject values cannot pass accidentally.

A final taxonomy pass also found that `working` was still accepted as a durable `memory_records.memory_type` even though working memory already had a separate snapshot authority and could not be proposed by the JSON contract. It was removed from durable records entirely; working memory is now snapshot-only.

Preference memory now requires an explicit subject, while all durable memory proposals require machine-readable scope, sensitivity, evidence, and invalidation conditions.

### Round 6 — Context receipt integrity

Two manual issues were corrected:

1. A manifest field named `contentHash` could be misread as the hash of the manifest containing that same field. The contract now defines it as the SHA-256 of the **separate effective model-input bytes artifact**.
2. A context package could otherwise be reused across runs. A package is now bound to exactly one preallocated run through an authority uniqueness constraint.

Context supplements inherit the parent package's scope, permissions, redaction policy, and remaining budget; they cannot broaden them.

### Round 7 — Benchmark and index mutation

Completed benchmark runs/comparisons and completed index generations were checked for mutable result/evidence fields. Terminal result/evidence assignment is now write-once. Comparisons with unequal cases, revisions, budgets, evaluator versions, policy, tool permissions, or model configuration are invalid rather than “approximately comparable.”

### Round 8 — Implementation handoff quality

The initial implementation plan was too high-level for independent agent execution. It was rewritten into 12 bounded tasks with:

- exact files to create/modify;
- consumed and produced interfaces;
- failing tests first;
- concrete commands and expected outcomes;
- minimal implementation rules;
- independent commits;
- final benchmark and release-evidence tasks.

A final type/name pass removed plan examples that referenced fields absent from the canonical JSON Schema.

### Round 9 — Terminal receipts, active-version uniqueness, and benchmark comparability

A column-by-column authority pass found several update-path gaps that insert-only checks did not cover:

- activation evidence could be preloaded or use a timestamp different from the lifecycle transition;
- an already expired memory could become active;
- two versions of one logical key could both be active;
- working-memory and reflection digests were not yet matched to their artifact bytes;
- terminal retrieval could omit its exact trace artifact or mutate branch status afterward;
- benchmark suite digest was not matched to its manifest artifact;
- terminal benchmark result scope was checked on insert but not when the result was attached by update;
- benchmark comparison matched evaluator configuration but not system configuration.

All paths were closed in SQLite and added to the permanent cognitive adversarial suite.

### Round 10 — Legacy memory governance

A post-review adversarial check found that the retained `memory_entries` table still accepted arbitrary inserts, lifecycle-forging updates such as `rejected → active`, and deletes. The weak legacy `verification_method` check was not a v4 evidence or review control.

The fix makes `memory_entries` read-only at v4 schema installation in both the clean schema and incremental migration. Database triggers reject insert, update, and delete while preserving `SELECT` for deterministic migration planning and backfill. Permanent regression tests cover clean-install insertion, migrated-row readability, status-forging update, and deletion.

### Round 12 — Artifact lifecycle, sidecar trust, and retrieval crash state

A final open-control review found three gaps: artifact availability and verification values had enums but no transition graph; the optional retrieval sidecar had no normative trust-tier assignment; and a crash-open retrieval session could not represent an unknown outcome.

The package now installs artifact transition guards in the v3.2 baseline, clean v4 schema, and incremental migration. artifact metadata is retained and cannot be replaced; `quarantined` and `rejected` are terminal in place while legitimate availability and verification progress remains supported. The external retrieval sidecar defaults to `brokered_process`, with a separate `isolated_worker` profile required when a mounted task volume or local execution is necessary. `retrieval_sessions` now accepts terminal `indeterminate` with exact trace evidence, and startup recovery creates a new session for retry rather than rewriting the uncertain receipt.

Permanent regression coverage includes artifact deletion/replacement/resurrection/promotion attacks, supported artifact transitions, traced retrieval uncertainty, missing-trace rejection, terminal immutability, sidecar classification, and startup-reconciliation contract checks.

### Round 11 — Package truthfulness

The final review detected stale README language describing the package primarily as v3.2. It was corrected to state that v4.0 is an implementation-oriented baseline, not a running product and not proof of quality improvement.

## 5. Machine-contract inventory

SQLite v3 contains:

| Object type | Count |
|---|---:|
| Tables | 50 |
| Indexes | 35 |
| Triggers | 209 |
| Total normalized schema objects | 294 |

Eighteen tables are dedicated to the cognitive subsystem:

- memory records, evidence, relations, and promotion reviews;
- working-memory snapshots and episodes;
- index generations and retrieval traces;
- context package items and feedback;
- reflections and evaluations;
- benchmark suites, cases, runs, and comparisons.

The cognitive JSON Schema contains 19 canonical definitions covering retrieval, source references, scoped proposals, context manifests/supplements, working-memory events, feedback, reflection, and evaluation. The benchmark schema separately locks corpus identity and comparison configuration.

## 6. Traceability result

All v4 functional and non-functional additions are linked to:

- normative design sections;
- SQLite/JSON contract locations;
- automated or planned implementation tests;
- UX/operations surfaces;
- MQ milestone and release gate.

The traceability validator confirms 30/30 structural requirements, including removal of a public `VectorStore` application port, mandatory context provenance/redaction/budget fields, explicit preference scope, non-promotable working memory, migration presence, and 12/12 implementation tasks.

## 7. Remaining implementation risks

These are not design-document defects; they are runtime questions that cannot be honestly closed before implementation:

1. **Benchmark validity:** the corpus must represent real coding, debugging, review, migration, and research tasks rather than favoring the new architecture.
2. **Retrieval effectiveness:** rank fusion, reranker choice, contradiction recall, and evidence expansion need measured precision/recall.
3. **Latency and scale:** context compilation, source re-read, graph expansion, and startup reconciliation require large-repository profiling.
4. **Memory quality:** false lessons, overspecific applicability, duplicate memory, and preference drift need operational monitoring.
5. **Judge reliability:** model-based evaluation remains advisory and must not override deterministic failed evidence.
6. **UX usability:** Context Debugger, Memory Explorer, learning review, and quality dashboard require user testing.
7. **Migration realism:** synthetic equivalence passes, but representative v3.2 databases and interrupted migrations still require rehearsal.
8. **Containment:** external agents and retrieval sidecars remain disabled until exact-tuple installed-product containment and disclosure tests pass.
9. **Trigger complexity:** 209 triggers demand strict repository encapsulation, generated schema documentation, interaction tests, and performance measurement.

## 8. Completion boundary

### Complete in this package

- v4 requirements and cognitive architecture;
- authority and trust boundaries;
- machine-readable SQLite/JSON contracts;
- deterministic incremental migration contract;
- adversarial cognitive validation;
- full cross-document traceability;
- UX, security, operations, roadmap, gates, and invariants;
- task-level implementation plan;
- historical regression compatibility;
- final self-review and checksum-ready package.

### Not yet complete

- Rust/Tauri/React implementation;
- real embedded/sidecar retrieval adapters;
- real model-provider integrations;
- real migration against production data;
- measured benchmark improvement;
- performance, usability, crash, race, and installed-product containment evidence;
- permission to enable write, final commit, external process, or public quality/security claims.

## 9. Final decision

No unresolved architecture contradiction or known contract bypass remains in the reviewed package. The correct next action is implementation against the included task plan, beginning with MQ0 quality baseline and the SQLite v3 authority layer. Further speculative redesign should be rejected unless implementation or benchmark evidence exposes a concrete deficiency.

## v4.2 correction to the historical conclusion

The earlier statement that no unresolved architecture contradiction or known
contract bypass remained was too broad. Structural and known-negative suites
were green, but read-only completion, exact candidate-commit semantics,
terminal-status persistence, benchmark comparability, preference round-trip,
retrieval recovery, actor proof, and full traceability had not been exercised as
end-to-end journeys.

v4.2 replaces that claim with: the encoded v4.2 workflow and cross-contract
journeys pass the dedicated gap suite, while runtime quality, external
containment, and product value remain conditional on their separate evidence.
