# v4.0 Cognitive Memory Traceability Matrix

This matrix connects requirements to design authority, machine-readable contracts, tests, UX, and delivery milestones. A row is complete only when every listed artifact exists and agrees on terminology and lifecycle.

| Requirement | Design authority | Storage/schema | Validation evidence | UX/operations | Delivery |
|---|---|---|---|---|---|
| FR-029 Typed memory lifecycle | `04` §§4, 12; `24` §§4, 6 | `memory_records`, evidence, relations, reviews | `memory.*` v4 negative tests | Memory Explorer, learning review | MQ1 |
| FR-030 Role-aware hybrid retrieval | `04` §§7–9; `02` §10.1 | retrieval sessions/candidates, index generations | retrieval and index conformance tests | Context Debugger branch trace | MQ2 |
| FR-031 Cognitive context compilation | `04` §§5–6; ADR-032 | context packages/items | context scope/hash/candidate tests | Context Debugger | MQ3 |
| FR-032 Progressive context | `04` §10; protocol §16 | immutable supplements as artifacts plus package receipts | cognitive JSON Schema examples and protocol plan tests | Package/supplement timeline | MQ3, M4 |
| FR-033 Verified learning loop | `04` §12; ADR-033 | reflections, evaluations, memory proposals/reviews | reflection/evaluation/promotion tests | Learning review queue | MQ4 |
| FR-034 Agent quality evaluation | `04` §13; `09` §12 | `run_evaluations` | terminal-run and immutability tests | Quality dashboard | MQ4–MQ5 |
| FR-035 Memory/context inspection | `08` §11 | item-level provenance and lifecycle history | reconstruction and scope tests | Context Debugger, Memory Explorer | M2, MQ4 |
| FR-036 Benchmark and comparison | `24` §8; `09` §12 | benchmark suites/cases/runs/comparisons | comparability negative test | Quality dashboard | MQ0, MQ5 |
| FR-037 Degraded cognitive operation | `04` §19; `02` §10.2 | index generation and retrieval branch status | degraded adapter conformance | Degraded-state UX and rebuild operation | MQ2, MQ6 |
| NFR-011 Memory integrity | `04` §§3, 12, 18 | lifecycle, evidence, promotion, scope triggers | v4 cognitive adversarial suite | explicit status and evidence display | G11 |
| NFR-012 Explainability | `04` §§6, 9; ADR-032 | retrieval trace and context item records | hash/source/candidate match tests | inclusion reasons and provenance | MQ3 |
| NFR-013 Quality measurability | `24` §8; ADR-035 | benchmark authority records | equal-input comparison tests | per-case regression dashboard | MQ0, MQ5, G12 |
| NFR-014 Replaceable retrieval | ADR-031; `02` cognitive ports | index generations remain disposable | adapter conformance and rebuild tests | health/degraded controls | MQ2, MQ6 |

## Invariant-to-test index

| Invariant | Primary test family |
|---|---|
| COG-001 | proposal/promotion boundary and adapter conformance |
| COG-002 | retrieval/context source hash and candidate binding |
| COG-003 | cross-project artifact, evidence, relation, context, feedback tests |
| COG-004 | direct activation and review-before-verified tests |
| COG-005 | verified/approved/active transition tests |
| COG-006 | active/unexpired retrieval and context tests |
| COG-007 | evaluation/reflection immutability tests |
| COG-008 | protocol supplement budget and permission tests in implementation plan Task 4 |
| COG-009 | route-complete privacy suite and remote disclosure tests |
| COG-010 | benchmark evaluator/configuration comparability test |
| COG-011 | index generation lifecycle and delete/rebuild release evidence |
| COG-012 | implementation plan Task 8 repeated-error guard |
| COG-013 | stale records cannot be reactivated; fresh version and supersession are required |
| COG-014 | one context manifest per run; effective-content hash is non-self-referential |
| COG-015 | retained legacy memory remains readable but post-v4 insert/update/delete are rejected |
| COG-016 | artifact metadata deletion, identity replacement, quarantine resurrection, and rejected-to-approved promotion are rejected; supported transitions pass |
| COG-017 | running retrieval can close as traced `indeterminate`; missing trace and terminal rewrite are rejected |
| COG-018 | retrieval sidecar tier text and exact-tuple release gate are structurally validated; runtime containment remains a release artifact |

## Contract ownership

| Contract | Owner | Non-owner restrictions |
|---|---|---|
| Memory lifecycle | Domain + MemoryRepository | Retrieval and Learning Engines may not transition authority state |
| Candidate retrieval | RetrievalEngine adapter | Scores do not become facts or permissions |
| External retrieval sidecar | Launcher + RetrievalEngine adapter | Defaults to `brokered_process`; no ambient repository/profile/SQLite/Artifact Store access |
| Retrieval crash reconciliation | Recovery service | Unproved outcome becomes traced terminal `indeterminate`; retry creates a new session |
| Final context bytes | Context Compiler | Agents and indexes cannot bypass source re-read or policy |
| Working-memory facts/inferences | Working Memory Manager | Agent statements remain typed assertions until evidenced |
| Run outcome | Workflow verifier | Reflection cannot determine success |
| Quality gate | Run Evaluator + workflow | Optional judge model remains advisory |
| Lesson proposal | Learning Engine | Proposal cannot activate itself |
| Benchmark comparison | Benchmark service | Mismatched fixtures/configuration produce `invalid` |

