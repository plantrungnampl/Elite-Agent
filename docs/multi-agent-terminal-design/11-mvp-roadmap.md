# MVP Delivery Roadmap v4.3

## 1. Delivery principle

Build the smallest real product slice that can falsify the product thesis. Governance, write authority, retrieval, and memory expand only after the preceding slice produces executable evidence. A milestone is incomplete when it uses only fake agents where the gate requires a real runtime.

## 2. S0 — Contract repair

Implement the current v4.3 machine authority:

- SQLite v7 and v6-to-v7 migration;
- workflow reducer commands, transition events, guard/effect bindings, and stream versions;
- protocol v2 fixtures and conformance harness;
- immutable run configuration and exact run binding;
- profile escalation and assurance degradation receipt;
- package validation and traceability.

**Exit:** historical regressions and v4.3 checks pass after fresh extraction; known raw-update, profile-route, missing-approval, missing-effect, replay, downgrade, and scope attacks are rejected.

## 3. S1 — Real read-only vertical slice

Ship one end-to-end user path with one supported real runtime:

1. onboard a local repository;
2. create a task in Simple Mode;
3. select or auto-select Quick/ReadOnlyResearch;
4. construct a policy-filtered context package;
5. launch one real agent through MAT Agent Control Protocol or a conforming bridge;
6. stream progress and evidence;
7. cancel and resume safely;
8. produce a source-linked report;
9. import selected results into task context;
10. recover after application restart.

Fake agents remain deterministic test fixtures and cannot satisfy this gate.

**Exit:** at least ten representative internal tasks complete without manual database repair; every report reconstructs its context, run configuration, evidence, and terminal receipt; cancel/restart tests pass.

## 4. S2 — Multi-agent proof

Run the equal-budget orchestration suite with:

- `single_direct`;
- `single_with_retrieval_and_verification`;
- `same_model_multi_sample`;
- `quick_profile`;
- `standard_cross_review`;
- `high_assurance`;
- `heterogeneous_models`.

Measure accepted outcome, defect escapes, first-pass tests, unsupported claims, omissions, human correction, time, tokens, tools, cost, approval interruptions, abandonment, and unique reviewer findings.

**Exit:** a reproducible paired report reaches `pass`, `fail`, or `inconclusive` without budget violations or hidden category regressions. Product defaults follow the evidence: multi-agent is not the default for categories where it does not earn its cost.

## 5. S3 — Mediated write

Add:

- repository/worktree broker;
- mutation detection;
- one fenced executor lease;
- structured file write, process, and test tools;
- policy decisions and operation receipts;
- implementation, verification, and repair loops;
- crash reconciliation.

**Exit:** direct ambient writes are impossible; stale fencing tokens and external workspace mutation are detected; deterministic verification evidence is bound to each candidate.

## 6. S4 — Exact local commit

Add complete candidate commit construction before approval, final verification, exact approval tuple, one-time approval consumption, and expected-old-value ref CAS.

**Exit:** tree/commit substitution, stale base, approval replay, hook-policy drift, and ref races are rejected; restart recovery preserves the exact candidate object.

## 7. S5 — Evidence retrieval

Implement information-need decomposition, exact/FTS search, source reread, repository graph expansion, freshness and contradiction checks, and trace receipts. Keep vector retrieval behind a replaceable adapter.

**Exit:** source reconstruction and required-evidence recall meet the locked corpus threshold; indexes can be deleted and rebuilt; vector retrieval remains disabled unless it produces measured incremental lift.

## 8. S6 — Memory and learning

Start with working checkpoints, verified episodes, and negative memory. Add procedures, semantic lessons, preference inference, and consolidation only through isolated shadow evaluation and explicit gates.

**Exit:** invalidated memory is excluded; negative memory prevents the locked repeated-error cases; no model-generated durable memory is promoted without exact origin, evidence, invalidation, and comparison receipts.

## 9. Deferred scope

- remote distributed agents and A2A production integration;
- marketplace, billing, and multi-user authority;
- broad semantic auto-extraction;
- autonomous split/merge or consolidation;
- cloud-only retrieval dependency;
- cross-project memory federation;
- public claims about secure containment or quality without corresponding evidence.

## 10. Stop conditions

Stop or simplify the product when evidence shows any of the following:

- the strong single-agent baseline matches orchestrated quality at lower correction effort and cost;
- user abandonment or approval interruption exceeds the locked threshold;
- provider/runtime containment cannot meet the supported Windows policy;
- write recovery cannot preserve exact authority;
- memory treatments produce category-level harm or unverifiable promotion.

A negative result is a product decision, not a reason to add more architecture.
## 11. Historical milestone alias index

The following aliases are retained only so earlier release evidence remains navigable. They do not change the S0–S6 execution order. v4.2 used **SQLite v6** as its clean-install authority.

- `MQ0` — Controlled quality baseline
- `MQ1 — Authoritative state foundation`
- `MQ2` — Evidence retrieval
- `MQ3 — Minimal experience memory`
- `MQ4` — Adaptive Context Compiler
- `MQ5 — Contribution and shadow learning`
- `MQ6` — Agent quality proof

In v4.3, their surviving work is resequenced behind S1 real-runtime and S2 product-proof evidence.
