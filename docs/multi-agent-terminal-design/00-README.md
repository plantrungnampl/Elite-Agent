# Local-First Multi-Agent Engineering Terminal — Design Baseline v4.3

**Design package status:** Self-reviewed implementation and product-proof baseline. Contract coherence is executable; live model quality, external-runtime containment, and market adoption remain unproven.  
**Date:** 2026-08-07  
**Target platform:** Windows-first, portable core  
**Primary stack:** Tauri + Rust + React + TypeScript

v4.3 preserves the v4.2 safety, exact-object finalization, crash consistency, and governed cognitive-memory design. It closes protocol-document drift and workflow-authority bypasses, adds reconstructible provider/model run configuration and explicit assurance degradation, and moves a fair single-vs-multi product proof ahead of broad memory expansion.

## 1. Product definition

The product is a local-first desktop engineering environment in which AI agents analyze a task, challenge assumptions, request evidence, collaborate through governed messages, and—only after policy and approval—produce verified changes in an isolated Git worktree.

It is not a multi-model chat shell. The trusted core owns workflow state, context disclosure, tool mediation, evidence, approval, persistence, budgets, and recovery. Provider adapters and external agents are untrusted workers.

## 2. Locked decisions

| Area | v4.3 decision |
|---|---|
| Default product proof | Compare against a strong single agent with the same retrieval and deterministic verification |
| Workflow authority | Trusted application reducer; SQLite rejects projections without matching accepted commands/events |
| Profiles | Quick, Standard, HighAssurance, ReadOnlyResearch |
| Escalation | Receipt-backed `Quick -> Standard -> HighAssurance`; no silent or in-task downgrade |
| Read-only conversion | A write request creates an explicitly approved child task |
| Provider setup | One provider is sufficient; additional providers are optional |
| Run identity | Immutable `RunConfiguration v1`; credential material excluded |
| Independence | Fingerprint provider, model family, prompt, context, retrieval, tools, and adapter implementation |
| High Assurance | Hard executor/reviewer separation plus policy-defined distinct groups |
| Degradation | Pause, cancel, or continue only with a visible actor-proved receipt |
| Protocol | MAT Agent Control Protocol v2 over stdio/JSON-RPC first; ACP/MCP bridges remain adapters, not authority |
| Context | Authoritative state + source evidence + eligible experience memory |
| Actions | Read-first; one fenced executor for writes; exact approval for final effects |
| Git | Per-task branch/worktree; local commit only in MVP |
| Storage | SQLite authority + content-addressed artifacts + deterministic reconciliation |
| Product sequencing | Real read-only slice and equal-budget orchestration proof before write breadth and memory breadth |

## 3. Package map

### Core design

1. [Product requirements](01-product-requirements.md)
2. [System architecture](02-system-architecture.md)
3. [MAT Agent Control Protocol](03-agent-protocol.md)
4. [Cognitive context and memory](04-context-memory.md)
5. [Workflow orchestration](05-workflow-orchestration.md)
6. [Security and threat model](06-security-threat-model.md)
7. [Storage and data model](07-storage-data-model.md)
8. [Desktop UX](08-desktop-ux.md)
9. [Testing and reliability](09-testing-reliability.md)
10. [Operations and packaging](10-operations-packaging.md)
11. [MVP roadmap v4.3](11-mvp-roadmap.md)
12. [Architecture decisions](12-architecture-decisions.md)
13. [Trust and sandbox model](13-trust-sandbox-model.md)
14. [Finalization and approval integrity](14-finalization-approval-integrity.md)
15. [Crash consistency and recovery](15-crash-consistency-recovery.md)
16. [Workflow transitions v4.3](16-workflow-transition-specification.md)
17. [Review resolution matrix](17-review-resolution-matrix.md)
18. [Validation report](18-validation-report.md)
19. [Assurance and release gates](19-assurance-release-gates.md)
20. [Invariant registry](20-invariant-registry.md)

### v4.3 delta

- [Implementation and product-proof baseline](38-v4.3-implementation-product-proof.md)
- [Run configuration, independence, and assurance](39-run-configuration-and-assurance.md)
- [Orchestration product-proof benchmark](40-orchestration-product-proof-benchmark.md)
- [Self-review report](41-v4.3-self-review-report.md)
- [v4.2-to-v4.3 migration](42-v4.2-to-v4.3-migration-contract.md)
- [v4.3 changelog](V4.3-CHANGELOG.md)

### Historical evidence

Documents 21–37 and changelogs through v4.2 remain immutable migration, audit, traceability, and regression evidence. They describe the authority of their own release and must not be read as the current v4.3 selection.

## 4. Current machine authority

- `schemas/sqlite-v7.sql` — clean-install authority;
- `schemas/migrate-v6-to-v7.sql` — exact v4.2-to-v4.3 migration;
- `schemas/workflow-transitions.v3.json` — profile/outcome/event/guard/effect rules;
- `schemas/workflow-transition-command.v1.schema.json` — reducer command artifact;
- `schemas/agent-protocol.v2.schema.json` — MAT Agent Control Protocol v2;
- `schemas/run-configuration.v1.schema.json` — provider/model/adapter/policy/budget/fallback/independence snapshot;
- `schemas/assurance-degradation-receipt.v1.schema.json`;
- `schemas/cognitive-memory.v4.schema.json` — current cognitive payload authority;
- orchestration benchmark suite, run-receipt, case-result, and comparison-report v1 schemas;
- context/memory benchmark v3 contracts, retained for their narrower treatment question;
- `schemas/product-traceability.v43.json` — all 51 current FR/NFR rows.

Earlier SQLite, workflow, cognitive, and benchmark contracts are historical inputs. New v4.3 records must not use conflicting earlier authority.

## 5. System invariants

1. Current instruction and approved authority outrank historical experience.
2. Events, artifacts, receipts, approvals, and source evidence are immutable or corrected by new records.
3. A workflow phase changes only through a declared, accepted transition event at the expected stream version.
4. Every required guard and effect is bound before an event becomes accepted.
5. Profile escalation is monotonic and separate from phase transition.
6. No untrusted agent receives ambient filesystem, shell, registry, credential, or network authority.
7. Only the current fenced executor may request authoritative writes.
8. A final approval binds one pre-created immutable Git object and one canonical logical effect.
9. Retrieval projections are rebuildable candidates, never authority.
10. Provider/model fallback is visible and creates a new run configuration.
11. High-assurance degradation is visible, immutable, and actor-proved when execution continues.
12. Quality claims require equal-budget paired evidence and category-level disclosure.
13. Fake agents are test fixtures and cannot satisfy a real-runtime or product-proof gate.
14. Cross-store success is never assumed; recovery reconciles SQLite and artifacts explicitly.

## 6. Delivery sequence

1. **S0 Contract repair** — v7 authority, protocol fixtures, run configuration, assurance, package validation.
2. **S1 Real read-only vertical slice** — one real supported runtime, repository onboarding, Quick task, evidence, report, cancel, restart/resume, Simple Mode.
3. **S2 Multi-agent proof** — strong single-agent baselines versus Quick, Standard, High Assurance, sampling, and heterogeneous arms under equal budgets.
4. **S3 Mediated write** — worktree broker, one fenced executor, write/process/test tools, verification, repair.
5. **S4 Exact local commit** — complete candidate object, exact approval, expected-old-value ref CAS.
6. **S5 Evidence retrieval** — exact/FTS first; vector only after measured lift.
7. **S6 Memory and learning** — negative memory first; broader learning only after isolated evidence.

See [the detailed roadmap](11-mvp-roadmap.md).

## 7. Assurance status

| Capability | Package verdict | Required runtime evidence |
|---|---|---|
| Protocol/document conformance | GO | Included fixtures and validator |
| Workflow structural authority | GO | Included negative/positive SQLite suite |
| Real read-only runtime | NOT YET PROVEN | S1 adapter, recovery, cancellation, privacy, and user-task evidence |
| Orchestration quality claim | NO-GO | S2 representative paired equal-budget result |
| Structured mutation | Disabled by default | S3 broker, fencing, race, crash, and verification gates |
| Exact local commit | Disabled by default | S4 exact-object and ref-CAS integration evidence |
| Broad experience memory | Deferred | S6 isolated treatment lift and harm controls |
| External process containment | NO-GO | Installed-tuple Windows adversarial evidence |
| Product adoption claim | NO-GO | Real user retention, correction-effort, and task-success evidence |

## 8. Validation

Run:

```bash
python validation/validate_package.py
```

The runner executes all historical suites, the v4.3 implementation/product-proof suite, schema/example checks, protocol fixture identity, v7 clean/migration parity, workflow bypass tests, traceability, relative links, and placeholder hygiene.

The generated reports are:

- `validation/V4.3-IMPLEMENTATION-PRODUCT-PROOF-RESULTS.md`;
- `validation/PACKAGE-VALIDATION-RESULTS.md`;
- their machine-readable JSON equivalents.

Passing these checks proves the encoded contracts are coherent. It does not prove live model quality, provider behavior, containment on every Windows configuration, or market adoption.
## 9. Historical compatibility index

These statements identify prior release authority for their own regression suites; none overrides the current v4.3 selection above.

- **Design Baseline v4.0** used `schemas/sqlite-v3.sql` and `schemas/cognitive-memory.v1.schema.json`.
- **Design Baseline v4.1** used `schemas/sqlite-v4.sql` and `schemas/cognitive-memory.v2.schema.json`.
- **Design Baseline v4.1.1** used `schemas/sqlite-v5.sql` and `schemas/cognitive-memory.v3.schema.json`.
- **Design Baseline v4.2** used `schemas/sqlite-v6.sql`, `schemas/migrate-v5-to-v6.sql`, and `schemas/workflow-transitions.v2.json`.

Historical validators assert that these references remain discoverable so migrations and archived evidence stay self-describing.
