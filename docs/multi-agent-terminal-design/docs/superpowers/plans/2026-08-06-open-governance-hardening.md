# Open Governance Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Close the remaining artifact lifecycle, retrieval-sidecar trust classification, and retrieval-session crash-state gaps in the v4.0 design package.

**Architecture:** Enforce artifact lifecycle transitions in SQLite rather than relying on application convention; represent unresolved retrieval outcomes as retained `indeterminate` receipts with exact recovery traces; and classify the external retrieval sidecar as a brokered process with an explicit escalation rule for implementations that require a mounted task volume. Keep clean-install and migrated schemas equivalent and prove the controls through focused negative and positive tests.

**Tech Stack:** SQLite STRICT DDL and triggers, Python 3 validation harnesses, Markdown normative contracts, SHA-256 package manifest.

## Global Constraints

- Preserve existing artifact identity and legitimate lifecycle updates.
- Never allow `quarantined` artifacts to return to service in place.
- Never allow `rejected` verification to be promoted in place.
- New retrieval sessions begin `running`; unresolved crash recovery ends `indeterminate` with exact trace evidence.
- External retrieval sidecars default to `brokered_process`; raw repository or profile paths remain forbidden.
- Clean v4 and v3.2-to-v4 migrated databases must have identical normalized schema objects.

---

### Task 1: Encode failing governance regressions

**Files:**
- Modify: `validation/validate_v32_hardening.py`
- Modify: `validation/validate_v4_memory.py`
- Modify: `validation/validate_v4_traceability.py`

**Interfaces:**
- Consumes: existing `blocked`, `record`, `db`, `seed`, and `start_retrieval` helpers.
- Produces: executable negative and positive checks for artifact transitions, retrieval crash state, and sidecar tier text.

- [x] Add negative tests for `quarantined -> available` and `rejected -> user_approved` in the v3.2 and v4 schemas.
- [x] Add positive tests for supported artifact lifecycle transitions.
- [x] Add a retrieval test requiring `running -> indeterminate` with a scoped trace artifact and terminal immutability.
- [x] Add traceability checks for the sidecar trust-tier contract and startup reconciliation.
- [x] Run focused suites and confirm they fail for the missing controls.

### Task 2: Enforce artifact lifecycle transitions

**Files:**
- Modify: `schemas/sqlite-v2.sql`
- Modify: `schemas/sqlite-v3.sql`
- Modify: `schemas/migrate-v2-to-v3.sql`
- Modify: `07-storage-data-model.md`
- Modify: `15-crash-consistency-recovery.md`
- Modify: `20-invariant-registry.md`

**Interfaces:**
- Consumes: `artifacts.availability`, `artifacts.verification_state`.
- Produces: `artifacts_availability_transition` and `artifacts_verification_transition` triggers in every supported installation path.

- [x] Add the minimal availability transition graph and make `quarantined` terminal.
- [x] Add the verification transition graph and make `rejected` terminal.
- [x] Preserve no-op updates and documented legitimate progression.
- [x] Document recovery and garbage-collection behavior.
- [x] Run v3.2 and v4 focused suites until green.

### Task 3: Add retrieval crash uncertainty

**Files:**
- Modify: `schemas/sqlite-v3.sql`
- Modify: `schemas/migrate-v2-to-v3.sql`
- Modify: `15-crash-consistency-recovery.md`
- Modify: `24-cognitive-memory-agent-quality.md`
- Modify: `20-invariant-registry.md`

**Interfaces:**
- Consumes: `retrieval_sessions.status`, terminal trace fields, startup reconciler.
- Produces: retained terminal `indeterminate` retrieval receipts and a normative startup reconciliation rule.

- [x] Add `indeterminate` to the retrieval session status domain.
- [x] Permit only `running -> succeeded|degraded|failed|indeterminate` and retain terminal irreversibility.
- [x] Require exact completion time and trace evidence for `indeterminate` exactly as for other terminal states.
- [x] Document that retry creates a new session and never rewrites the uncertain receipt.
- [x] Run retrieval lifecycle tests until green.

### Task 4: Classify retrieval sidecar trust

**Files:**
- Modify: `13-trust-sandbox-model.md`
- Modify: `02-system-architecture.md`
- Modify: `11-mvp-roadmap.md`
- Modify: `19-assurance-release-gates.md`

**Interfaces:**
- Consumes: `RetrievalEngine` sidecar adapter and four-tier trust model.
- Produces: explicit default `brokered_process` classification, denied capabilities, and escalation rule.

- [x] State the external retrieval sidecar's normative default tier.
- [x] Define identity, ACL, path, network, process-tree, protocol, and fail-closed requirements.
- [x] Define when an implementation becomes an `isolated_worker` instead.
- [x] Gate MQ6 enablement on containment and cognitive conformance for the exact executable tuple.
- [x] Run traceability checks until green.

### Task 5: Close package evidence

**Files:**
- Modify: `25-v4-self-review-report.md`
- Modify: `27-v4-traceability-matrix.md`
- Modify: `V4-CHANGELOG.md`
- Modify: `18-validation-report.md`
- Modify: `SHA256SUMS.txt`
- Generated: `validation/package-validation-results.json`
- Generated: `validation/PACKAGE-VALIDATION-RESULTS.md`

**Interfaces:**
- Consumes: all schema, test, and document changes.
- Produces: reproducible package evidence and updated checksums.

- [x] Record the three closed findings and exact controls.
- [x] Update expected suite counts.
- [x] Run core, hardening, cognitive, traceability, and full package validation.
- [x] Verify clean/migrated normalized schema equivalence and SQLite integrity.
- [x] Rebuild `SHA256SUMS.txt`, package the directory, extract the ZIP, and rerun validation from the extracted copy.
