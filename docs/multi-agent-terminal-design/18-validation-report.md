# Validation Report v4.0

**Date:** 2026-08-04  
**Primary command:** `python validation/validate_package.py`

## 1. Result

All included design-package checks pass:

- core regression suite: **39/39**;
- v3.2 adversarial hardening suite: **68/68**;
- v4 cognitive memory and quality suite: **79/79**;
- v4 traceability suite: **30/30**;
- package-level validation: **56/56**.

Generated details are stored in:

- `validation/VALIDATION-RESULTS.md` and `validation/validation-results.json`;
- `validation/PACKAGE-VALIDATION-RESULTS.md` and `validation/package-validation-results.json`;
- `validation/V3.2-RED-BASELINE.md`.

The v3.2 checks were added in four test-first passes. Before each corresponding schema change, the suite exposed 27, then 20, then 11, then 5 additional unsafe behaviors. The v3.2 hardening suite rejects all 68 captured counterexamples, and the v4 cognitive suite closes 79 lifecycle, provenance, recovery, and comparability checks.

## 2. Proven by the included executable suites

The package proves that its checked-in contracts reject the represented cases, including:

- SQLite v2 clean install and `integrity_check`;
- immutable/retained migration, event, policy, run, attempt, tool, approval, protocol, lease, checkpoint, and update evidence where the design requires retention;
- every task update increments `row_version` exactly once, while fencing/workspace versions cannot decrease;
- artifact task/project scope, immutable content identity, coherent supersession, quarantine-before-byte-GC, retained artifact metadata, identity-replacement rejection, lifecycle transition enforcement, and terminal quarantine/rejection;
- coherent task/run/context/config/message/intent/attempt/policy/approval/tool authority chains;
- canonical operation digest binding to the immutable request artifact;
- exact granted and unexpired approval enforcement for `require_approval` policy;
- set-once run, attempt, tool, protocol, message-supersession, and approval-resolution evidence;
- terminal run/intent/attempt/tool/protocol/message/lease/update state consistency and irreversibility;
- successful attempt receipts and terminal completion timestamps;
- exact final-commit approval type and repository/ref/old-OID/candidate-OID consumption tuple;
- external descriptor enablement, revocation disablement, and run-time exact-tuple attestation checks;
- protocol method-specific response shape, task-scoped response evidence, replay retention, stream identity, and contiguous sequence history;
- cross-project source-document, memory-artifact, and graph-edge rejection;
- retrieval crash uncertainty represented as exact-trace terminal `indeterminate`;
- retrieval-sidecar trust classification and startup reconciliation contract traceability;
- all 16 JSON files parse;
- all five JSON Schemas compile under Draft 2020-12;
- all eight checked examples validate against their intended schema/definition;
- all relative Markdown links resolve;
- workflow phase/condition/operation enums align with SQLite;
- no TODO/TBD/FIXME placeholders remain in active package sources.

## 3. Not proved by these suites

This report does not claim production security or release readiness. It does not prove:

- broker linearizability under real filesystem/Git races;
- Windows power-loss and antivirus/sharing-lock durability;
- full production migration from earlier pre-release SQLite v2 checksums;
- credential-backed human identity binding in the packaged application;
- installed AppContainer/LPAC or Hyper-V containment;
- provider/process external-effect reconciliation;
- route-complete context leakage prevention;
- update/rollback/restore on installed binaries;
- accessibility, performance, or the supported Windows matrix.

These remain explicit P0/P1 gates in `19-assurance-release-gates.md`.

## 4. Interpretation

A green suite means the audited counterexamples represented by the package are rejected by the v3.2 contracts. It does not mean an implementation that bypasses the storage factory, capability broker, artifact verifier, Git adapter, or launcher inherits those guarantees.

The architecture/design baseline is ready to freeze for implementation of scaffold, pure domain logic, reducers, storage adapters, fake agents, read models, and a built-in read-only prototype. Write, final-commit, external-process, and public secure/recoverable claims remain disabled until their runtime and installed-product gates pass.

## v4.2 end-to-end correction validation

The v4.2 suite adds journey and round-trip checks that were absent from the
v4.1.1 structural validators. It verifies:

- read-only, workspace-only, and local-commit terminal paths;
- complete candidate commit creation before verification and exact ref CAS;
- all six terminal and all three nonterminal run statuses;
- retrieval indeterminate wire recovery;
- preference wire-to-storage-to-wire reconstruction;
- logical benchmark versioning and exact controlled comparison inputs;
- declared versus undeclared treatment changes;
- actor-binding challenge replay rejection;
- clean SQLite v6 versus migrated v5 object parity;
- complete FR/NFR traceability.

The current executable evidence is:

- `96/96` v4.2 end-to-end checks passed;
- clean install and v5→v6 migration expose the same `451/451` SQLite objects;
- all four workflow profiles have complete successful routes for every supported outcome mode;
- read-only and local-commit SQL journeys reject artifact/OID substitution and missing ref-CAS evidence;
- the package runner remains green across all retained regressions.

These checks establish encoded contract coherence. They do not establish runtime
model quality or representative benchmark improvement.
