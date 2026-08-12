# v4.3 S0 Authority Refactor Design

**Date:** 2026-08-12
**Status:** Approved for implementation
**Normative source:** `docs/multi-agent-terminal-design` v4.3

## 1. Purpose

Refactor the current implementation to use the v4.3 S0 machine authority before any S1 runtime expansion. The refactor replaces production dependencies on historical workflow, protocol, and storage contracts while preserving valid product behavior already implemented for repository onboarding, context handling, deliberation, tools, and recovery.

This document is an implementation design. It does not modify or supersede the normative v4.3 package.

## 2. Audit baseline

The updated design package passes its isolated package validator (`182/182`). That result proves design-package coherence, not implementation conformance.

The current implementation has these confirmed gaps:

- `crates/domain` loads `workflow-transitions.v1.json` and its workflow state omits v4.3 profile, outcome, profile-revision, and accepted-event authority.
- `crates/agent-protocol` generates and validates `agent-protocol.v1.schema.json`; production descriptors and tests still negotiate protocol `1.0`.
- `crates/storage-sqlite` installs the historical SQLite v1 baseline plus application migrations numbered 1 through 9 rather than using SQLite v7 as the current authority.
- The current `agent-run-config.v2` artifact contains useful provider/model fields but is not the normative `RunConfiguration v1` shape and has no v7 `run_configuration_bindings` authority.
- No production `AssuranceDegradationReceipt v1` or monotonic profile-revision authority exists.
- Deliberation commands can construct a task-state projection directly instead of persisting the v4.3 command, prepared event, guard/effect bindings, accepted event, and projection atomically.
- The workspace compiles, but one deliberation persistence test is red because its old fixture omits the rejected alternatives and dissent now required to preserve every quorum position.

No production source file currently exceeds 2,000 lines. New work must preserve that limit.

## 3. Scope

### Included

- SQLite v7 clean-install authority;
- the exact normative SQLite v6-to-v7 migration and clean/migrated object parity;
- workflow transition specification v3 and a pure domain reducer;
- `WorkflowTransitionCommand v1` preparation and canonical digest validation;
- atomic workflow event, guard, effect, and projection persistence;
- monotonic profile escalation and downgrade rejection;
- MAT Agent Control Protocol v2 generated types, codec, session, conformance, and runtime wiring;
- immutable `RunConfiguration v1` construction and exact run binding;
- `AssuranceDegradationReceipt v1` construction and persistence;
- adaptation of existing orchestration, runtime, provider, deliberation, and recovery paths to the new authority;
- focused and full verification for S0.

### Excluded

- compatibility with existing application databases using the internal schema version 9;
- the S1 real-runtime product gate;
- S2 benchmark execution with live representative cases;
- new write, final-commit, retrieval, or memory breadth beyond behavior already present;
- changes to the normative design package;
- claims that design validation proves runtime quality, containment, or product value.

The user explicitly approved a clean database reset. Existing application databases are not migrated by this refactor.

## 4. Chosen approach

Use an authority-first replacement.

Production code will have one current authority:

- `schemas/sqlite-v7.sql` for authoritative storage;
- `schemas/workflow-transitions.v3.json` for workflow rules;
- `schemas/workflow-transition-command.v1.schema.json` for transition command artifacts;
- `schemas/agent-protocol.v2.schema.json` for protocol frames;
- `schemas/run-configuration.v1.schema.json` for run configuration;
- `schemas/assurance-degradation-receipt.v1.schema.json` for degraded assurance.

Historical schemas remain available only for historical validators and fixtures. Production modules must not import them.

Application-specific deliberation tables may remain only as append-only evidence or rebuildable projections installed after the v7 authority. They must not create an alternate phase/profile/outcome authority or permit raw task projection updates.

## 5. Module boundaries

### Domain

The domain workflow module owns pure values and deterministic policy:

- phase, condition, operation state, workflow profile, and outcome mode;
- stream, profile, workspace, and fencing versions;
- last accepted transition/profile-revision identities;
- parsing and validating workflow v3;
- exact rule selection;
- guard/effect requirement validation;
- terminality, profile-route, outcome-route, and monotonicity rules;
- calculation of the next workflow state without I/O.

The domain must not construct SQLite, protocol, provider, runtime, or artifact implementations.

### Application

Application use cases own authority orchestration and output ports:

- prepare a canonical workflow transition command;
- load authoritative workflow state at an expected stream version;
- persist an accepted or rejected transition result;
- prepare and persist a profile escalation receipt;
- build and validate `RunConfiguration v1` without credential material;
- bind one immutable run configuration to one preallocated run;
- evaluate assurance requirements and prepare a degradation receipt.

The application layer creates canonical artifacts and typed failures. It does not issue direct SQL.

### Storage SQLite

The storage adapter installs SQLite v7 verbatim for a clean database and applies `migrate-v6-to-v7.sql` only to the exact normative SQLite v6 predecessor. It rejects the application's unrelated internal schema version 9. Clean and migrated v7 databases must expose identical non-internal authority objects. Required runtime pragmas and schema identity are verified before dispatch opens.

One transition transaction performs this order:

1. load `task_workflow_authority` at `expectedStreamVersion`;
2. verify the exact normalized rule and source/profile/outcome relation;
3. persist the command artifact reference and a `prepared` transition event;
4. bind every required guard evidence row;
5. bind every required effect row;
6. change the event to `accepted`;
7. update the workflow projection, last-event pointer, and stream version by exactly one;
8. commit atomically.

Rejected events remain immutable. Accepted events cannot be replayed. No repository method may update phase/profile/outcome outside the authority API.

### Agent protocol

The protocol crate imports v2 generated types and validates complete method-specific request/notification/response shapes. The implementation negotiates protocol `2.0`, enforces method ownership, durable pending-method correlation, one terminal result, sequence continuity, frame/output limits, and notification response rules.

Canonical v2 fixtures are used directly by contract tests. Production code no longer imports the v1 schema.

### Runtime, providers, orchestration, and bootstrap

- Bootstrap remains the sole composition root.
- A run ID is preallocated before context/config binding.
- The context package and `RunConfiguration v1` are immutable before dispatch.
- SQLite binds the exact run, configuration artifact, configuration digest, and context package.
- The v2 `agent.run.start` frame contains only fields permitted by the v2 schema; run configuration authority remains in the trusted binding.
- A fallback creates a new run ID and configuration artifact and re-evaluates budget and independence.
- High Assurance requires hard executor/reviewer separation and the configured minimum independence groups.
- Insufficient assurance pauses, cancels, or continues only with an actor-proved degradation receipt.

Existing valid M1-M4 behavior is adapted through these ports. It is not reimplemented as a second path.

## 6. Workflow data flow

### Phase transition

1. A caller submits typed intent, expected stream version, evidence references, and proposed effects.
2. The application reloads current authority and asks the pure reducer for exactly one v3 rule.
3. The application validates evidence/effect coverage and constructs canonical `WorkflowTransitionCommand v1` bytes and digest.
4. The storage adapter executes the single authority transaction.
5. UI notifications and external dispatch occur only after commit.

`AwaitingPlanApproval -> Implementation` must select `WF-P015`, bind the exact granted plan-approval receipt, and bind both `persist_approved_plan_version` and `allocate_executor_lease`.

### Profile escalation

Profile escalation is separate from phase transition. Only these changes are legal:

- Quick to Standard;
- Quick to HighAssurance;
- Standard to HighAssurance.

An escalation binds a risk-reassessment receipt, creates an immutable profile revision, increments stream/profile revisions, and leaves phase unchanged. Downgrade and in-place ReadOnlyResearch-to-write conversion are rejected.

### Run creation

1. Preallocate the run and context-package identities.
2. Resolve provider connection, adapter, model endpoint, capability snapshot, policy, budgets, fallback, and independence dimensions.
3. Build canonical `RunConfiguration v1` with `credentialsExcluded=true`.
4. Persist the configuration artifact and exact v7 run binding.
5. Verify the context package and run binding.
6. Dispatch the v2 run-start request.

Changing any configuration section produces a new artifact and run.

### Degraded assurance

When required independence or role separation is unavailable, record the observed run set and requested requirements. `continue_degraded` requires actor binding and an acceptance artifact. The requested profile remains unchanged and every later report/export carries the degradation receipt.

## 7. Errors and recovery

Typed fail-closed classifications include:

- stream-version conflict;
- undeclared or ambiguous rule;
- profile/outcome route conflict;
- missing, substituted, or stale guard evidence;
- missing or substituted required effect;
- command/artifact digest mismatch;
- accepted-event replay;
- forbidden profile downgrade;
- run-configuration mutation or credential-field violation;
- protocol incompatibility or method-shape violation;
- assurance policy unsatisfied without an allowed decision.

A rejected transition may be corrected with a new command/event ID at the same stream version. An accepted transition consumes that version exactly once.

Protocol failure terminalizes only the affected run. Provider/model fallback never reuses the prior run configuration. Startup continues to reconcile incomplete external operations honestly and never treats a missing completion receipt as success.

## 8. Testing strategy

Implementation follows red-green-refactor in this order:

1. protocol v2 schema, fixture, method, replay, and sequence contracts;
2. workflow v3 state shape, rule selection, profile route, outcome route, escalation, and downgrade contracts;
3. SQLite v7 clean install, exact v6-to-v7 migration parity, runtime pragma checks, authority transaction, replay, missing guard/effect, and raw-update rejection;
4. RunConfiguration canonicalization, credential exclusion, immutability, scope, and exact binding;
5. assurance degradation shape, scope, actor-proof, and immutability;
6. orchestration/runtime/provider/bootstrap integration;
7. existing M1-M4 regression adaptation and full gates.

Mandatory negative cases include:

- raw workflow projection update;
- prepared event missing one required guard or effect;
- Quick/Standard severe-objection route substitution;
- accepted-event replay and expected-version reuse;
- profile downgrade;
- plan approval without exact receipt or either required effect;
- cross-task run/config binding;
- configuration mutation and any credential-bearing field;
- v1 protocol frame accepted by the production v2 path;
- `continue_degraded` without actor proof;
- application-specific deliberation projection attempting to change authority.

The currently failing deliberation fixture must be updated to preserve all quorum positions through rejected alternatives and dissent. The invariant must not be weakened to make the test pass.

## 9. Completion gates

S0 is complete only when all of the following are true:

- no production module imports workflow v1 or agent-protocol v1;
- SQLite v7 authority objects and guards are installed and used by production storage;
- the exact normative v6-to-v7 migration produces the same authority surface as a clean v7 install, while the old application schema v9 is rejected;
- workflow transitions persist command, event, guard, effect, and projection authority atomically;
- profile escalation and downgrade rejection are executable;
- v2 fixtures round-trip through generated types, codec, session, and runtime;
- each run reconstructs its exact normative configuration and contains no credential material;
- degraded assurance requires the exact allowed decision and actor proof;
- existing valid product behavior passes through the new authority;
- every source file remains at or below 2,000 lines;
- `cargo fmt --all -- --check` passes;
- `cargo check --workspace --all-targets` passes;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes;
- `cargo test --workspace --all-features` passes;
- `cargo test --workspace --doc` passes;
- frontend unit/build and architecture contracts pass;
- the v4.3 design package validator passes independently on an isolated copy;
- implementation audit finds no remaining current-authority v1 path.

## 10. Plan and evidence discipline

A new S0 implementation plan will use checkbox steps with an exact verification command or artifact for each step. A checkbox is marked complete only after that evidence is green.

The historical M4 Task 10 plan remains unchanged: its Steps 4 through 6 stay unchecked until their original review, evidence, and clean-branch conditions are actually satisfied. The S0 refactor does not retroactively claim those gates.
