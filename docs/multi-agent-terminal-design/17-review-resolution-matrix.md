# Review Resolution Matrix v3.2

## 1. Status model

Every finding is tracked on three independent axes:

- **Specified:** the intended rule exists in normative prose.
- **Machine-enforced:** schema, transition primitive, broker, or OS boundary rejects the unsafe state.
- **Acceptance-proven:** executable negative/race/crash/installed-product evidence exists for the supported tuple.

`Specified` alone never authorizes a capability.

## 2. Current resolution matrix

| Finding | Specified | Machine-enforced in package | Acceptance-proven in package | Capability effect |
|---|---|---|---|---|
| Immutable/retained audit authority | Yes | Append-only, immutable, delete, quarantine, and set-once SQLite guards | Core + v3.2 adversarial DB suites | Runtime storage-path bypass tests pending |
| Task optimistic concurrency bypass | Yes | Every `tasks` update increments `row_version` exactly once | Direct-update bypass test | Reducer/storage conformance pending |
| Monotonic fencing and lease history | Yes | Monotonic epoch, immutable holder/token/expiry, terminal release evidence | Targeted DB tests | Broker race gate pending |
| Artifact identity and supersession scope | Yes | Task/project coherence, immutable identity, same-scope supersession, retained metadata, quarantine-before-byte-GC, and lifecycle transition guards | Mutation/scope/delete/replacement/lifecycle tests | Real artifact-store crash matrix pending |
| Cross-task run/context/config/message splicing | Yes | Run/message scope, immutable identity, retained history | Cross-task and mutation tests | Captured-wire/restart suite pending |
| Cross-task operation authority splicing | Yes | Intent/attempt/policy/approval/execution scope and exact-attempt binding | Generated targeted DB counterexamples | Broader property suite pending |
| Canonical request and policy approval binding | Yes | Operation digest equals request artifact hash; policy-selected approval exact, granted, and unexpired | Digest, omission, mismatch, expiry tests | Storage API canonicalization proof pending |
| Attempt/tool/run evidence preservation | Yes | Retained rows, terminal consistency, task-scoped evidence, NULL-safe set-once guards | Overwrite, clear, delete, reversal tests | Effect crash matrices pending |
| Actor-bound approval lifecycle | Yes | Pending-only creation, request/credential scope, immutable receipt/time, set-once resolution | Pre-grant, wrong actor/artifact/time/expiry tests | Credential integration pending |
| Exact final commit object/effect | Yes | Final-commit approval type, immutable candidate, exact consumption tuple | Schema and DB tuple tests | Git object/ref integration pending |
| External containment fail-closed | Yes | Enable-time and run-time exact-tuple attestation; revocation disables descriptor | Missing/disabled/revoked tests | Installed hostile suite pending |
| Method-specific protocol responses | Yes | Protocol v2 schemas and durable request correlation | Schema and DB tests | Captured-wire restart suite pending |
| Protocol replay/sequence reset | Yes | Request/stream retention, immutable stream key, contiguous sequence | Insert/update/delete/key-reset/gap tests | Multi-connection restart/fuzz pending |
| Protocol terminal/response evidence | Yes | Pending/completed/failed consistency, task scope, set-once evidence | Missing time/response, cross-task, clear tests | Transport integration pending |
| Context and retrieval privacy scope | Yes | Immutable context packages; source/memory/graph project guards | Structural and cross-project DB tests | Route-complete canary pending |
| Update journal recovery evidence | Yes | Immutable identity, retained rows, terminal irreversibility | Delete/terminal tests | Installed update/restore pending |
| Windows file/Git durability | Yes | Adapter/broker contract only | No | Write release blocker |
| Accessibility/performance | Yes | Criteria only | No | Public release blocker |

## 3. Release claim rule

A capability may be enabled only when every invariant it depends on is both machine-enforced and acceptance-proven for the exact binary/schema/OS/toolchain profile. Evidence is attached to the release manifest. Missing evidence means disabled capability, not best-effort fallback.
