# Assurance and Release Gates

> **v4.3 authority notice:** real read-only runtime proof and equal-budget single-vs-multi proof are required before orchestration or quality claims. Degraded High Assurance requires an actor-proved receipt.


## 1. Rule

Capability enablement is conjunctive. A P0 failure cannot be offset by unrelated passing tests. Evidence is produced by the exact release binary, schema, Windows build, architecture, toolchain, isolation profile, and adapter tuple.

## 2. Gates

| Gate | Blocks | Required acceptance evidence |
|---|---|---|
| G0 Structural contract | All development | Schemas compile, SQLite installs, checksums match |
| G1 Authority and audit | Any write | Append-only, scope coherence, monotonicity, terminality, attempts, approval receipts; zero unsafe negative successes |
| G2 Broker fencing | Filesystem/Git write | Four-pause race suite and out-of-band mutation suite; zero stale authoritative mutations |
| G3 Effect recovery | Process/provider/Git/filesystem effects | Crash at every commit point; no false success, no unsafe retry, honest indeterminate |
| G4 Exact approval | Final commit/destructive effect | Wrong actor/session/task/intent/repository/ref/OID/replay cases rejected; ref equals approved candidate OID |
| G5 Protocol trace | Third-party adapter | Captured-wire schemas, pending-method correlation, digest replay, one terminal response, sequence continuity, restart and slow-consumer tests |
| G6 Context privacy | Remote provider/read-only release | Route-complete denied-canary suite and exact outbound payload receipts |
| G7 Installed containment | External executable/PTY | Exact-tuple attestation; hostile binary; zero denied-access success, surviving descendants, stale writes, or fallback |
| G8 Update and restore | External/public release | Supported-generation upgrade, switch-point crash injection, signed rollback prevention, verified whole-state restore |
| G9 Product quality | External/public release | Accessibility, diagnostics redaction, resource ceilings, performance corpus, Windows support matrix |
| G10 Finding policy | External/public release | Zero unresolved critical/high findings and no UI/document claim above evidence |

## 3. Capability mapping

- Built-in read-only: G0, G1 read subset, G6.
- Structured internal writer: G0–G3 and G6.
- Final local commit: G0–G4 and G6.
- Third-party protocol adapter: G0, G1, G5, plus G7 if executable.
- External worker/agent PTY: G0–G3, G5–G7.
- Public secure/recoverable release: all gates.

## 4. Evidence format

Each gate emits a signed or checksummed manifest containing test ID, result, binary/schema/OS/toolchain digests, start/end time, environment profile, and artifact references. Expected-failure baselines are check-specific and expire when their target version changes.

## G11 — Cognitive memory integrity

Required evidence:

- typed memory lifecycle tests;
- zero cross-project leakage suite;
- active-memory verification and promotion receipts;
- stale/superseded/retracted exclusion tests;
- index deletion and rebuild proof;
- remote embedding/reranking disclosure tests;
- artifact availability/verification transition tests, including terminal quarantine and rejection;
- retrieval crash reconciliation proving exact trace or terminal `indeterminate`;
- external retrieval sidecar containment for the exact executable, manifest, policy, and network tuple.

## G12 — Agent quality evidence

Required evidence:

- locked benchmark suite and v3.2-style baseline;
- equal-configuration comparison receipts;
- per-case correctness and regression report;
- repeated-error, unsupported-claim, and first-pass acceptance metrics;
- explanation of any unmet target or accepted exception.

A release cannot claim improved memory or quality if G11 or G12 is incomplete.

## G13 — Authoritative state and invalidation

Required evidence:

- current instruction, task override, approved decision, project setting, explicit preference, and inferred preference precedence matrix;
- equal-rank conflict handling and supersession evidence;
- zero cross-project and cross-task state leakage;
- typed invalidation schema and database negative tests;
- current passing invalidation evaluation for every retrieved durable memory rule;
- exclusion of missing, failed, expired, indeterminate, and prose-only legacy invalidation.

## G14 — Shadow learning and memory contribution

Required evidence:

- four-arm equal-input benchmark receipts;
- passing shadow evidence before deterministic or policy promotion of model-generated semantic, procedural, or negative memory;
- zero new forbidden mistakes, unsupported claims, stale-memory use, or cross-scope leakage in a passing shadow result;
- immutable memory usage and utility evidence;
- proof that utility cannot mutate authority;
- consolidation history retention;
- per-memory helpful, harmful, redundant, conclusion-used, and token-cost reporting.

A release cannot claim adaptive learning, useful long-term memory, or safe memory consolidation until G11–G14 pass on representative repositories.

## G15 — Context admission and learning isolation

Required evidence:

- newly created state is active and valid, and every terminal state has an immutable end time;
- every equal-rank divergent state resolution references an explicit conflict, selects exactly one declared candidate, and has no second receipt;
- invalidation rules have unique IDs and kind-valid payloads, while retrieval accepts only task/project-applicable evaluations observed no later than retrieval;
- every durable-memory context item references the exact selected retrieval candidate from the same preallocated package run that admitted it;
- every memory-origin record is created while the memory is a candidate, binds coherent actor kind/ID plus actor-binding digest and exact artifact evidence/digest, and exists before verification; verified legacy memory cannot be reclassified;
- every shadow result binds the exact experiment arm and candidate memory, uses a unique evaluation time, and promotion consults only the latest isolated result;
- legacy shadow records without arm and memory binding cannot authorize promotion;
- every included or conclusion-used memory usage event links the exact retrieval candidate and context item for the same run, package, task, project, and memory;
- every applied consolidation action has one immutable effect and retains all input memories; unsupported `split` actions are rejected;
- adaptive context allocations satisfy the declared total, maximum, reserved minima, and exact authority tuple.

G15 is required for any v4.2 claim that context admission is fail-closed, shadow learning is isolated, or memory contribution is attributable to a specific retrieval and context package.

## 5. v4.2 capability mapping

The following mappings are normative and supersede the shorter v4.1.1 list:

- Quick read-only workflow: G0, G1 read subset, G6, and profile-selection journey tests.
- Standard read-only workflow: G0, G1 read subset, G6, and exact deliverable acceptance evidence.
- High-assurance read-only workflow: G0, G1 read subset, G4 actor-proof subset, G6, and all risk-selected review gates.
- Structured workspace change: G0–G3, G4 acceptance subset, and G6.
- Final local commit: G0–G4 and G6, including exact pre-created commit verification and ref CAS.
- typed memory/retrieval/context compiler: G0, G1 read subset, G6, G11, G13, and G15.
- verified learning: G0, G1, G6, G11, G13, G14, and G15.
- quality dashboard/comparison: G0, G1, G6, G11, G12, G13, G14, and G15.
- public improvement claim: every gate applicable to the enabled product surface, plus G11–G15 and a v4.2 quality release decision.

G12 evidence must use controlled configuration equality plus explicitly declared
treatment differences. The legacy phrase `equal-configuration comparison` does
not permit falsely identical digests for systems whose retrieval, context, or
memory treatment intentionally differs.
