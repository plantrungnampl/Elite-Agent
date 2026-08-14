# Invariant Registry v4.1

> **v4.3 authority notice:** workflow projection changes now require matching accepted transition events at the expected stream version; profile changes require monotonic escalation receipts.


| ID | Invariant | Normative primitive | Negative/race test | Release gate | Owner |
|---|---|---|---|---|---|
| INV-001 | Audit source evidence is immutable or append-only according to record type | SQLite event/checkpoint/receipt/run/policy/tool/protocol/update guards | update/delete/source-evidence overwrite | G1 | Storage |
| INV-002 | Every task mutation increments `row_version` exactly once; fencing/workspace versions never decrease | Unconditional task update trigger + monotonic triggers + transition CAS | raw update without version; decrease/reuse token | G1/G2 | Storage/Broker |
| INV-003 | Lease transfer/renewal creates a new immutable fenced history row | Lease schema + grant transaction + immutable holder/token/expiry | change holder/expiry without new token; terminal without release time | G1/G2 | Broker |
| INV-004 | Only current fenced holder can commit external mutation | Per-task barrier + in-barrier tuple check | four pause-point race | G2 | Broker |
| INV-005 | Authority chain is task/digest/actor coherent, including artifact, run, message, intent, attempt, policy, approval, and execution scope | SQLite scope and exact-attempt triggers | cross-task/project ID splice | G1 | Storage/Application |
| INV-006 | Logical effect and dispatch attempts are distinct; aggregate attempt state cannot invent history | Intent/attempt tables + counter/current-terminal guards | advance without attempt; terminal intent without matching terminal attempt | G1/G3 | Storage/Recovery |
| INV-007 | Non-repeatable unknown effects are not auto-retried | Recovery classifier | crash after started without query proof | G3 | Recovery |
| INV-008 | Final approval binds exact commit object, actor, and logical Git effect | Approval v2, receipt, candidate table, exact consumption tuple | wrong metadata/OID/actor/session/type/ref/replay | G4 | Finalization |
| INV-009 | Ref update is expected-old CAS to approved OID | Git broker adapter | old/candidate/other recovery branches | G2/G4 | Git Adapter |
| INV-010 | Protocol response matches durable pending method, task scope, terminal timing, and immutable evidence | Protocol v2 schemas + retained requests + response/lifecycle triggers | arbitrary result, missing time/response, cross-task artifact, clear/delete | G5 | Protocol |
| INV-011 | One terminal protocol/run result and contiguous sequence history cannot reset | Unique terminal index + retained immutable stream heads | duplicate terminal, sequence gap, key mutation, delete/recreate | G1/G5 | Protocol/Storage |
| INV-012 | Context disclosure binds exact bytes and policy | Immutable context package + policy binding + outbound receipt | denied canary across every route | G6 | Context/Security |
| INV-013 | External process enablement and run creation are fail-closed | Exact-tuple attestation + run-time recheck + revocation disable | enable/run missing, stale, mismatched, disabled, revoked attestation | G7 | Launcher/Security |
| INV-014 | Worker lacks ambient authoritative write capability | Private staging + broker-only promotion | direct handle/reparse/IPC escape | G2/G7 | Launcher/Broker |
| INV-015 | Cross-store recovery never invents success | Typed resource receipts, artifact journal, reconcilers | crash at every commit point | G3 | Recovery/Adapters |
| INV-016 | Runtime DB settings are verified per connection | Connection factory startup check | foreign keys/defensive mode disabled | G1 | Storage |
| INV-017 | Update preserves one compatible whole-state generation and retained journal evidence | Update journal + backup manifest | switch-point crash, journal mutation/delete, restore | G8 | Operations |
| INV-018 | UI does not overstate authority or certainty | Derived trust/operation states | indeterminate and stale-attestation UX tests | G9/G10 | UX |
| INV-019 | Artifact content identity cannot be rewritten or cross-scoped | Immutable artifact identity + task/project/supersession guards + quarantine GC | hash/project/task/supersession mutation; direct delete | G1/G3 | Storage |
| INV-020 | Approval-required work uses the exact policy-selected, granted, unexpired approval | Policy/approval/attempt exact binding and immutable receipt time | omit, substitute, expire, pre-grant, rewrite | G1/G4 | Policy/Finalization |
| INV-021 | Successful run/tool/attempt outcomes retain terminal timing and set-once evidence | Terminal consistency + receipt/time/set-once/delete guards | success without receipt/time; overwrite/clear/delete/reverse | G1/G3/G5 | Storage/Recovery |
| INV-022 | Retrieval records cannot cross project privacy scope | Source document, memory artifact, and graph edge scope guards | cross-project document/memory/edge | G6 | Context/Indexing |
| INV-023 | Machine-readable workflow enums stay aligned with the authority schema | Package validator compares transition JSON and SQLite | enum/transition endpoint drift | G1 | Domain/Storage |

The registry is version controlled. A requirement without a primitive and test is `specified` only. A primitive without release evidence is not acceptance-proven.

## v4 cognitive invariants

| ID | Invariant | Authority enforcement | Required evidence |
|---|---|---|---|
| COG-001 | A retrieval/index engine cannot activate, verify, approve, or retract memory. | Application port boundaries and storage authorization | Conformance tests and operation receipts |
| COG-002 | Every context item resolves to an authoritative source identity, revision, and digest. | Context Compiler plus database references | Byte reconstruction test |
| COG-003 | Cross-project memory, evidence, relation, episode, retrieval, and context-item references are rejected. | SQLite foreign keys and triggers | Adversarial SQL tests |
| COG-004 | Agent reflection and model agreement remain untrusted proposals. | Memory lifecycle transition policy | Negative promotion tests |
| COG-005 | Active long-term memory has matching verification/promotion evidence, atomic activation time, no expired activation, and one active version per logical key. | SQLite checks/triggers and application policy | Lifecycle, timestamp, expiry, and uniqueness matrix |
| COG-006 | Superseded, retracted, stale, or expired memory is excluded from current packages. | Query policy and freshness validation | Seeded retrieval tests |
| COG-007 | Evaluation records are immutable and bound to one run/configuration. | Append-only storage triggers | Overwrite/delete tests |
| COG-008 | Context supplements do not broaden permissions or parent budgets. | Protocol and Context Compiler | Capability/budget tests |
| COG-009 | Remote embedding or reranking follows external-disclosure policy and exact receipt capture. | Policy Evaluator and outbound broker | Denied-canary route tests |
| COG-010 | Benchmark comparisons bind equal suite, case, fixture revision, budget, policy, system configuration, and evaluator configuration. | Benchmark record constraints | Comparison validity and update-scope tests |
| COG-011 | Index loss cannot destroy authoritative memory or context receipts; terminal retrieval binds immutable branch status and exact trace bytes. | Storage separation, retrieval receipts, and rebuild operation | Trace-artifact, immutability, and delete/rebuild tests |
| COG-012 | A known applicable negative memory must be resolved before conflicting high-risk write action. | Orchestrator repeated-error guard | Seeded workflow test |
| COG-013 | Stale memory is never reactivated in place; reuse creates a fresh version with fresh evidence and review. | SQLite lifecycle transition guard + versioned supersession | Stale-reverification and valid-new-version tests |
| COG-014 | A context manifest binds one preallocated run, and its `content_hash` identifies the separate exact effective-input artifact rather than the manifest itself. | Unique run/package index + artifact hash binding | Package-reuse rejection and byte-reconstruction tests |
| COG-015 | Legacy `memory_entries` is a retained migration source, never a writable v4 authority path. | SQLite insert/update/delete rejection triggers installed by clean schema and incremental migration | Read succeeds; insert, status-forging update, and delete fail on clean/migrated schemas |
| COG-016 | Artifact availability and verification cannot bypass lifecycle governance; metadata is retained, identity replacement is forbidden, and `quarantined`/`rejected` are terminal in place. | SQLite transition, retained-delete, and replacement guards in v3.2, clean v4, and incremental migration | Forbidden delete/replacement/resurrection/promotion plus supported-transition tests |
| COG-017 | A retrieval whose crash outcome cannot be proved is retained as terminal `indeterminate` with exact trace evidence. | Retrieval-session status domain, terminal-evidence guard, and startup reconciler | Crash-state, missing-trace, immutability, and new-session retry tests |
| COG-018 | An external retrieval sidecar has an explicit fail-closed trust profile. | Default `brokered_process` classification; separate `isolated_worker` escalation | Exact-tuple containment and cognitive-conformance suite |


## v4.1 state, invalidation, and utility invariants

| ID | Invariant | Authority enforcement | Required evidence |
|---|---|---|---|
| COG-019 | Authoritative state is resolved by fixed precedence and scope; experience memory cannot override the winner. | `state_records`, precedence trigger, immutable `state_resolution_receipts` | Precedence, equal-rank conflict, and cross-scope tests |
| COG-020 | Every new durable memory has typed executable invalidation, and retrieval requires a current passing result for every rule. | Cognitive schema v2, typed-rule trigger, invalidation evaluations, retrieval eligibility trigger | Malformed rule, missing/failed/expired/indeterminate evaluation tests |
| COG-021 | Deterministic or policy promotion of model-generated semantic, procedural, or negative memory requires a passing equal-input shadow comparison. | `memory_shadow_evaluations` and promotion trigger | Missing shadow, incomparable runs, and regression-containing pass tests |
| COG-022 | Memory usage and utility are immutable evidence or rebuildable projections and cannot change authority state directly. | Usage/utility tables and immutable triggers; lifecycle remains review-gated | Cross-scope, overwrite/delete, and unauthorized lifecycle tests |
| COG-023 | Consolidation retains every input memory and creates explicit reviewed actions or new versions. | `memory_consolidation_actions`, memory retention, supersession lifecycle | Delete-source, cross-project input, and invalid lifecycle tests |
| COG-024 | Adaptive context allocations are non-negative, sum to the declared total, and bind one exact project/task/run/package/policy tuple. | `context_budget_decisions` and scope/sum triggers | Sum mismatch, cross-task/package, rewrite/delete tests |
| COG-025 | Retrieval stops at sufficient coverage, budget/policy limit, no candidates, or marginal utility below cost; filling the context window is not a goal. | Context Compiler strategy and immutable budget receipt | Deterministic stopping and progressive supplement tests |

## v4.1.1 loop-review invariants

| ID | Invariant | Authority enforcement | Required evidence |
|---|---|---|---|
| COG-026 | A newly created authoritative state value is active and valid at creation; terminal state has an immutable `ended_at`. | State validity/lifecycle/terminal-time triggers and v4-to-v5 backfill | Future/expired creation, missing end time, end-time rewrite, and migration tests |
| COG-027 | Equal-precedence divergent state values require one explicit conflict, and that conflict permits exactly one resolution receipt choosing exactly one declared candidate. | `state_resolution_conflicts`, candidate-set matching, conflict-linked unique receipt | Direct-resolution bypass, candidate substitution, second receipt, and valid-resolution tests |
| COG-028 | Invalidation rules have unique identities and kind-valid payloads; retrieval uses only task/project-applicable evaluations observed no later than retrieval. | Schema v3 definitions plus invalidation rule/evaluation/retrieval triggers | Duplicate ID, malformed payload, unrelated-task failure, future evaluation, and valid project-scope tests |
| COG-029 | Durable memory can enter a context package only through the exact selected retrieval candidate produced by the same preallocated run for the same memory, task, project, and package. | Context-item candidate foreign key plus retrieval-session/run/package admission trigger | Direct context insertion, unselected candidate, cross-run reuse, candidate substitution, and valid admission tests |
| COG-030 | Shadow promotion evidence is isolated to the exact benchmark arm and candidate memory, has deterministic temporal ordering, and legacy unbound evidence grants no authority. | Memory origin, run-arm, run-memory binding, unique evaluation time, latest-shadow promotion trigger | Wrong arm, wrong memory, duplicate time, older-pass/newer-fail, legacy-shadow, and valid latest-pass tests |
| COG-031 | A memory usage event marked included, cited, conclusion-used, helpful, misleading, or redundant links both the exact selected retrieval candidate and exact context item for the same authority tuple. | Usage linkage and implication triggers | Missing candidate/item, mismatched run/package/task/memory, conclusion-without-inclusion, and valid linkage tests |
| COG-032 | An applied consolidation action has one immutable effect, retains all inputs, and cannot use an unsupported action shape. | Consolidation action/effect triggers and retained memory authority | Applied-without-effect, effect rewrite, input deletion, unsupported split, and merge/supersede tests |
| COG-033 | Adaptive context allocation satisfies exact total, configured maximum, reserved minima, integer bounds, and immutable scope binding. | Budget shape/sum/max/reserve/scope triggers | Over-max, reserve violation, fractional/negative allocation, tuple mismatch, and valid budget tests |
| COG-034 | A memory-origin classification is recorded only while memory is `candidate`, is immutable, actor-kind and actor-binding-digest coherent, time-valid, and backed by exact in-scope artifact evidence; verification requires it and verified legacy memory cannot be reclassified. | `memory_origin_records` actor/binding/evidence columns, candidate-only insert trigger, and verification gate | Missing origin/evidence, invalid binding digest, wrong scope/time, actor-kind substitution, post-verification laundering, and valid-origin tests |
