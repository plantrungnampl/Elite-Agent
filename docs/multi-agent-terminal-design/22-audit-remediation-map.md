# Audit Remediation Map

This file maps material findings from the v2 audit and the repeated v3/v3.1/v3.2 self-review to current v3.2 design changes. It distinguishes contract changes from evidence still required at implementation time.

| Audit finding | v3.2 remediation | Included evidence | Remaining proof |
|---|---|---|---|
| Authority/evidence rows could be updated or deleted | Retained/immutable/set-once guards for migrations, events, runs, messages, policies, approvals, intents, attempts, tools, protocol, leases, checkpoints, and update journal | 107 core + adversarial executable cases | Production storage API bypass tests |
| Artifact identity/scope could be rewritten or spliced | Task/project insert scope, immutable identity, same-scope supersession, retained artifact metadata, quarantine-before-byte-GC, identity-replacement rejection, and availability/verification transition graphs | Scope/mutation/delete, replacement, resurrection, and promotion tests | Artifact-store crash/GC integration |
| Direct task update could omit `row_version` | Every task update requires exactly `OLD + 1` | Raw phase-update bypass test | Reducer/storage command conformance |
| Fencing/lease history could be mutated | Monotonic task epoch, immutable holder/token/expiry, terminal release time | DB negative tests | Real broker four-pause races |
| External worker remained runnable after revocation | Enable-time and run-time exact-tuple attestation; revocation disables descriptor | Missing, disabled, revoked tests | Installed hostile-binary suite |
| Run/intent/tool terminal state or evidence could reverse | Terminal consistency/irreversibility, retained rows, set-once evidence | DB lifecycle tests | Reducer/storage transition conformance |
| Individually valid IDs could be spliced across tasks/projects | Run/message/intent/attempt/policy/approval/tool/artifact/retrieval scope guards | Cross-task/project negative tests | Property-generated combinations |
| Canonical intent digest was not tied to request artifact | Request artifact hash must equal operation digest | Digest mismatch test | Canonicalization implementation proof |
| `require_approval` policy could run without its exact approval | Policy-named approval must be exact, granted, and unexpired | Omission/mismatch/expiry tests | Credential integration |
| Approval could be pre-granted or resolution evidence rewritten | Pending-only insert, immutable receipt/time, set-once invalidation/resolution | Pre-grant/time/overwrite tests | Windows Hello/equivalent integration |
| Successful operation lacked persisted receipt | Success requires task-scoped immutable receipt | Missing/cross-task/clear tests | Effect-specific receipt integration |
| Final approval could be consumed for another Git effect | Final approval type plus exact repository/ref/old-OID/candidate-OID tuple | Wrong type/tuple tests | Git object/ref integration |
| Protocol replay/sequence could reset via delete or key mutation | Retained request/head rows, immutable stream identity, contiguous sequence | Delete/recreate/key-reset/gap tests | Multi-connection restart/fuzz |
| Protocol terminal timestamps/response could be inconsistent | Pending/completed/failed consistency and task-scoped set-once response | Missing time/response/scope tests | Transport integration |
| Retrieval index could cross project boundaries | Source-document, memory-artifact, and graph-edge scope guards | Cross-project DB tests | Route-complete leakage suite |
| SQLite runtime pragmas were not proven by DDL | One connection factory must set and query-verify settings | Current connection check | Packaged startup failure tests |
| Generic rename implied excessive durability | Exact adapter commit-point/flush/identity contract | Normative design | Power-loss/disk/AV/sharing matrix |
| Validation headline mixed contract and runtime assurance | Separate core, adversarial, package, and runtime-only claims | 39/39 + 68/68 + 79/79 + 30/30 + 56/56 reports | Release evidence bundle |
| Roadmap allowed breadth before safety proof | Authority → broker → read-only → exact write → protocol → containment → release | Updated roadmap/gates | Milestone evidence during implementation |

A row is complete only when both the contract and the remaining runtime proof are satisfied for the exact release tuple.
