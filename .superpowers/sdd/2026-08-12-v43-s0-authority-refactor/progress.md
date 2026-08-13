# SDD ledger — plan: docs/superpowers/plans/2026-08-12-v43-s0-authority-refactor.md
Task 1: dispatched (base b8dc516)
Task 1: fix round 1/5 (1 addressed, 0 open — UTF-8 feedback unit mismatch; commits 0067cee..f2f984c)
Task 1: complete (commits b8dc516..f2f984c, review clean)
Task 2: dispatched (base e8e3a09)
Task 2: first implementer stopped before edits (agent quota exhausted after ambiguity report)
Task 2: redispatched (base 4c5d5be; condition authority clarified)
Task 2: deferred final-gate lint — crates/storage-sqlite/tests/plan_approval_store.rs single-element loop
Task 2: deferred final-gate lint — crates/bootstrap/src/deliberation_runtime.rs items after test module
Task 2: deferred final-gate test — bootstrap tool_broker production_runtime_writes_with_durable_recovery_evidence (expected 1, observed 0)
Task 2: deferred final-gate test — bootstrap tool_broker production_startup_completes_a_started_file_write_with_the_exact_post_image (expected 1, observed 0)
Task 2: review critical (open) — public WorkflowState::new fabricates Standard/WorkspaceChange/revision 1/empty authority IDs and production SQLite rehydration trusts them
Task 2: minor (deferred) — restore or relocate the deleted domain-purity architecture regression
Task 2: BLOCKED pending Task 3 — current app v9 persists no v3 workflow authority fields; no truthful rehydration source exists
Task 3: reordered as Task 2 persistence prerequisite
Task 3: dispatched (base 086fe55)
Task 3: fix round 1/5 (5 addressed, 0 open - SQL literal normalization; seeded workflow authority; v6 preflight; parallel budget authority; package-wide tests; commits efb1ac0..85f556a)
Task 3: complete (commits 086fe55..85f556a, review clean)
Task 2: fix round 1/5 resumed after Task 3 (base 628c27e; rehydrate both SQLite readers from exact v7 authority)
Task 2: Ruling: expand Fix Round 1 ownership to crates/storage-sqlite/tests/plan_approval_store.rs - package tests that exercise later approval checks must first seed valid v7 task authority; keep their assertions unchanged because missing-authority fail-closed is covered by dedicated reader regressions - cost if wrong: a fixture could hide an authority setup defect, mitigated by the explicit missing-authority test
Task 2: fix round 1/5 (0 addressed, 2 open - causal authority mismatch validation incomplete; workspace mutation diverges tasks from task_workflow_authority; commits 628c27e..6ef222f)
Task 2: fix round 2/5 (3 addressed, 0 open - causal binding completeness; missing-authority no-mutation regression; atomic WF-W001 authority persistence and reload; commits 6ef222f..0f17cbe)
Task 2: complete (commits 4c5d5be..0f17cbe, review clean)
Task 4: dispatched (base 6d9c539)
Task 4: implementation verified locally (focused tests 6+7; application and storage-sqlite all-features green; review pending)
Task 4: review round 0 (3 Important open - trusted-core actor was caller-asserted; timestamp fallback was not RFC3339; direct-SQL bypass tests did not reach intended triggers)
Task 4: fix round 1/5 (3 addressed, 0 known open - composition-bound trusted actor verified before publication and persistence; monotonic RFC3339 fallback; exact profile-route, accepted-replay, and cross-task-receipt trigger tests; commits aae9f23..3524620; re-review pending)
Task 4: complete (commits 6d9c539..3524620, review clean; fresh application and storage-sqlite all-features package gates green)
