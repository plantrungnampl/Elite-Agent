# v4.0 Self-Review Plan

## Executed review sequence

1. Run historical core and v3.2 adversarial suites unchanged.
2. Compile and execute SQLite v3 in memory.
3. Construct a clean v3 database and a v2 database upgraded through the incremental migration; compare normalized schema definitions.
4. Validate all JSON Schemas and positive examples.
5. Attack cross-project memory, evidence, relation, retrieval, context, reflection, evaluation, index, and benchmark boundaries.
6. Attack lifecycle shortcuts, stale-version replay, missing evidence/review, preference scope, context reuse, and terminal evidence mutation.
7. Check relative links, JSON parsing, schema compilation, workflow/SQL alignment, and placeholder hygiene.
8. Inspect requirement-to-design-to-schema-to-test-to-UX-to-milestone traceability.
9. Scan terminology, fields, method names, and implementation-plan interfaces against canonical contracts.
10. Perform manual gap reviews for authority, failure modes, migration, UX, measurements, and package truthfulness.
11. Repair each finding inline and rerun affected suites.
12. Run the full verification set again before checksum generation.

Final results are recorded in [V4-SELF-REVIEW-RESULTS.md](V4-SELF-REVIEW-RESULTS.md) and [the normative self-review report](../25-v4-self-review-report.md).
