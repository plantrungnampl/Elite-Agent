# Machine-Readable Contracts v4.3

## Current authority

- `sqlite-v7.sql` — authoritative clean install.
- `migrate-v6-to-v7.sql` — exact additive v4.2-to-v4.3 migration plus workflow-trigger replacement.
- `workflow-transitions.v3.json` — versioned event/profile/outcome/guard/effect rules.
- `workflow-transition-command.v1.schema.json` — immutable reducer-command artifact.
- `agent-protocol.v2.schema.json` — MAT Agent Control Protocol v2 closed core and bounded extensions.
- `run-configuration.v1.schema.json` — reconstructible provider/model/adapter/policy/budget/fallback/independence snapshot with credentials excluded.
- `assurance-degradation-receipt.v1.schema.json` — explicit degraded-assurance decision.
- `cognitive-memory.v4.schema.json` — current cognitive payload authority.
- `orchestration-benchmark-suite.v1.schema.json`, `orchestration-benchmark-run-receipt.v1.schema.json`, `orchestration-benchmark-case-result.v1.schema.json`, and `orchestration-benchmark-comparison-report.v1.schema.json` — equal-budget product proof.
- `benchmark-suite.v3.schema.json` and related v4.2 receipts — context/memory treatment benchmark.
- `product-traceability.v1.schema.json` and `product-traceability.v43.json` — all current FR/NFR mappings and proof boundaries.
- approval, actor-binding, and credential-challenge v2/v1 schemas remain current where not superseded.

## Canonical examples

- `examples-v2/` contains protocol/approval v2 fixtures. Every complete JSON-RPC frame in `03-agent-protocol.md` is annotated and structurally identical to its fixture.
- `examples-v43/` contains workflow command, run configuration, assurance, orchestration benchmark, and traceability examples.

## Historical contracts

- `sqlite-v3.sql` — authoritative v4.0 clean-install contract.
- `sqlite-v4.sql` — authoritative v4.1 clean-install contract.
- `sqlite-v5.sql` — authoritative v4.1.1 clean-install contract.
- `sqlite-v6.sql` — authoritative v4.2 clean-install contract.

SQLite v1-v6, workflow v1-v2, cognitive v1-v3, and earlier benchmark schemas remain immutable migration and regression inputs. They must not be silently selected for new v4.3 records.

## Validation

```bash
python validation/validate_package.py
```

The package runner executes historical regressions, v4.3 authority tests, JSON/schema/example checks, protocol fixture identity, v7 clean/migration parity, Markdown links, traceability, and placeholder hygiene.
