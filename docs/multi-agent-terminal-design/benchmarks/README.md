# Benchmarks

This directory contains two separate benchmark questions. Their evidence must not be mixed.

## 1. Context and memory treatment benchmark

`context-memory-bootstrap-v1.json` compares:

1. `control_no_memory`;
2. `compaction_only`;
3. `evidence_retrieval`;
4. `evidence_plus_experience`.

It asks whether state/evidence/experience treatments improve a fixed agent configuration while preventing stale or harmful memory. It does not prove that multi-agent orchestration is valuable.

## 2. Orchestration product-proof benchmark

`orchestration-product-proof-bootstrap-v1.json` declares all required arms:

1. `single_direct`;
2. `single_with_retrieval_and_verification`;
3. `same_model_multi_sample`;
4. `quick_profile`;
5. `standard_cross_review`;
6. `high_assurance`;
7. `heterogeneous_models`.

It controls total tokens, tools, time, cost, repository revision, acceptance rules, tool policy, and evaluator configuration. Required metrics include correctness, defect escapes, unsupported claims, human correction, interruptions, abandonment, and unique reviewer findings.

The included orchestration fixture validates the contract only. It contains no live provider runs and authorizes no quality claim. Production claims require representative categories, at least three paired repeats per case, predeclared thresholds, budget compliance, uncertainty, and category-level disclosure.

See [the benchmark design](../40-orchestration-product-proof-benchmark.md).
