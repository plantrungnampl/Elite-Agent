# Orchestration Product-Proof Benchmark

## 1. Question

The benchmark answers one product question:

> Under comparable total token, tool, time, cost, repository, acceptance-rule, policy, and evaluator budgets, does orchestration improve accepted engineering outcomes enough to justify its complexity and user interruptions?

The existing context/memory benchmark remains valid for memory-treatment questions. It cannot answer this orchestration question.

## 2. Required arms

Every suite declares all seven arms:

1. `single_direct` — one agent, ordinary task context, no orchestration review;
2. `single_with_retrieval_and_verification` — the strongest fair single-agent baseline with the same retrieval and deterministic verification available to multi-agent arms;
3. `same_model_multi_sample` — multiple samples from one model family, synthesized under the same total budget;
4. `quick_profile` — MAT Quick workflow;
5. `standard_cross_review` — independent analysis/cross-review workflow;
6. `high_assurance` — required role separation and independence policy;
7. `heterogeneous_models` — orchestration with distinct provider/model-family groups.

The second arm is the default product baseline. Comparing only against `single_direct` would exaggerate orchestration value.

## 3. Equal-budget rule

The comparison unit is one case and one repeat. The suite freezes:

- repository revision and fixture;
- objective and acceptance rules;
- evaluator configuration;
- tool policy and available deterministic checks;
- input/output token ceilings;
- tool-call ceiling;
- wall-time ceiling;
- cost ceiling and currency.

An arm that exceeds a ceiling is marked `invalid_budget_overflow`; budget is not retroactively rebalanced. Shared preprocessing must either be charged to every arm or excluded from every arm by predeclared policy.

## 4. Cases and repetitions

The production suite must cover at least:

- bug fixes;
- feature changes;
- refactors;
- security reviews;
- research tasks;
- migrations.

Each category needs at least three accepted cases and each case needs at least three randomized repeats before a product claim. The bootstrap fixture included in this package validates the contract only and is not a quality result.

## 5. Metrics

Required metrics are:

- accepted outcome;
- defect escapes;
- first-pass test success;
- unsupported claims;
- requirement omissions;
- human correction minutes;
- time to accepted result;
- input and output tokens;
- tool calls;
- cost;
- approval interruptions;
- task abandonment;
- reviewer findings not found by the primary run.

Results are reported by task category as well as in aggregate. A positive aggregate cannot hide a material regression in a category.

## 6. Evaluation

Deterministic tests, static checks, and repository acceptance scripts run before model-based evaluation. Model evaluators receive blinded arm labels when feasible. Human correction time and abandonment are captured from task telemetry rather than guessed by an evaluator.

Reports use paired comparisons by case/repeat, predeclared directionality, confidence intervals, invalid-run counts, and limitations. No quality claim is allowed when:

- budget equivalence is violated;
- the evaluator changed after results were observed;
- the sample threshold is not met;
- a material safety or defect-escape regression exists;
- results are only from synthetic or trivial fixtures.

## 7. Product decisions

- **Pass:** at least one orchestrated arm improves accepted outcomes or human correction effort while remaining non-inferior on defect escapes, unsupported claims, cost, and abandonment.
- **Fail:** orchestrated arms add cost/interruptions without a compensating quality or effort gain.
- **Inconclusive:** sample, variance, or budget integrity is insufficient.

A fail result triggers product simplification: default to the strongest single-agent path and expose multi-agent workflows only for categories where measured lift exists.

## 8. Milestone gate

S2 is complete only when live run receipts and case results validate against the v4.3 schemas, the comparison report is reproducible from included receipts, and the decision is not based on the bootstrap example. Memory expansion S6 remains locked until either orchestration value or a narrowly scoped memory treatment shows measured lift.
