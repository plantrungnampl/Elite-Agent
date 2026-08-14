# Run Configuration, Independence, and Assurance

## 1. Purpose

A completed agent response is not reproducible unless the system can reconstruct which provider connection, adapter, resolved model, prompt profile, capabilities, policy, budget, fallback rule, and independence group were used. `RunConfiguration v1` freezes those facts for each run without retaining credential material.

## 2. RunConfiguration v1

The canonical wire contract is `schemas/run-configuration.v1.schema.json`. Its digest is stored in the run artifact and bound to the run by `run_configuration_bindings` in SQLite v7.

Required sections:

| Section | Required meaning |
|---|---|
| `providerConnectionRef` | opaque trusted-core reference; never an API key or token |
| `adapter` | adapter identity/version, transport, protocol, and optional implementation digest |
| `modelEndpoint` | provider, resolved model ID, model family, endpoint class, capacity limits, and optional region |
| `agentProfile` | role, profile ID, prompt version, tool policy, and response schema |
| `generationParameters` | exact decoding/output controls |
| `capabilitySnapshot` | negotiated tools, structured output, streaming, cancellation, context query, vision, and parallelism |
| `dataPolicySnapshot` | policy digest, retention, provider-training policy, allowed data classes, and network scope |
| `budgetReservation` | input, output, tool, wall-time, and cost ceilings |
| `fallbackPolicy` | none or explicit-only candidate set; silent substitution is forbidden |
| `independence` | group ID and fingerprint over correlation dimensions |
| `credentialsExcluded` | must be `true` |

Changing any section creates a new configuration artifact and a new run. A run configuration binding is immutable and retained.

## 3. Connection lifecycle

1. The trusted core stores credentials in an OS-backed or enterprise credential mechanism.
2. The design artifact stores only `providerConnectionRef`.
3. The adapter resolves the connection at launch and returns a capability snapshot.
4. The core freezes the resolved model and capability snapshot before `agent.run.start`.
5. The protocol frame references `runConfigurationRef` and `contextPackageRef`; it does not duplicate mutable model fields.
6. Logs and benchmark receipts record digests and references, never credential bytes.

A single configured provider is sufficient for Quick and Standard operation when policy permits. The UI reports unavailable profiles rather than forcing a user to authenticate every provider.

## 4. Independence model

Agent count is not evidence of independent review. Two runs belong to the same correlation group when their effective assumptions are likely to fail together.

The fingerprint includes:

- provider;
- model family;
- prompt family;
- context corpus/package;
- retrieval pipeline;
- tool policy;
- adapter implementation.

The scheduler records both a human-readable `groupId` and a canonical digest. Policy may require stronger separation for specific risk classes.

Default assurance policy:

| Profile | Minimum run structure | Default independence requirement |
|---|---|---|
| Quick | one primary path; optional verifier | no distinct-group requirement |
| Standard | primary plus cross-review | reviewer must not be the same run; distinct group preferred and measured |
| HighAssurance | primary/executor plus final reviewer | at least two distinct groups and hard executor/reviewer separation |
| ReadOnlyResearch | research plus source/evidence verification | separation based on research risk; no write capability |

Same-model multi-sampling is a benchmark arm, not automatically independent. It must report a shared group with different sample IDs unless another fingerprint dimension materially changes.

## 5. Degraded assurance

A task that cannot satisfy its requested assurance policy must not silently continue as though the policy were met. The core creates `AssuranceDegradationReceipt v1` with:

- requested profile;
- policy requirements;
- observed run groups and role separation;
- reason code;
- decision: `pause`, `cancel`, or `continue_degraded`;
- exact run-set digest;
- actor proof and acceptance artifact when continuing;
- immutable receipt digest.

`continue_degraded` preserves the requested profile label but visibly marks the task as degraded. It does not rewrite history or downgrade the profile. Subsequent reports, completion packages, and exports include the degradation receipt.

## 6. Fallback

`fallbackPolicy.mode=none` permits no model replacement. `explicit_only` lists candidates and requires user approval. A fallback run:

1. terminates or supersedes the unavailable run with a reason receipt;
2. creates a new run ID and new configuration artifact;
3. recomputes independence and assurance status;
4. re-evaluates budgets;
5. shows the substitution in the task timeline.

A provider/model change can never reuse the previous `configDigest`, run receipt, or benchmark arm identity.

## 7. Security properties

- No credential field is legal in the schema.
- Connection references are not proof of authorization; the trusted credential subsystem rechecks access at launch.
- External agents receive only mediated protocol data.
- Model and capability claims are frozen as observations, not trusted declarations of safety.
- Data policy and network scope remain enforced by the broker even when the model claims broader capability.
