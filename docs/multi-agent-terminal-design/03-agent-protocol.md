# MAT Agent Control Protocol v2

## 1. Purpose and trust model

The internal protocol was previously called “Open Agent Protocol.” v4.3 uses the collision-free name **MAT Agent Control Protocol (MACP)**; method names and wire compatibility remain unchanged.

The protocol lets a provider adapter or external agent participate without
linking provider-specific behavior into application use cases. The protocol is
bidirectional JSON-RPC 2.0: the core can start or cancel a run, while an agent
can request context, tools, or a specialist.

Protocol compatibility does not imply trust. The core binds every connection to
the executable, manifest, launch record, effective trust tier, and negotiated
capabilities. An agent-supplied ID, timestamp, cost, tool result, or claim is
untrusted until the core records or verifies it.

The machine-readable payload contract is
[`schemas/agent-protocol.v2.schema.json`](schemas/agent-protocol.v2.schema.json).
Schema-valid fixtures are in [`schemas/examples-v2`](schemas/examples-v2).

## 2. Transport profile

MVP transport is UTF-8 newline-delimited JSON-RPC 2.0 over a child process's
stdin/stdout.

Rules:

- stdout contains protocol frames only;
- stderr contains bounded diagnostic text and is never parsed as protocol;
- one complete JSON object occupies one line;
- embedded line breaks are JSON-escaped;
- the default maximum frame is 8 MiB;
- both peers honor operating-system pipe backpressure;
- request IDs are strings and unique for the connection;
- core-originated IDs start with `core:` and agent-originated IDs with `agent:`;
- a message without `id` is a notification and must not receive a response;
- malformed JSON, duplicate terminal messages, or a stream sequence gap fails
  the affected run;
- large content uses opaque authorized references rather than oversized frames.

HTTP and WebSocket transports may be added later but must preserve the same
method semantics, identity binding, limits, and schemas.

## 3. Method ownership

| Method | Initiator | Kind | Meaning |
|---|---|---|---|
| `initialize` | Core | Request | Negotiate one protocol version and capabilities |
| `initialized` | Core | Notification | Confirm that initialization state is active |
| `agent.run.start` | Core | Request | Ask the agent to accept a stable run ID |
| `agent.run.cancel` | Core | Request | Request cancellation and acknowledgement |
| `agent.run.complete` | Agent | Request | Submit the single terminal result |
| `agent.stream.delta` | Agent | Notification | Emit presentation-only streaming content |
| `context.query` | Agent | Request | Ask the core for additional authorized context |
| `tool.request` | Agent | Request | Ask the core to evaluate and execute a tool |
| `specialist.request` | Agent | Request | Ask the orchestrator for another capability |
| `agent.heartbeat` | Agent | Notification | Report liveness for a long-lived process |
| `shutdown` | Core | Request | Ask the process to shut down cleanly |
| `exit` | Core | Notification | End the protocol session after shutdown |

Every request receives exactly one success or error response. A response only
confirms the corresponding request; it is not a workflow transition.

## 4. Initialization

### 4.1 Core request

<!-- protocol-schema:initializeRequest fixture=schemas/examples-v2/protocol-initialize.request.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "core:1",
  "method": "initialize",
  "params": {
    "protocolVersions": [
      "2.0"
    ],
    "capabilities": [
      "agent.stream.delta",
      "context.query",
      "tool.request",
      "specialist.request"
    ],
    "connectionBindingDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

### 4.2 Agent response

<!-- protocol-schema:initializeResponse fixture=schemas/examples-v2/protocol-initialize.response.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "core:1",
  "result": {
    "protocolVersion": "2.0",
    "capabilities": [
      "agent.stream.delta",
      "context.query",
      "tool.request",
      "specialist.request"
    ],
    "connectionId": "conn-71",
    "limits": {
      "maxFrameBytes": 8388608,
      "maxPendingRequests": 128,
      "streamHighWatermark": 512,
      "streamLowWatermark": 256
    }
  }
}
```

The core rejects a response that selects an unoffered protocol version, exceeds
manifest limits, or requests a higher trust tier. Capabilities may be reduced
by policy but never expanded by handshake.

After validation the core emits:

<!-- protocol-schema:initializedNotification fixture=schemas/examples-v2/protocol-initialized.notification.json -->
```json
{
  "jsonrpc": "2.0",
  "method": "initialized",
  "params": {
    "connectionId": "conn-71"
  }
}
```

## 5. Manifest

```yaml
schema_version: 1
id: qwen-coder-local
display_name: Qwen Coder Local
transport:
  type: stdio-ndjson
  executable: C:\Program Files\AgentTerminal\agents\qwen-agent.exe
  args: [serve, --protocol, jsonrpc]
capabilities:
  roles: [analyst, critic, executor, reviewer]
  skills: [code-analysis, implementation, testing]
limits:
  max_concurrent_runs: 1
  max_context_tokens: 32768
  max_frame_bytes: 8388608
security:
  requested_trust_tier: brokered_process
  network: denied
  filesystem: brokered
  shell: brokered
health:
  startup_timeout_ms: 15000
  heartbeat_interval_ms: 30000
```

The executable is launched directly from a canonical absolute path, never
through shell lookup. The core records the executable and manifest digests for
each connection. A manifest is a permission request, not an authorization.

## 6. Run lifecycle

```mermaid
sequenceDiagram
    participant C as Core
    participant A as Agent
    C->>A: agent.run.start request
    A-->>C: accepted response
    A--)C: agent.stream.delta notifications
    A->>C: context.query or tool.request
    C-->>A: authorized result or error
    A->>C: agent.run.complete request
    C-->>A: terminal result accepted
```

`agent.run.start` returns promptly. It does not keep one JSON-RPC request open
for the duration of the model run.

<!-- protocol-schema:runStartRequest fixture=schemas/examples-v2/protocol-run-start.request.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "core:8",
  "method": "agent.run.start",
  "params": {
    "runId": "run-238",
    "taskId": "task-1",
    "contextPackageRef": "ctx-501",
    "idempotencyKey": "task-1:analysis:qwen:1",
    "role": "critic"
  }
}
```

The immutable `contextPackageRef` and `RunConfiguration v1` binding carry the objective, effective permissions, provider/model snapshot, response schema, deadline, and budgets; those fields are not duplicated in the closed v2 frame.

Acceptance:

<!-- protocol-schema:runStartResponse fixture=schemas/examples-v2/protocol-run-start.response.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "core:8",
  "result": {
    "runId": "run-238",
    "accepted": true
  }
}
```

At most one `agent.run.complete` request is accepted for a run. Connection loss
before an accepted terminal request marks the run `interrupted`. MVP restarts
the work as a new run with `supersedesRunId`; it does not pretend to resume an
unrecoverable model generation.

## 7. Streaming

<!-- protocol-schema:streamDeltaNotification fixture=schemas/examples-v2/protocol-stream-delta.notification.json -->
```json
{
  "jsonrpc": "2.0",
  "method": "agent.stream.delta",
  "params": {
    "runId": "run-238",
    "sequence": 17,
    "channel": "content",
    "delta": "The main risk is"
  }
}
```

Sequence starts at `1` and increases by one. A duplicate with identical bytes
is ignored; a conflicting duplicate or gap fails the stream. Stream deltas are
untrusted presentation data. They are not evidence, project memory, or the
authoritative run result.

The core enforces per-run byte and token budgets. When a limit is reached it
cancels the run rather than dropping an unknown suffix and accepting a
potentially malformed final result.

## 8. Context requests

Because the agent expects a result, `context.query` is a JSON-RPC request and
must include `id`.

<!-- protocol-schema:contextQueryRequest fixture=schemas/examples-v2/protocol-context-query.request.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "agent:12",
  "method": "context.query",
  "params": {
    "runId": "run-238",
    "queryId": "cq-12",
    "query": "Previous verified decisions about authentication persistence",
    "scopes": [
      "project-memory",
      "decisions",
      "repository"
    ],
    "maxItems": 12,
    "maxTokens": 8000
  }
}
```

The response returns an immutable supplement:

<!-- protocol-schema:contextQueryResponse fixture=schemas/examples-v2/protocol-context-query.response.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "agent:12",
  "result": {
    "queryId": "cq-12",
    "items": [
      {
        "itemId": "ctx-item-44",
        "contentRef": "artifact:ctx-supp-44:item-1",
        "contentDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "sourceRefs": [
          "decision:auth-persistence-v3"
        ],
        "observationClass": "core_observed"
      }
    ],
    "truncated": false,
    "effectivePayloadDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "redactionReportDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }
}
```

Opaque references never reveal an operating-system path. Reads of referenced
content remain mediated and scoped to the run.

## 9. Tool requests

<!-- protocol-schema:toolRequest fixture=schemas/examples-v2/protocol-tool.request.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "agent:77",
  "method": "tool.request",
  "params": {
    "runId": "run-238",
    "requestId": "tool-77",
    "planStepId": "step-4",
    "executorFencingToken": null,
    "tool": "git.diff",
    "arguments": {
      "path": "src/auth"
    },
    "argumentsDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "reason": "Verify whether the proposed change matches the approved scope"
  }
}
```

Read-only requests omit the fencing token. Every write-capable request must
carry the current token and is rejected if the lease changed.

Possible results:

- success with result artifact references;
- denied with matched policy rules;
- approval required with an immutable approval request ID;
- redacted success;
- typed tool error.

Process execution uses structured arguments:

```json
{
  "tool": "process.exec",
  "arguments": {
    "executable": "toolchain:cargo",
    "argv": ["test", "--workspace", "--locked"],
    "cwd": "worktree:",
    "environmentProfile": "rust-build-no-secrets",
    "network": "denied",
    "timeoutMs": 600000,
    "expectedWrites": ["target/**"]
  }
}
```

`shell.raw` is a separate tool classification. A free-form string passed to
`process.exec` is invalid and is not repaired or reinterpreted as shell syntax.

## 10. Specialist requests

<!-- protocol-schema:specialistRequest fixture=schemas/examples-v2/protocol-specialist.request.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "agent:91",
  "method": "specialist.request",
  "params": {
    "runId": "run-238",
    "requestId": "specialist-91",
    "capability": "database-migration-review",
    "reason": "The proposal introduces a new token-family table.",
    "requiredContext": [
      "artifact:proposal-3",
      "source:schema.sql"
    ]
  }
}
```

The orchestrator may approve, reject, reuse a participant, or request user
approval. The response never grants the requesting agent additional access.
Specialist depth, count, cost, and context are bounded by the parent task.

## 11. Final message and evidence

The agent submits the terminal result in `agent.run.complete`:

<!-- protocol-schema:runCompleteRequest fixture=schemas/examples-v2/protocol-run-complete.request.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "agent:100",
  "method": "agent.run.complete",
  "params": {
    "runId": "run-238",
    "status": "succeeded",
    "message": {
      "messageId": "msg-900",
      "type": "critique",
      "replyTo": "msg-877",
      "threadId": "thread-auth-security",
      "content": "The proposal does not revoke the token family after reuse detection.",
      "claims": [
        {
          "statement": "Current code has no token-family invalidation path.",
          "observationClass": "agent_claimed",
          "evidenceRefs": [
            "source:src/auth/token_service.rs@worktree-task-1-abc123:88-140"
          ]
        }
      ]
    },
    "usage": {
      "inputTokens": 12000,
      "outputTokens": 1800,
      "providerReportedCostMicrounits": 80000
    }
  }
}
```

The core:

1. binds the message to the authenticated connection and run;
2. assigns the authoritative receipt timestamp and event sequence;
3. validates every evidence reference and marks missing or stale evidence;
4. records provider-reported usage separately from core estimates;
5. persists the terminal event before acknowledging it.

Agent-supplied `authorAgentId` and authoritative timestamps are intentionally
absent from the payload.

## 12. Cancellation and shutdown

Cancellation is a request:

<!-- protocol-schema:runCancelRequest fixture=schemas/examples-v2/protocol-run-cancel.request.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "core:30",
  "method": "agent.run.cancel",
  "params": {
    "runId": "run-238",
    "reason": "user_cancelled"
  }
}
```

The agent acknowledges whether cancellation was accepted. The cancellation deadline is core-owned connection state rather than peer-controlled frame data. If the process does not stop
by that deadline, the core terminates the process tree and records the run as
`terminated`, not `cancelled_cleanly`.

For normal process shutdown the core sends `shutdown`, waits for its response,
then sends the `exit` notification. Unexpected process exit interrupts every
active run on that connection.

## 13. Errors

<!-- protocol-schema:errorResponse fixture=schemas/examples-v2/protocol-error.response.json -->
```json
{
  "jsonrpc": "2.0",
  "id": "core:8",
  "error": {
    "code": -32031,
    "message": "Context window exceeded",
    "data": {
      "category": "context_too_large",
      "retryable": true,
      "suggestedMaxTokens": 24000
    }
  }
}
```

Reserved application error categories:

- `protocol_incompatible`
- `invalid_request`
- `identity_binding_failed`
- `provider_unavailable`
- `rate_limited`
- `context_too_large`
- `cancelled`
- `timeout`
- `policy_denied`
- `approval_required`
- `stale_fencing_token`
- `malformed_structured_output`
- `output_limit_exceeded`
- `internal_agent_failure`

Only the core classifies whether a workflow retry is safe.

## 14. Compatibility and conformance

- a major protocol mismatch fails initialization;
- a minor version may add optional fields and methods;
- unknown optional fields are ignored and preserved when proxying;
- unknown required capabilities fail before dispatch;
- payload schema versions evolve independently but must be declared;
- every adapter must pass the protocol conformance suite;
- an adapter cannot claim tool execution without a matching core tool receipt;
- evidence references must resolve to the recorded revision or be marked
  external and unverified;
- context input is reconstructible, but model output is not claimed to be
  deterministic or reproducible.

The run record captures protocol version, manifest and executable digests,
adapter version, provider/model identifier, generation parameters, prompt
template version, response schema version, policy snapshot, and exact context
package digest.


## 15. v2 method-specific response and durable trace contract

Protocol validation has three independent layers:

1. **Frame schema:** encoding, size, method parameters, and method-specific result/error shape.
2. **Authenticated connection state:** direction ownership, negotiated version/capabilities, pending `(connectionId, requestId, method)`, queue limits, and backpressure.
3. **Durable trace state:** request digest replay, one terminal response, stream sequence continuity, and restart behavior.

The receiver looks up the pending method from `protocol_requests` and validates the response against that method's `$defs/*Response` schema. It MUST NOT trust a peer-supplied method discriminator. The v2 schema defines distinct results for `initialize`, `agent.run.start`, `agent.run.cancel`, `agent.run.complete`, `context.query`, `tool.request`, `specialist.request`, and `shutdown`.

Core and authority objects remain closed. Forward-compatible optional data may appear only inside the bounded namespaced `extensions` object after capability negotiation. The same `(connectionId, requestId)` with the same canonical request digest returns the persisted/current result; the same identifier with a different digest is a protocol conflict. A completed or failed request is terminal across restart.

Backpressure is quantitative. Each connection negotiates maximum frame bytes, maximum pending requests, stream high/low watermarks, and overflow behavior. Authoritative requests, responses, audit records, and terminal messages are never dropped. Telemetry may be sampled or dropped only under an explicit negotiated policy.

## 16. Cognitive extension v1

The cognitive extension capability is negotiated under `cognitive-memory.v1`. Its current payload authority is `schemas/cognitive-memory.v4.schema.json`; extension capability version and payload schema version evolve independently. It does not change the authority model of MAT Agent Control Protocol v2.

### 16.1 Capability negotiation

An agent manifest may declare:

```json
{
  "extensions": {
    "cognitive-memory.v1": {
      "progressiveContext": true,
      "workingMemoryEvents": true,
      "contextFeedback": true,
      "structuredReflection": true
    }
  }
}
```

The core may decline any extension. Absence of the extension does not prevent the core from compiling an initial cognitive context package.

### 16.2 Progressive context methods

Supported requests:

- `context.request_more`;
- `context.request_source`;
- `context.request_related_symbols`;
- `context.request_previous_failures`;
- `context.request_decision_history`.

Every request includes `runId`, `requestId`, reason, requested scope, maximum items, and maximum tokens. The response returns an immutable supplement ID, exact digest, provenance, redactions, policy decisions, and remaining budget.

### 16.3 Working-memory events

The agent may emit:

- `agent.fact.record`;
- `agent.inference.record`;
- `agent.unknown.record`;
- `agent.hypothesis.open`;
- `agent.hypothesis.resolve`;
- `agent.next_action.set`;
- `agent.check.record`.

A fact requires evidence references. An inference identifies supporting facts and confidence. An unknown or hypothesis cannot be submitted as evidence in `agent.run.complete` without later resolution.

### 16.4 Context feedback

`context.feedback` is a request with one entry per referenced package or supplement item. Allowed labels are `critical`, `useful`, `redundant`, `irrelevant`, `stale`, `contradictory`, and `misleading`.

Feedback is retained for evaluation and offline tuning. It does not mutate authority data or current retrieval ranking in place.

### 16.5 Reflection

`agent.run.reflect` may be sent only after `agent.run.complete` and before the core closes the reflection window. It contains observed outcome, failed assumptions, useful evidence, wasted actions, proposed lessons, and remaining uncertainty.

Reflection is untrusted input. The core binds it to the run and sends it to the Learning Engine only after outcome verification and quality evaluation.

### 16.6 Error codes

- `COGNITIVE_EXTENSION_NOT_NEGOTIATED`;
- `CONTEXT_BUDGET_EXHAUSTED`;
- `CONTEXT_SCOPE_DENIED`;
- `CONTEXT_SOURCE_STALE`;
- `WORKING_MEMORY_SEQUENCE_CONFLICT`;
- `FACT_EVIDENCE_REQUIRED`;
- `REFLECTION_WINDOW_CLOSED`;
- `RETRIEVAL_DEGRADED`.

The current machine-readable payloads are defined in [`schemas/cognitive-memory.v4.schema.json`](schemas/cognitive-memory.v4.schema.json). Historical v1-v3 payload schemas remain migration and regression inputs only.
