# Task 7 report - MACP v2 protocol/runtime/provider cutover

## Scope and contract ruling

- Replaced the protocol crate's generated source with `agent-protocol.v2.schema.json` and made the codec validate the closed v2 request and response definitions directly.
- Added explicit allowlists for the 13 canonical v2 fixtures. `protocol-tool.response.json` is exercised separately and no test assumes the directory has a fixed number of files.
- Moved session negotiation, correlation, replay, terminal, sequence, pending-limit, and backpressure state to the v2 contract.
- Updated runtime frames, replay handling, fake peers, and both provider adapters/requests to use v2 descriptors and the out-of-band execution binding.
- Kept `docs/multi-agent-terminal-design/**` read-only.

Document 39, section 3.5 says an `agent.run.start` frame references `runConfigurationRef`. That conflicts with the closed canonical `runStartRequest` schema and the approved Task 7 ruling. The machine-readable v2 schema governs this implementation: the frame contains exactly `runId`, `taskId`, `contextPackageRef`, `idempotencyKey`, and optional `role`; `runConfigurationRef` and RunConfiguration limits remain out of band.

## TDD and review evidence

- Switching generated types and fixtures to v2 exposed the remaining v1 field, method, and response-shape assumptions before implementation.
- Closed-codec regressions cover v1-field rejection, method ownership prefixes, response ambiguity, bounded frames, and direct validation of each named v2 definition.
- Session regressions cover durable method-specific response validation, exact request replay versus digest conflicts, one terminal request, stream gaps, pending/high-low limits, rejected post-terminal requests not consuming pending capacity, and policy capabilities that may reduce but never expand during initialization.
- Runtime replay regressions retain defense in depth for a schema-valid frame that bypasses the wire codec with the wrong request owner; normal wire decoding rejects it at the codec boundary.
- Self-review found and repaired two state-machine edges: late agent requests no longer reserve pending capacity, and an initialize response cannot add a manifest-supported capability that the core policy did not request.

## Implementation details

- `RunExecutionBinding` carries provider-neutral execution data, including `max_output_tokens`, outside `agent.run.start`; providers derive their output limit from that binding only.
- The session records connection ID, request ID, method, canonical digest, origin, and optional run ID. It validates responses with the stored method rather than a peer-supplied discriminator.
- The runtime sink caches typed responses by request ID and replays only the exact method/digest tuple. A changed tuple returns the v2 `protocol_conflict` category.
- Provider descriptors advertise protocol `2.0` and v2 capability names. OpenAI and Anthropic terminal, cancel, and start behavior use v2 frame shapes.

`crates/agent-runtime/src/runtime/sink.rs`, `crates/agent-runtime/src/fakes.rs`, both provider request modules, and the focused acceptance/routing tests were necessary scope expansions: they are the execution and test boundaries that otherwise retained v1 wire assumptions or could not prove exact replay behavior.

## Fresh verification

- `cargo fmt --all -- --check` - exit 0.
- `cargo clippy -p local-agent-terminal-agent-protocol -p local-agent-terminal-agent-runtime -p local-agent-terminal-provider-openai -p local-agent-terminal-provider-anthropic --all-targets --all-features -- -D warnings` - exit 0.
- `cargo test -p local-agent-terminal-agent-protocol --all-features` - 28 passed, 0 failed.
- `cargo test -p local-agent-terminal-agent-runtime --all-features` - 76 passed, 0 failed.
- `cargo test -p local-agent-terminal-provider-openai --all-features` - 28 passed, 0 failed.
- `cargo test -p local-agent-terminal-provider-anthropic --all-features` - 32 passed, 0 failed.
- Production source scan for v1 schema/version strings and `runConfigurationRef` - no matches.
- Scoped `git diff --check` - exit 0 (only Git line-ending conversion warnings).
- All 30 changed Rust files are below 2,000 lines; the largest is `crates/provider-anthropic/tests/streaming_contract.rs` at 1,364 lines.

## Integration concern

The v2 schema is currently an untracked, user-owned file in the preserved docs worktree and is absent from `HEAD`. Task 7 intentionally does not stage or commit docs, so this code-only commit requires the docs/schema owner's companion commit for a clean checkout to build. The full-worktree `git diff --check` also reports pre-existing trailing whitespace only in the untouched docs files `00-README.md` and `18-validation-report.md`; the Task 7 scoped check is clean.

## Fix round 1 - durable protocol correlation

- Added application-owned durable protocol request identities, pending/terminal records, exact response artifacts, and per-channel stream heads.
- Implemented the existing v7 `protocol_requests` and `protocol_stream_heads` authority in SQLite. Exact tuples replay immutable response bytes after reopen; method or digest drift conflicts; terminal completion verifies the physically published artifact before changing the row.
- Extended `ProtocolSession` with exact pending-request restoration, method-specific response prevalidation without state mutation, and per-channel stream-head restoration.
- Made core `initialize`, `agent.run.start`, and `agent.run.cancel` use stable durable request identities. Core responses now follow validate, publish artifact, complete terminal row, then mutate session state or return to the caller. Completed starts and cancels replay after reconstruction without another peer side effect.
- Made agent-originated completed, failed, and rejected responses publish immutable evidence before terminalizing their durable request row. Exact restart replay bypasses routing; tuple drift returns `protocol_conflict`.
- Injected the request store and protocol-response publisher through runtime/bootstrap composition, and extracted the bootstrap publisher to keep every touched source file below 2,000 lines.
- Restored durable stream heads before accepting the next per-channel sequence. The pending-start crash-window regression proves the next sequence is accepted only after restoration.

### Fix round 1 verification

- `cargo test -p local-agent-terminal-agent-protocol` - all unit, codec, conformance, schema, session, and doc tests passed; session contract 15 passed.
- `cargo test -p local-agent-terminal-agent-runtime` - 5 unit, 2 fake-conformance, and 77 runtime-contract tests passed; doc tests passed.
- `cargo test -p local-agent-terminal-application` - all application tests and doc tests passed; durable protocol store contract 2 passed.
- `cargo test -p local-agent-terminal-storage-sqlite --test agent_store` - 24 passed, including exact terminal replay/reopen/conflict evidence.
- `cargo test -p local-agent-terminal-provider-openai -p local-agent-terminal-provider-anthropic` - both provider packages and doc tests passed.
- `cargo test -p local-agent-terminal-bootstrap agent_runtime::tests::` - 5 passed.
- `cargo clippy -p local-agent-terminal-agent-runtime --all-targets -- -D warnings` and `cargo clippy -p local-agent-terminal-bootstrap --all-targets -- -D warnings` - exit 0.
- `cargo fmt --all -- --check` - exit 0.
