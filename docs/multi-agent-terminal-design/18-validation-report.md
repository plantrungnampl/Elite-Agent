# Validation Report

**Package:** Local-First Multi-Agent Engineering Terminal v2  
**Validation date:** 2026-07-23

## Results

| Check | Result |
|---|---|
| Markdown relative links | Passed; no missing target |
| Markdown fenced blocks | Passed; all fences balanced |
| JSON examples embedded in Markdown | Passed; all parsed |
| JSON files | Passed `jq` syntax validation |
| Protocol JSON Schema | Passed Draft 2020-12 compilation with format support |
| Approval JSON Schema | Passed Draft 2020-12 compilation with format support |
| Protocol fixtures | 3/3 valid |
| Final-commit approval fixture | 1/1 valid |
| SQLite schema creation | Passed against an in-memory SQLite database |
| SQLite integrity | `ok` |
| SQLite foreign-key check | 0 violations |
| SQLite behavioral smoke test | Passed event-sequence and fencing-token guards |
| Workflow transition references | Passed |
| Duplicate primary phase transition keys | None |
| Checksum manifest | Passed after final package generation |
| ZIP archive integrity | Passed after final package generation |

## Workflow contract summary

- 21 primary phase transitions;
- 6 condition transitions;
- 10 operation transitions;
- 18 declared phases;
- 3 terminal phases.

## SQLite contract summary

The schema contains the production tables, indexes, and triggers for:

- projects, tasks, events, projections, agents, runs, messages, and context;
- approvals, policy decisions, operation intents, and tool executions;
- content-addressed artifacts and cross-store journal entries;
- durable executor leases and monotonic fencing;
- verified memory, source chunks, and optional repository graph metadata;
- signed checkpoints and update recovery.

## Scope of validation

This report validates document consistency and executable contract syntax. It
does not claim that a future application binary has implemented or passed the
runtime containment, recovery, performance, or security acceptance suites.
Those remain milestone exit criteria.
