# Operations, Packaging, and Platform Design

## 1. Platform strategy

MVP is supported on Windows 11. Portable interfaces are required for:

- process spawning;
- PTY sessions;
- path handling;
- secret storage;
- filesystem watches;
- process-tree termination;
- shell selection;
- application data directories.

Linux and macOS implementations can be added without changing domain or orchestration modules.

## 2. Windows implementation

Recommended platform services:

- ConPTY for interactive terminal sessions;
- Windows Job Objects for process-tree lifecycle, termination, and resource
  limits, not filesystem or network authorization;
- a dedicated low-privilege identity, explicit ACLs, and enforced network
  policy for workers that need OS access;
- DPAPI or Windows Credential Manager for secrets;
- native file notifications for incremental indexing;
- Git for Windows discovery with explicit executable path support;
- PowerShell as the default user-terminal shell with configurable alternatives;
  structured process tools never invoke it implicitly.

## 3. Application directories

```text
%LOCALAPPDATA%/AgentTerminal/
├── config/
├── database/
├── artifacts/
│   ├── objects/
│   ├── staging/
│   └── quarantine/
├── indexes/
├── logs/
├── plugins/
├── cache/
└── backups/
```

Project artifacts default to application data and reference the repository by a
stable identity. A project-local `.ai-workspace` is opt-in, automatically added
to a repository-local Git exclusion, receives restrictive ACLs, and cannot be
placed inside a task worktree.

## 4. Packaging

- Tauri signed installer;
- explicit versioning for application, database schema, and protocol;
- bundled migrations;
- optional embedded vector components;
- no bundled provider credentials;
- plugin directory created with restricted permissions;
- installer verifies required WebView runtime and Git availability;
- software bill of materials and locked dependency manifests;
- signed update metadata with monotonic version checks;
- no unsigned external executable plugin enabled by default.

## 5. Updates

Automatic updates should be opt-in during early releases. Update packages must be signed. Before applying an update:

1. ensure no non-resumable tool operation is running;
2. flush event and artifact stores;
3. create and verify a consistent SQLite online backup plus artifact and
   configuration manifest;
4. apply update;
5. run backward-compatible expand migrations;
6. verify storage integrity;
7. if startup health fails, either run the previous binary against a schema it
   supports or restore the complete pre-update database, artifact metadata, and
   configuration snapshot.

A binary rollback is never promised after an incompatible forward-only
migration. Artifact formats and policy bundles participate in the same upgrade
journal as SQLite.

## 6. Database migrations

- forward-only production migrations;
- expand/contract migrations remain readable by the immediately previous binary
  throughout the rollback window;
- migration version stored in SQLite;
- backup before destructive migration;
- migration tests against representative old databases;
- event payloads remain immutable and are upcast at read time;
- destructive contract steps run only after the rollback window closes and a
  verified backup exists.

## 7. Logging

Local structured logs include:

- component;
- severity;
- task and run correlation IDs;
- event or tool request ID;
- duration;
- error category.

Logs must exclude source content, prompts, responses, secrets, and raw environment variables by default. Full task output belongs in protected task artifacts, not application diagnostic logs.

Provider-reported usage, agent claims, and core observations use different
fields. Diagnostic logs never present untrusted values as verified facts.

## 8. Health checks

Startup health:

- SQLite open and integrity status;
- artifact directory read/write status;
- vector store availability;
- Git executable and version;
- agent manifest validation;
- provider credential references;
- orphaned worktrees and processes;
- pending migration status;
- unresolved operation intents and artifact journals;
- stale executor leases and current fencing epoch;
- artifact quarantine count;
- free disk reserve;
- update-journal state.

Agent health:

- initialization success;
- heartbeat;
- latency;
- recent error rate;
- rate-limit status;
- capability consistency.

## 9. Resource controls

Global limits:

- concurrent agent processes;
- concurrent provider requests;
- maximum child-process memory where enforceable;
- maximum command duration;
- maximum stored stream size;
- maximum task artifact size;
- vector index size warning;
- disk-space reserve;
- maximum protocol frame, stderr, terminal scrollback, and tool output sizes;
- maximum unresolved operation intents;
- maximum specialist depth and request fan-out.

## 10. Backup and recovery

The application provides:

- manual project backup;
- automatic database backup before migration;
- export of task audit packages;
- worktree recovery instructions;
- orphan cleanup that never deletes uncommitted work without user confirmation.

## 11. Plugin lifecycle

MVP plugin support:

- built-in signed adapters;
- local manifest import for inspection and health diagnostics, with external
  executable activation disabled;
- explicit enable/disable for built-in adapters;
- capability and permission display;
- health test;
- update performed by user;
- manifest digest binding.

Later production hardening:

- signature verification;
- publisher identity;
- permission-change review;
- isolated plugin host;
- revocation list;
- executable activation only after signature/trust decision and containment
  suite success;
- automatic disable and reapproval after executable, arguments, requested
  permissions, publisher, or trust tier changes.

`full_access_legacy` plugins remain disabled rather than being presented as
sandboxed. Job Objects and a restricted cwd are not sufficient to enable them.

## 12. Support diagnostics

A user-generated diagnostic bundle may include:

- application version;
- OS version;
- database schema version;
- sanitized component logs;
- agent health summary;
- failed event and error codes;
- no repository content or secrets;
- active trust-tier summary without executable arguments containing secrets;
- unresolved or indeterminate operation counts;
- artifact and database integrity status.

## 13. v3 startup and update gates

Startup remains closed to dispatch until it has verified runtime database pragmas, schema/update journal, immutable evidence reachability, leases, operation attempts, protocol traces, approval receipts, Git/worktree state, and containment attestation validity.

An update may not begin while a non-resumable or indeterminate effect is unresolved. Acceptance requires upgrade from every supported schema generation, crash injection around every migration/health switch, and either a compatible current generation or a verified whole-state restore. Database, artifacts, policy/config, update journal, and credential references form one backup generation; mixed generations are not success.

## v4 cognitive operations

The application exposes maintenance operations for:

- inspect and rebuild an index generation;
- verify memory evidence freshness;
- export memory, retrieval, context, and evaluation receipts without secret payloads;
- quarantine a retrieval adapter;
- migrate from legacy memory entries to versioned memory records;
- compare benchmark configurations;
- delete disposable index generations while preserving authority data.

Backup includes SQLite authority, content-addressed artifacts, policies, and migration receipts. Embedded vector/graph indexes may be excluded when a verified rebuild is possible. Sidecar or remote engine state is never the sole backup of memory.
