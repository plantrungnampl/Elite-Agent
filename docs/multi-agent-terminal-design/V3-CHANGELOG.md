# v3 Change Log

- Reclassified the package from implementation-ready safety contract to implementation-oriented baseline with capability gates.
- Added authoritative SQLite v2 schema with append-only audit, monotonic fencing, immutable lease history, operation attempts, authority-scope checks, exact-tuple containment attestations, protocol trace state, actor-bound approval receipts, and immutable final commit candidates.
- Added protocol v2 schema with method-specific success responses and bounded namespaced extensions.
- Added approval digest v2 and decision receipt schema; final commit now requires a pre-created candidate commit OID.
- Added executable validation with 27 passing checks and generated evidence.
- Reordered roadmap so machine authority, broker races, exact approval, protocol conformance, and containment precede capability activation.
- Added assurance release gates, invariant registry, and v1-to-v2 migration contract.
