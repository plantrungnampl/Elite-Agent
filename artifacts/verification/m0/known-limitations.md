# Known M0 limitations

- Repository mutation is unavailable.
- Agents, tools, and provider calls are unavailable.
- Approval operations are inactive: the design approval schema gaps (actor binding, workflow/expected-read/fenced-write fields, and canonical digest handling) remain deferred until the approval milestone. No M0 path relies on them.
- CI intentionally excludes secret-dependent provider, signing, and release jobs.
