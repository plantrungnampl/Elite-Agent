# Known M3 limitations

- OpenAI adapter coverage uses deterministic loopback HTTP/SSE fixtures only. It is not a live OpenAI credential, network, service-availability, quota, or production-TLS certification.
- The runner inherits a unique credential canary through `OPENAI_API_KEY` into every child gate command solely as a leak detector. Provider configuration remains explicit and in-memory, and provider tests use explicit deterministic fixtures; no provider path is expected to consume `OPENAI_API_KEY`. Raw credentials are not retained in source, logs, manifests, reports, or other evidence artifacts.
- Provider behavior outside the exercised deterministic fixtures, including unsupported providers, remains unverified; the evidence makes no claim beyond the tested provider-neutral interfaces.
