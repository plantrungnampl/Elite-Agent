# Known M3 limitations

- OpenAI adapter coverage uses deterministic loopback HTTP/SSE fixtures only. It is not a live OpenAI credential, network, service-availability, quota, or production-TLS certification.
- The evidence runner passes a unique credential canary through `OPENAI_API_KEY` to every child gate command; only the provider-openai path is expected to consume it for non-disclosure checks. Raw credentials are not retained in source, logs, manifests, reports, or other evidence artifacts.
- Provider behavior outside the exercised deterministic fixtures, including unsupported providers, remains unverified; the evidence makes no claim beyond the tested provider-neutral interfaces.
