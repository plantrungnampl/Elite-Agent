# Known M3 limitations

- OpenAI adapter coverage uses deterministic loopback HTTP/SSE fixtures only. It is not a live OpenAI credential, network, service-availability, quota, or production-TLS certification.
- Credentials are injected only into the isolated provider test process for non-disclosure checks. Raw credentials are not retained in source, logs, manifests, reports, or other evidence artifacts.
- Provider behavior outside the exercised deterministic fixtures, including unsupported providers, remains unverified; the evidence makes no claim beyond the tested provider-neutral interfaces.
