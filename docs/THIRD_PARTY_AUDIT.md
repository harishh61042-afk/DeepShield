# Third-party integration audit

| Service/dependency | Purpose | Data sent or accessed | Required for core scan? | Privacy/availability note |
|---|---|---|---|---|
| OSV.dev API | Canonical package/version vulnerability match | Ecosystem, package name and exact declared/resolved version candidates | Yes for live vulnerability matching | Package metadata leaves the local app; public service availability and rate limits apply |
| NVD API | Enrich matching CVEs with descriptions, CVSS and CWE | CVE IDs only | No; enrichment is best effort | Optional API key improves public limits; absence does not disable OSV scan |
| CISA KEV catalog | Known-exploitation list match | Full public catalog download; no user package list | Important for exploitation context | Cache is process-local and source may be unavailable/stale |
| Ollama | Optional structured explanation | Selected advisory and package metadata | No | Model runs locally when configured; model weights have separate terms/hardware requirements |
| PostgreSQL | Primary persistence and durable queue | Local account, project, parsed component and scan data | Yes | Operator controls backups and access |
| Mailpit / SMTP | Password-reset delivery | Email address and one-time reset link | No for scan; needed to deliver resets | Mailpit is development-only; use a real operator-controlled mail service in production |
| npm/PyPI/crates.io package registries | Optional license evidence refresh for versioned inventory entries | Ecosystem, package name and version sent to a fixed public registry; redirects are disabled | No | Bounded to 100 components per refresh; only allow-listed registry hosts are contacted. Evidence may be missing or stale and must be reviewed |
| GitHub Actions | Repository CI when workflow is enabled | Source checkout and test/build artifacts; optional policy-gate credentials are provided through GitHub secrets | No for local use | Default workflow does not require a DepShield hosted account. Example policy-gate workflow uses least-privilege `contents: read` |
| Playwright | Browser E2E test dependency | Browser runs against the configured local/CI app | No at runtime | Development-only test dependency; CI browser runs use isolated test data |

No analytics trackers, advertising SDKs, remote fonts or external AI APIs are included. Verify current licenses and service terms at release time.
