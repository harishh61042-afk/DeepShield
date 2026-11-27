# Threat model

## Assets

- Account credentials, session/reset token digests, email and display name.
- Project names/descriptions and owner/member relationships.
- Parsed dependency names, versions, package URLs, scan snapshots and reports.
- Audit events, intelligence cache, service credentials and application/database configuration.

## Trust boundaries

1. User browser to API: cookies, CSRF token, request validation and CORS/origin enforcement.
2. Uploaded file to parser: all bytes and archive metadata are hostile; parsing is bounded and read-only.
3. API/worker to PostgreSQL: parameterized SQL, foreign keys, transaction boundaries and authorization.
4. Worker to OSV/NVD/CISA: public external responses are untrusted; timeouts, schema checks and source attribution apply.
5. API to local Ollama: advisory text and package fields are untrusted data; only selected structured evidence is sent; output is schema-validated.
6. Operator environment to process: secrets and external service endpoints are operator-supplied; production settings reject selected unsafe defaults.

## Scenarios and mitigations

| Threat | Mitigations | Remaining risk |
|---|---|---|
| Cross-user ID guessing | Project access is checked before scans/findings/reports; unauthorized objects return 404 | Must be verified with PostgreSQL integration tests |
| Brute-force login/reset | Generic responses, Argon2id and process-local IP throttles | Distributed attacks need shared rate limiting and proxy-aware controls |
| CSRF against cookie session | SameSite cookies, separate CSRF cookie/header comparison, origin allowlist | Deployment proxy/domain behavior needs live verification |
| ZIP Slip/symlink/ZIP bomb | No extraction, traversal/symlink checks, entry/expanded/upload limits | Parser fuzzing and malformed-archive tests remain needed |
| XXE/malicious XML | `defusedxml`, size limit, no external resolution | Test malicious payload corpus before release |
| Shell or package execution | No subprocess/package install; parsing only | Syft/OSV-Scanner process integration is not implemented |
| SQL injection | SQLAlchemy query parameters and ORM | Validate inputs and run security tests |
| OSV/NVD/CISA outage or poisoned response | HTTPS, fixed destinations, response shape checks, source status, cache expiry | Upstream data correctness and availability are outside project control |
| Prompt injection in advisory/package data | Structured system/user messages treat all fields as untrusted; output schema checks; local model | Local model may still produce inaccurate advice; review required |
| Sensitive data sent to third parties | OSV receives package/version only, NVD receives CVE ID, Ollama is local | Public endpoint requests reveal queried package metadata to those services |
| Resource exhaustion | Upload/archive/component/query limits, HTTP timeouts, intelligence-call deadline and bounded worker retry | Full wall-clock limits and per-user quotas need further hardening |
| Admin privilege escalation | Registration fixes Developer role; role endpoint forbids Administrator grants | Secure administrator lifecycle is currently CLI-only |

## Data handling

The app does not store complete uploaded files. It stores parsed dependency data, source hash/name/size, findings and audit metadata. Project deletion removes project scan snapshots; global public vulnerability records and limited audit events may remain. Backups may retain deleted records until configured backup expiry. Operator policy and cleanup automation are required before public launch.
