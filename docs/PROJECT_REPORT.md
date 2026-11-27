# DepShield: Project Report

## 1. Abstract

DepShield is a defensive web application for examining dependency manifests, generating a CycloneDX software bill of materials, matching exact package/version candidates against public vulnerability records, and prioritizing findings transparently. It combines a React/TypeScript browser client, FastAPI service, PostgreSQL persistence, a separate durable scan worker, OSV queries, optional NVD enrichment, CISA KEV status and optional local Ollama explanations. It never runs uploaded software or installs dependencies. This report describes the current implementation and explicitly distinguishes unfinished or unverified work.

## 2. Introduction

Modern software projects depend on direct and transitive packages maintained outside the project team. These packages can contain publicly disclosed vulnerabilities. A team needs an inventory, evidence of affected versions, a clear view of source availability and safe upgrade guidance.

## 3. Problem statement

Dependency declarations are spread across ecosystem-specific files. A version range may not identify the version that is installed. Vulnerability feeds may be temporarily unavailable, and a dashboard can mislead users if missing data is treated as a clean result. DepShield addresses those constraints with parsers, source-status reporting and historical scan snapshots.

## 4. Objectives

- Parse selected manifests without executing untrusted project content.
- Preserve package URL, version evidence, ecosystem and dependency directness where available.
- Generate CycloneDX JSON and store scan snapshots in PostgreSQL.
- Match package/version candidates against OSV and enrich matched CVEs with NVD and CISA KEV information where available.
- Calculate a deterministic, documented triage heuristic separate from official severity.
- Secure API access with sessions, CSRF checks, roles and object authorization.
- Produce downloadable reports and optional local AI explanations.
- Import/compare CycloneDX snapshots, evaluate project security policy, present evidence-based remediation and license reports, and monitor saved inventories on a schedule.

## 5. Existing system

Developers may manually inspect package files and public advisories or use ecosystem-specific scanners. Manual processes are difficult to repeat, compare and audit. This project does not claim all existing tools share the same limitations; it provides a focused academic implementation around a common workflow.

## 6. Proposed system

The browser submits a supported manifest to FastAPI. The API validates size, parses content, stores component metadata and enqueues a PostgreSQL job. A worker queries OSV, obtains KEV data, optionally enriches CVEs through NVD, scores findings and stores results. The browser displays stored scan state and authorized reports.

## 7. Literature and technology background

The project uses publicly documented vulnerability identifiers, package ecosystems, CycloneDX SBOM format, PostgreSQL transactions and Argon2id password hashing. It relies on primary technical references listed in Section 20. No academic paper or experimental claim is invented in this report.

## 8. Hardware requirements

- Minimum practical local development: 4 CPU cores, 8 GB RAM, several GB of disk, PostgreSQL and Node/Python runtimes.
- Optional Ollama model performance depends on the selected model, quantization, memory and hardware. A CPU-only small model may be slow. Ollama is not required for scans.
- Docker image and downloaded model storage depend on local configuration.

## 9. Software requirements

Python 3.12+, PostgreSQL 16+, Node.js 22.13+, 24, or 26+, npm, a modern browser, optional Docker Compose and optional Ollama. Backend direct versions are pinned in `requirements.txt`; frontend direct and transitive versions are locked in `frontend/package-lock.json`.

## 10. System architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). The API and durable worker share PostgreSQL. The worker is separate from request handling so long scans survive API restarts and can be reclaimed after stale locks.

## 11. Module descriptions

- **Authentication:** Argon2id, HMAC-digested opaque sessions, CSRF, password change/reset and account deletion endpoint.
- **Authorization:** Developer, Administrator and Auditor roles plus owner/read-only project membership checks.
- **Project management:** create, update, archive, delete and read-only auditor grants through the API.
- **File processing:** bounded multipart and ZIP content; no extraction, package installs or source execution.
- **Parsers:** requirements, package-lock, Maven POM, go.mod and Cargo.lock.
- **SBOM:** CycloneDX 1.6 JSON with PURLs, source/evidence properties and known relationships.
- **Intelligence:** OSV batch matching, CISA KEV and optional NVD enrichment with visible source availability.
- **Risk:** transparent CVSS/KEV/directness/fix heuristic; unknown CVSS is not zero.
- **AI:** optional local Ollama with structured validation; deterministic fallback labelled honestly.
- **Reports:** authorized JSON/PDF and CycloneDX downloads.
- **Security Center:** structural CycloneDX import validation, snapshot diffing, package-url OSV checks, persisted policy decisions and remediation plans based on OSV version/range evidence.
- **License review:** fixed public registry metadata lookups, recognized license identifiers, allow/restricted policy review, and JSON/PDF evidence reports. Unknown licenses remain review items.
- **Monitoring:** scheduled scans reuse parsed inventory in the durable worker queue; project-owner alerts are idempotent and optional SMTP delivery is configurable.
- **CI:** GitHub Actions runs backend, PostgreSQL, frontend, dependency-audit and Playwright jobs; an example policy gate uses the authenticated API.
- **Frontend:** public pages and authenticated project, dashboard, scan, findings, settings and administrator views.

## 12. Database design

See [DATABASE_DESIGN.md](DATABASE_DESIGN.md). Initial migration tables include users, sessions, reset tokens, projects, memberships, scans, scan jobs, components, vulnerabilities, intelligence cache, findings and audit records.

## 13. Implementation details

The implementation uses synchronous SQLAlchemy sessions in FastAPI endpoints and the worker. Public data calls use HTTPX timeouts. XML is parsed with `defusedxml`; ZIP members are read in memory after path/size checks. OSV cache keys are SHA-256 hashes of ecosystem/name/version and have expiry timestamps. Passwords are never stored as plain text.

## 14. Algorithms

Risk score: `min(100, round(CVSS × 6) + KEV(25) + direct(10) + fix(5))`. Official severity uses the CVSS base score categories independently. Missing CVSS yields an unknown score/priority. Component matching uses exact name/ecosystem/version query candidates through OSV; no substring-based NVD CPE guess is used.

## 15. Security methodology

The project applies least-privilege access checks, parameterized persistence, CSRF protection, secure cookie configuration, input and archive bounds, no shell invocation, no uploaded code execution, generic production errors and AI prompt-injection constraints. See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md). No penetration-test or certification claim is made.

## 16. Testing methodology

Unit tests cover parsers, archive limits, API/auth flows, scan-worker lifecycle, new Security Center behavior, frontend helpers and feature interactions. PostgreSQL migration/queue integration, browser E2E and Compose rebuild results are tracked in [TEST_REPORT.md](../TEST_REPORT.md). Accessibility automation, performance and security certification remain separate checks. See [TESTING.md](TESTING.md).

## 17. Results

Backend unit/API tests and Ruff pass; frontend tests, lint, TypeScript/Vite build and npm audit pass. The PostgreSQL integration test passes against an isolated `depshield_test` database, and Compose services rebuild with API/database readiness passing. A representative CycloneDX 1.6 document passed a one-off official-schema check, while runtime import uses bounded structural validation. Exact current results and browser verification status are in `../TEST_REPORT.md`.

## 18. Limitations

Automated official CycloneDX JSON Schema validation for every BOM, Syft/OSV-Scanner invocation, generated-report metadata, AI explanation history, deletion-request review workflow, exhaustive ecosystem resolution semantics, distributed rate limiting, audit/back-up retention and operational restore controls remain incomplete or unverified. Browser E2E does not provide axe/screen-reader or penetration-test coverage. Account deletion is immediate after current-password confirmation; scan snapshots are pruned by the worker according to `DATA_RETENTION_DAYS`.

## 19. Future enhancements

Container scanning, release provenance verification, reachability analysis and expanded ecosystem/registry coverage remain future work. CI workflow, saved-inventory monitoring, SBOM comparison and license policy are implemented in this workspace; the CI example does not imply hosted GitHub repository scanning.

## 20. References

1. Open Source Vulnerabilities (OSV) API, [querybatch](https://google.github.io/osv.dev/post-v1-querybatch/).
2. CycloneDX, [CycloneDX Specification](https://cyclonedx.org/specification/overview/).
3. National Vulnerability Database, [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities).
4. CISA, [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
5. SQLAlchemy, [Managing Transactions](https://docs.sqlalchemy.org/en/20/orm/session_transaction.html).
6. FastAPI, [OAuth2 password flow and password hashing](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/).
7. RFC 9106, [Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications](https://www.rfc-editor.org/rfc/rfc9106).
8. OWASP, [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
9. CycloneDX, [official 1.6 JSON schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json).

## 21. Conclusion

DepShield demonstrates a modular path from dependency manifest to source-attributed vulnerability findings and downloadable SBOM/report output. The architecture keeps uploads unexecuted and uncertainty visible. The project is a substantial foundation, not yet a verified production release or completion of every requirement in the master prompt.
