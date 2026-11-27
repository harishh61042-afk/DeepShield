# Changelog

## Unreleased - 2026-11-27

- Added a responsive Security Center for CycloneDX import/comparison/advisory lookup, project security policy gates, evidence-based remediation plans, license evidence/reports, scheduled rescans and owner notifications.
- Added additive PostgreSQL migration `0002_security_center.py`, API schemas/routes, feature-focused backend/API tests, PostgreSQL migration/locking/recovery integration coverage and refreshed the SQL schema reference.
- Added Playwright full-stack Chromium coverage and GitHub Actions jobs for PostgreSQL, backend/frontend quality, audits and the browser journey, plus an authenticated policy-gate example.
- Fixed readable frontend display of structured API validation errors; corrected the exact `#ECEDEF` secondary-grey design token.
- Updated API, database, testing, architecture, user, security, privacy and project status documentation.

## 1.0.0 foundation - 2026-11-26

- Added FastAPI and PostgreSQL application foundation, authentication, project authorization, durable scan jobs and public intelligence adapters.
- Added five manifest parsers, CycloneDX JSON, deterministic risk scoring and JSON/PDF reporting.
- Added React dashboard, project/scan workflows, vulnerability view and local AI explanation path.
- Added Docker/native instructions, threat/privacy docs, educational fixtures and starter tests.
- Original foundation verification is archived in `FINAL_QA_REPORT.md`; current verification is recorded in `TEST_REPORT.md`.
