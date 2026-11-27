# Final QA Report — DepShield

**Audit date:** 2026-11-27 (Asia/Kolkata)  
**Result:** The five security-center features are implemented in the existing application. The warm palette is applied across the UI. Backend/frontend checks and security dependency audits pass, the app stack was rebuilt, and the live app is healthy.

## Scope

Reviewed the existing FastAPI, SQLAlchemy, Alembic, worker and React application; added the security-center routes and UI; updated tests, CI, API/architecture/database/user documentation and the generated SQL schema. The existing .env was not opened or changed. Compose was restarted without removing its PostgreSQL volume.

## Feature verification

| Feature | Result | Verified behavior |
|---|---|---|
| SBOM import and comparison | PASS | CycloneDX 1.6 upload, validation, persistence, generated/imported snapshot comparison and vulnerability check against imported packages. |
| Security policies | PASS | Project policy save and evaluation; result status and summary are displayed. |
| Remediation planner | PASS | Advisory and affected-version evidence is used for remediation suggestions; downloadable PDF plan works. |
| License evidence | PASS | Package registry metadata refresh and evidence/report flow; downloadable PDF works. |
| Monitoring and alerts | PASS | Schedule create, pause/resume and delete; notification list and read-state action. Worker scan completions can publish notifications. |
| Existing functionality | PASS | Account registration/login/logout, project creation, real manifest scan, findings, explanation and existing scan PDF were exercised in the browser. |

The feature APIs enforce project ownership and use the existing authentication/session model. The new Alembic migration is additive. No database, authentication, or existing scan workflow was replaced.

## Automated and live checks

| Check | Result |
|---|---|
| Backend unit/API suite in local environment | PASS — 50 passed; the PostgreSQL-only integration test was skipped in this host run. |
| Backend suite in rebuilt API image with dedicated depshield_test DB | PASS — 51 passed, including the PostgreSQL concurrency and worker-lifecycle regression. |
| Ruff | PASS — all checks passed. |
| Frontend Vitest | PASS — 13 tests across 5 files. |
| Frontend ESLint | PASS. |
| TypeScript and Vite production build | PASS. |
| npm audit | PASS — 0 reported frontend vulnerabilities. |
| pip-audit | PASS — no known backend vulnerabilities in the pinned requirements. |
| Playwright browser journey | PASS — signup/sign-in, project and scan workflow, all five security features, downloads, palette tokens, responsive widths, navigation and sign-out/sign-in; route smoke coverage is in UI_REDESIGN_REPORT.md. |
| Frontend source palette scan | PASS — no blue/sky/indigo/cyan/teal theme tokens or previous blue palette literals found in source, index metadata or public assets. |
| Docker Compose rebuild/restart | PASS — frontend, API and worker images rebuilt; API and worker recreated; database volume retained. |
| Live frontend/API readiness | PASS — frontend, /health/live and /health/ready returned HTTP 200; readiness reports database available. |
| Python dependency consistency in API image | PASS — pip check reported no broken requirements. |

The browser-driven test creates an account, project, scan, imported BOM and a few feature records in the local PostgreSQL application database. These records were left in place. The PostgreSQL integration test uses the separate depshield_test database.

| Source archive | PASS — 134 files; ZIP integrity and forbidden-path checks passed. |

## Dependency upgrades

The audit found known advisories in the prior FastAPI/Starlette, python-multipart and pytest pins. backend/requirements.txt now pins FastAPI 0.165.0, Starlette 1.10.0, python-multipart 0.0.34 and pytest 9.2.0. The backend suite, PostgreSQL integration test, package consistency check and pip-audit all passed after rebuilding.

## Main files changed

- Backend models/migration/API/worker: backend/app/models/entities.py, backend/alembic/versions/0002_security_center.py, backend/app/api/features.py, backend/app/features/, backend/app/workers/scan_worker.py, backend/app/intelligence/osv.py and backend/requirements.txt.
- Backend regression tests: backend/tests/test_features.py, backend/tests/test_api.py and backend/tests/test_postgres_integration.py.
- Frontend feature and theme: frontend/src/features/SecurityCenter.tsx, frontend/src/App.tsx, frontend/src/api/client.ts, frontend/src/styles.css and frontend/src/scanReadiness.ts.
- Frontend tests: frontend/src/features/SecurityCenter.test.tsx, frontend/src/scanReadiness.test.ts and frontend/e2e/security-center.spec.ts.
- CI and policy integration: .github/workflows/ci.yml, ci/security_policy_gate.py and docs/examples/depshield-policy-gate.yml.
- Documentation and schema: README.md, docs/, database/schema.sql, CHANGELOG.md, THIRD_PARTY_NOTICES.md, this report, TEST_REPORT.md, DEVELOPMENT_STATUS.md and UI_REDESIGN_REPORT.md.

## Limits

This is a local verification, not production certification. The browser checks responsive layout and computed palette tokens but are not screenshot-diff or formal accessibility audits. The administrator-only browser page is not covered by the regular account journey. Ollama generation and SMTP delivery were not started. External vulnerability sources can be incomplete or slow; their status remains visible to users. Load testing, penetration testing, parser fuzzing and backup/restore drills remain outstanding.

See README.md and docs/ for run instructions, API routes, data model, feature usage, CI and operational details.

## Source archive

output/DepShield_Complete_Project.zip was regenerated after the documentation updates. The packaging script included 134 files and passed its ZIP integrity and forbidden-path checks; the .env file and generated build/dependency/test directories are excluded.

## Scan-job duplicate-log investigation and fix

### Root cause

The PostgreSQL log showed duplicate-key events at 2026-11-27 07:51:40.392 UTC for scan fe057fd5-15c0-4635-850c-19f5614efc33 and 2026-11-27 08:31:33.918 UTC for scan fc138c30-397c-4ca6-af86-94055dce5ec1. A read-only query confirmed both scans were in the dedicated depshield_test database. The prior PostgreSQL test deliberately added a second raw ScanJob for the same scan, expected IntegrityError, then rolled back. PostgreSQL correctly logged each rejected INSERT as ERROR even though the test passed. These two reported log entries came from that test, not from a live API or worker request.

That test exposed a latent application weakness: the upload API and scheduled-monitoring path each constructed ScanJob rows directly, without an idempotent enqueue operation. Automatic worker retries already update the claimed ScanJob row; they do not insert a new one. Replaying any enqueue operation for an existing scan could nevertheless issue a second INSERT and surface the unique-constraint error.

### Fix

- Added backend/app/scan_jobs.py with one enqueue operation shared by API scan creation, scheduled scans and cancellation repair. PostgreSQL and SQLite use INSERT ... ON CONFLICT (scan_id) DO NOTHING ... RETURNING, then select and lock the existing job. Duplicate calls return the same row and preserve the scan_jobs_scan_id_key constraint.
- Reworked cancellation, job claiming, completion and failure handling to lock job then scan consistently, reconcile terminal states, and prevent a late failure or stale worker from re-queueing a cancelled/completed scan. Retries continue to update the same job row and stop at max_attempts.
- Replaced the test that intentionally emitted an ERROR with repeated/concurrent enqueue assertions and an explicit PostgreSQL schema inspection proving the named unique constraint remains installed. No constraint was removed and no existing records were deleted.
- Each PostgreSQL regression run uses a new schema in the dedicated *_test database, so old test rows remain untouched and cannot affect the next queue-claim test.

### Verification evidence

- The real PostgreSQL concurrency regression passed: eight simultaneous enqueue attempts for one scan returned one job ID, exactly one insert reported success, and the database contained one job for that scan.
- Two concurrent workers claimed only one active job. The same job ID was reused for retry, recovered after a stale lock, and transitioned to failed at the retry limit. A stale processing job for a cancelled scan stayed cancelled and was not revived.
- PostgreSQL introspection confirmed scan_jobs_scan_id_key still uniquely constrains scan_id.
- Full backend suite inside the rebuilt API image, with the PostgreSQL test enabled: 51 passed. Ruff passed locally and in the rebuilt container. Frontend unit tests: 13 passed; lint and production build passed. Playwright passed 1/1 against the rebuilt API/worker, including a real scan and all feature flows (3.1 minutes; NVD enrichment is rate-limited).
- After that scan, the live application DB had zero queued/processing jobs and 14 scans in the valid partial/completed-to-completed job state. PostgreSQL logs still contain the two identified historical test-generated ERROR entries; no additional duplicate-key entries appeared during the corrected PostgreSQL test or browser scan.
