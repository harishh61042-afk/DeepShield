# Test report

**Date:** 2026-11-27 (Asia/Kolkata)

## Results

| Check | Result | Notes |
|---|---|---|
| Backend pytest on host | PASS — 50 passed, 1 skipped | PostgreSQL test is skipped when the dedicated test database URL is not set. |
| Backend pytest in rebuilt API container | PASS — 51 passed | Includes PostgreSQL concurrency/idempotency and worker lifecycle integration in depshield_test. |
| Ruff | PASS | All checks passed. |
| Frontend Vitest | PASS — 13 tests across 5 files | Includes API error formatting, theme/readiness helpers and Security Center UI state. |
| Frontend ESLint | PASS | No lint errors. |
| Frontend TypeScript/Vite production build | PASS | Docker build and local build both completed. |
| npm audit | PASS — 0 vulnerabilities | Locked frontend dependency tree. |
| pip-audit | PASS — no known vulnerabilities | Pinned backend requirements after advisory-driven updates. |
| API pip check | PASS | No broken Python requirements in the rebuilt API image. |
| Source archive | PASS — 134 files | ZIP CRC passed; .env, build output, dependencies and test artifacts are excluded. |
| Playwright Chromium journey | PASS | Browser signup/login, project, live scan, findings/explanation, exports, all security features, responsive widths, palette tokens, sign-out and sign-in. Expanded route result is recorded in UI_REDESIGN_REPORT.md. |
| Compose rebuild and restart | PASS | Rebuilt frontend, API and worker. Retained the existing postgres_data volume. |
| Live readiness | PASS | Frontend and API health/readiness returned HTTP 200; database available. |
| Warm-palette source scan | PASS | No blue, sky, indigo, cyan or teal theme tokens or previous blue palette literals in frontend source, metadata or public assets. |
| SQL schema export | PASS | database/schema.sql reflects additive Alembic migrations through head. |

## PostgreSQL test isolation

The integration test ran in the rebuilt API image with DEPSHIELD_TEST_DATABASE_URL pointing to the dedicated depshield_test database. Each run created a new schema, applied migrations and exercised the retained unique constraint, concurrent idempotent enqueue, concurrent queue claiming, retries and stale-lock recovery. It did not delete earlier test schemas or use/remove the application's depshield database or postgres_data volume.

The browser test created persistent local QA records in the application database: an account, project, scan, imported SBOM and related security-center data. They were left in place. No user database was dropped or cleaned.

## Run locally

From the repository root:

- Backend: enter backend and run .venv/Scripts/python.exe -m pytest -q.
- Ruff: run .venv/Scripts/ruff.exe check app tests alembic ../scripts/create_admin.py ../scripts/package_project.py from backend.
- Frontend: run npm.cmd test, npm.cmd run lint, npm.cmd run build and npm.cmd audit --audit-level=low from frontend.
- Browser journey: run npm.cmd run test:e2e from frontend with the app stack available at localhost:5173.
- Compose: run docker compose up -d --build from the repository root. Do not use down -v when retaining local PostgreSQL data.

The API readiness endpoints are /health/live and /health/ready.

## Not covered

No screenshot-diff, axe, keyboard-only, screen-reader, performance/load, penetration, parser-fuzz or backup/restore tests were run. The admin-only page was not exercised by the regular user browser journey. Optional SMTP and Ollama services were not started.

The regenerated output/DepShield_Complete_Project.zip contains 134 files. The packaging script passed the ZIP CRC and forbidden-path checks.

## Scan-job duplicate and lifecycle regression

The logged PostgreSQL duplicate inserts were caused by the previous integration test directly inserting a second ScanJob, catching IntegrityError, then rolling back. Both logged scan IDs were confirmed in the dedicated depshield_test database. Application enqueueing also lacked a shared idempotent boundary, although API uploads and scheduled scans each create their own scan and worker retries update an existing job.

PostgreSQL verification passed in a fresh schema within depshield_test: eight concurrent enqueue submissions for one scan created exactly one row and returned the same job ID; the existing scan_jobs_scan_id_key unique constraint was inspected and retained. Concurrent workers claimed one job only. Retry updated that row, stale-lock recovery reused it, max attempts produced matching failed scan/job states, and restart recovery kept a cancelled scan/job cancelled. Full container backend result: 51 passed. No records or schemas from prior test runs were deleted.
