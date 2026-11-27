# Testing guide

## Backend unit and API tests

From `backend/`:

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check app tests alembic ..\scripts\create_admin.py ..\scripts\package_project.py ..\ci\security_policy_gate.py
```

Feature tests cover CycloneDX structure and diffing, policy decisions, license evidence/policy, upgrade evidence, monitoring schedule queueing, idempotent alerts, API authorization, and generated reports. API/worker unit fixtures use isolated SQLite databases.

## PostgreSQL integration

The integration test verifies Alembic migrations, PostgreSQL schema/constraints, concurrent `FOR UPDATE SKIP LOCKED` job claims, stale-lock recovery and the one-job-per-scan constraint. It refuses to run unless `DEPSHIELD_TEST_DATABASE_URL` points to a PostgreSQL database whose name ends in `_test`.

```powershell
$env:DEPSHIELD_TEST_DATABASE_URL = 'postgresql+psycopg://user:password@localhost:5432/depshield_test'
.venv\Scripts\python.exe -m pytest -q tests/test_postgres_integration.py
```

The test creates a new, uniquely named schema inside the dedicated `*_test` database for each run, applies Alembic migrations there, and leaves earlier schemas and rows untouched. Do not point it at a user or production database.

## Frontend checks

From `frontend/`:

```powershell
npm.cmd test
npm.cmd run lint
npm.cmd run build
npm.cmd audit --audit-level=low
```

Vitest covers frontend helpers and Security Center interaction states. ESLint and TypeScript/Vite validate the client and production bundle.

## Full-stack browser journey

Playwright Chromium exercises registration, project creation, a real worker scan, finding explanation and report download, each Security Center tab, SBOM import/compare/lookup, policy evaluation, remediation and license PDFs, monitoring controls, notification state, mobile/tablet/desktop overflow and return login.

```powershell
cd frontend
npx.cmd playwright install chromium
npm.cmd run test:e2e
```

The target application must be available at `http://localhost:5173` with API and worker at the configured Compose endpoints. The test creates a uniquely named account, project and scan; it does not clean up those rows. Run it only against a disposable/test environment if persistent test data is undesirable. CI uses a fresh Compose project and isolated database volume.

## Continuous integration

`.github/workflows/ci.yml` runs Python tests/Ruff/pip-audit, frontend tests/lint/build/npm audit, a PostgreSQL service test, then a fresh Compose application and Playwright journey. The workflow uses throwaway credentials and its cleanup is restricted to the isolated CI runner.

The structural SBOM validator is not a full official JSON Schema validator. `axe`, screen-reader testing, parser fuzzing, penetration testing, load testing, and backup/restore drills remain separate work. See `TEST_REPORT.md` for this run's recorded results and limitations.
