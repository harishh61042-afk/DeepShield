# DepShield development status

Updated: 2026-11-27

## Current status

The complete local DepShield stack is running at http://localhost:5173. Five security-center capabilities were added to the existing application, and its shared warm cream, butter-yellow, white, grey and charcoal design system remains in place across the current routes. Application database storage was retained during the rebuild.

## Implemented security-center features

- CycloneDX 1.6 SBOM import, validation, snapshot comparison and vulnerability checks.
- Project security policies with saved rules and scan evaluation results.
- Evidence-based remediation guidance using advisory and affected-version information, with downloadable reports.
- License metadata and evidence tracking, refreshable registry evidence and downloadable license reports.
- Project scan schedules with pause/resume, deduplicated notifications, preferences and read state.

The new page is /app/security. The additions are in the existing React/FastAPI/SQLAlchemy/Alembic architecture. The migration is additive; existing authentication, project authorization and scan behavior are retained. See README.md, docs/API_DOCUMENTATION.md and docs/USER_GUIDE.md for usage and endpoint details.

## Verification completed

- Backend in the rebuilt API image: **51 passed**, including the PostgreSQL idempotent-enqueue concurrency and worker lifecycle regression in the separate depshield_test database.
- Local backend suite: **50 passed, 1 PostgreSQL integration test skipped** because the host process did not use the dedicated Docker test database. Ruff passed.
- Frontend: **13 tests across 5 files passed**; ESLint, TypeScript checking and the Vite production build passed.
- Dependency audits: **pip-audit found no known backend vulnerabilities**; npm audit found **0 frontend vulnerabilities**.
- Docker: Compose rebuilt the frontend, API and worker and restarted API/worker. The existing postgres_data volume was retained. Database and API report healthy.
- Live checks: http://localhost:5173, /health/live and /health/ready return HTTP 200; readiness reports the database available.
- Source archive: output/DepShield_Complete_Project.zip contains 134 files; ZIP integrity and forbidden-path checks passed.
- Browser regression: Playwright drives account registration/login, project creation, a real scan and finding explanation, PDF download, SBOM import/compare/check, policy evaluation, remediation, license evidence, monitoring schedule controls, notifications, computed palette tokens, responsive widths, navigation and sign-out/login. It checks public and standard-user routes. See UI_REDESIGN_REPORT.md for the final run result and scope.
- Scan queue: PostgreSQL-backed concurrent enqueue/reuse, unique-constraint retention, one-worker claim, retry, max-attempt failure, stale-lock restart recovery and cancelled-scan recovery tests pass. See FINAL_QA_REPORT.md for the duplicate-log root cause.

The test account, project, scan and imported SBOM created by the browser test remain in the local application database as test records. No user data or database volume was deleted.

## Remaining limits

- Browser checks verify route rendering, feature behavior, palette token values and horizontal overflow at desktop, tablet and phone widths. They are not a screenshot comparison, axe audit, keyboard-only review or screen-reader test.
- The non-admin browser journey does not exercise the administrator-only page. Admin and ownership behavior remains covered by backend tests.
- OSV, CISA KEV and NVD are live external sources. NVD enrichment is rate-limited and can make a full real scan take several minutes; an unavailable or partial source remains reported by the application.
- Optional Ollama and SMTP delivery were not started. The deterministic explanation fallback was exercised by the browser workflow; no email was sent.
- No penetration test, performance/load test, parser fuzz campaign, production secret review or backup/restore drill was performed. The local Compose run is not a production certification.

See FINAL_QA_REPORT.md, TEST_REPORT.md and UI_REDESIGN_REPORT.md for verification details.
