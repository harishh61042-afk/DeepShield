# DepShield UI redesign report

**Date:** 2026-11-27

## Design system

The existing frontend now uses the reference's warm SaaS palette across its shared components and page surfaces:

- Main background: #F7F6F1
- Card/surface: #FFFFFF
- Cream: #FBF4E5
- Butter-yellow primary: #F5D65E
- Secondary grey: #A7ADB8
- Soft grey: #ECEDEF
- Main text: #202127

The shared tokens live in frontend/src/styles.css. Buttons, navigation selection, focus states and important highlights use the butter-yellow token. Cards use white surfaces, soft-grey borders and subtle shadows. Existing meaningful severity/status colors continue to convey risk state; they are not a blue interface theme. The optional dark theme retains the yellow highlight.

## Pages covered

The global styles apply to the landing and information pages; registration, login and password recovery; dashboard; projects and project detail; scan detail/results; vulnerabilities; settings/profile and admin layout; and the new Security Center at /app/security.

The Security Center has six sections: SBOMs, security policies, remediation, license evidence, monitoring schedules and alerts. Existing upload, history, findings and report actions remain inside the existing project and scan pages.

## Responsive and browser checks

Playwright exercises a full browser workflow: account registration/login, project creation, requirements scan, finding explanation, PDF exports, all six Security Center tabs and their API actions, schedule pause and deletion, alert read state, mobile navigation and re-login. It checks the exact computed light-theme token values and verifies no horizontal document overflow at 1280, 768 and 390 pixel widths.

The browser route sweep visits the public information/authentication routes and the standard-user dashboard, projects, project detail, scan detail, vulnerabilities and settings. Admin-only behavior is covered by backend tests, not by this regular-user browser test.

## Files changed

- frontend/src/styles.css — shared color tokens, component styling, focus/hover/disabled states, dark-theme accent and responsive layouts.
- frontend/src/App.tsx — Security Center route, workspace navigation and shared page surfaces.
- frontend/src/features/SecurityCenter.tsx — responsive security feature screens and API-backed interactions.
- frontend/src/api/client.ts and frontend/src/scanReadiness.ts — API error display and scan evidence readiness.
- frontend/index.html and frontend/public/shield.svg — browser theme color and warm brand mark.
- frontend/src/features/SecurityCenter.test.tsx, frontend/src/scanReadiness.test.ts and frontend/e2e/security-center.spec.ts — UI unit and browser coverage.
- frontend/playwright.config.ts and frontend/.dockerignore — browser-test configuration and generated-artifact exclusions.

## Validation

- Frontend unit tests: 13 passed across 5 files.
- ESLint, TypeScript/Vite production build: passed.
- npm audit: 0 reported vulnerabilities.
- Frontend source scan across src, index metadata and public assets: no blue, sky, indigo, cyan or teal theme tokens and no previous blue palette literals.
- Docker Compose rebuilt frontend, API and worker, then restarted the services without deleting the PostgreSQL volume.
- Live frontend at http://localhost:5173 returned HTTP 200. API /health/live and /health/ready returned HTTP 200 and readiness reported the database available.
- Browser E2E verified the real app flow and exact palette values; test records remain in the local app database.

The browser checks do not replace screenshot comparison or a formal accessibility review. No axe, keyboard-only or screen-reader audit was run.
