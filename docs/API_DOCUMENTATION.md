# API documentation

FastAPI publishes the interactive reference at `/docs` and the OpenAPI document at `/openapi.json`. Routes below are relative to `/api/v1`. JSON is used unless a route accepts a multipart upload or returns a file.

## Authentication and CSRF

Call `GET /auth/csrf` first. It sets the CSRF cookie and returns a token. Send the token in `X-CSRF-Token` for every POST, PUT, PATCH, or DELETE that changes state. Login sets a separate HttpOnly session cookie. Never put session credentials in local storage or URLs.

## Existing route groups

| Group | Routes |
|---|---|
| Auth | `POST /auth/register`, `/auth/login`, `/auth/logout`, `/auth/password`, `/auth/password-reset`, `/auth/password-reset/complete`; `GET /auth/me`, `/auth/csrf`; `DELETE /auth/account`; `POST /auth/sessions/revoke-others` |
| Projects | `GET/POST /projects`, `GET/PATCH/DELETE /projects/{id}`, `GET/POST /projects/{id}/members`, `DELETE /projects/{id}/members/{user_id}` |
| Scans | `POST /projects/{id}/scans`, `GET /projects/{id}/scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/components`, `/findings`, `/sbom`, `/report.json`, `/report.pdf`, `/compare/{other_id}` |
| Vulnerabilities | `GET /vulnerabilities`, `POST /findings/{id}/explanation` |
| Dashboard/profile | `GET /dashboard`, `GET/PATCH /profile` |
| Administrator | `GET /admin/overview`, `/users`, `/audit`, `/jobs`, `/health`; `PATCH /admin/users/{id}/role`, `/status` |
| Health | `GET /health/live`, `/health/ready` |

## Security Center routes

| Capability | Routes |
|---|---|
| SBOM import and inventory | `GET /projects/{project_id}/sboms`, `POST /projects/{project_id}/sboms/import` (multipart CycloneDX JSON, max 5 MiB) |
| SBOM comparison and advisory check | `POST /projects/{project_id}/sboms/compare`, `POST /projects/{project_id}/sboms/{sbom_id}/vulnerabilities` |
| Policy | `GET/PUT /projects/{project_id}/security-policy`, `POST /scans/{scan_id}/policy/evaluate`, `GET /scans/{scan_id}/policy-result` |
| Remediation | `GET /scans/{scan_id}/remediation` (optional `ai_explanations=true`), `GET /scans/{scan_id}/remediation.pdf` |
| License inventory | `GET /projects/{project_id}/licenses`, `POST /projects/{project_id}/licenses/refresh`, `GET /projects/{project_id}/licenses/report.json`, `/report.pdf` |
| Monitoring | `GET/PUT/DELETE /projects/{project_id}/monitoring/schedule` |
| Notifications | `GET /notifications`, `POST /notifications/{id}/read`, `POST /notifications/read-all`, `GET/PUT /notification-preferences` |

Project writes require project-owner or administrator rights; project readers can inspect permitted evidence. Notification routes are scoped to the authenticated user. A policy result treats partial scans and unavailable required evidence as warnings/failures according to policy; it never silently reports a clean result. Imported SBOM validation checks supported CycloneDX version, shape, bounds and component identities; it is structural validation rather than a claim of full official JSON Schema validation.

## Shared response behavior

Project, scan, and finding IDs are UUIDs. Inaccessible project objects return 404. List endpoints use `{ "items": [...], "limit": n, "offset": n }`. Scan status is `queued`, `processing`, `completed`, `partial`, `failed`, or `cancelled`. A partial scan must not be presented as a clean result. Download routes authorize against the owning project before rendering.
