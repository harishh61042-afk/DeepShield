# Security implementation notes

DepShield is a defensive analysis tool. It does not execute uploaded projects or construct exploits.

## Implemented

- Argon2id one-way password hashing. Passwords, session values and password reset tokens are not written to audit logs.
- High-entropy opaque sessions; only a keyed HMAC digest is stored. Sessions expire, can be revoked, and are checked against current account status.
- HttpOnly, SameSite=Strict session cookie; CSRF cookie/header validation and configured-origin check on unsafe methods. Production requires secure cookies and HTTPS frontend configuration.
- Registration, login and reset request rate limits per client address in the API process. Login and reset messages avoid confirming whether an email exists.
- Backend role and object authorization for projects and their scans/findings/reports. Auditor membership is read-only; new registrations are Developers. Public API cannot assign Administrator.
- Pydantic server-side validation, parameterized SQL through SQLAlchemy, object-level access before report or finding retrieval.
- Bounded upload size, archive entry and expansion limits, component cap, no filesystem extraction, path and symlink checks, hardened XML parsing, no shell invocation.
- External request timeouts, bounded retry behavior, OSV cache expiry, NVD request spacing, and degraded scan states.
- Security Center authorization uses project ownership/roles; imported BOMs are size/component bounded and checked for supported CycloneDX shape/version. SBOM lookups and package license refreshes use fixed public HTTPS registry destinations, disable redirects, and never submit uploaded source files.
- License registry package names and versions are validated before constructing requests. Unknown license values remain unknown; generated reports escape content and include a human-review disclaimer.
- Monitoring alerts are stored with unique per-user event keys. Email delivery is disabled until SMTP is configured and the user opts in; messages are claimed before sending to avoid duplicate outbox attempts.
- PostgreSQL migration/constraint/queue integration coverage, a real browser feature journey, responsive viewport checks, and CI dependency audit workflow are included.
- Security headers; CSP in Nginx; CORS restricted to configured origins.
- No third-party analytics SDK, external AI API, package installation or uploaded source retention.

## Required before public deployment

- Run dependency lockfile audits and update vulnerable/outdated libraries based on current advisories.
- Move auth throttling to a shared store and configure trusted proxy handling.
- Review CSRF/session behavior behind the chosen HTTPS proxy and domain; enable secure cookies.
- Add email verification, abuse monitoring, stronger lockout policy and operational session revocation UI.
- Replace bounded structural SBOM validation with automated official CycloneDX JSON Schema validation for every generated and imported BOM; run parser fuzzing and expand ZIP/XML security tests. A representative schema check was run during development, but it is not wired into runtime validation.
- Run full authorization, CSRF, SSRF, XSS, rate-limit and privacy tests against PostgreSQL.
- Set log retention, backups, restore drills, deletion/backup expiry, alerting and incident response procedures.
- Review production CSP and CORS against the actual domain; configure secrets through an operator-controlled secret store.

## Known limits

The auth throttle is in-memory and resets with process restarts. NVD and KEV memory caches are per worker. Playwright tests do not replace axe/screen-reader checks, penetration testing or load testing. A failed SMTP outbox item requires operator review; sending state prevents automatic duplicate retries. This document is not a claim of certification or complete security.
