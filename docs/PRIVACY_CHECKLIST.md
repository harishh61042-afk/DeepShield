# Privacy implementation checklist

Implementation-based draft; obtain legal review before public use.

- **Collected:** email, display name, password hash, role/status, sessions/reset token digests, project names/descriptions, parsed dependency metadata, scans, findings and minimal audit records.
- **Uploaded files:** parsed in bounded memory and discarded; stored metadata includes a sanitized filename, size and SHA-256 digest. Complete source archives are not retained.
- **External requests:** OSV receives package ecosystem/name/version candidates; NVD receives CVE identifiers for enrichment; CISA KEV catalog is fetched by the worker. Optional license refresh sends package ecosystem/name/version to fixed npm/PyPI/crates.io registries. Availability and public service terms apply.
- **Local AI:** when enabled, structured vulnerability details and package metadata are sent to configured local Ollama. No OpenAI/Gemini/Claude API integration exists.
- **Cookies:** essential HttpOnly session cookie and CSRF cookie. No analytics/advertising cookies. Theme and cookie-notice dismissal use browser localStorage.
- **Notifications:** project owners can receive persisted in-app security alerts. Email is off by default, requires operator SMTP configuration and explicit user opt-in, and contains advisory/package details; treat the configured mail system as a data processor.
- **Retention:** terminal scan snapshots and associated inventory/findings/jobs are deleted by the worker once per day when older than `DATA_RETENTION_DAYS` (default 365). Projects, accounts, vulnerability records and audit events follow separate deletion/retention behavior; audit rows are not automatically pruned. Backups may retain deleted data until operator-configured expiry.
- **Deletion:** account deletion endpoint requires current password and confirmation, removes owned project scan data and revokes session by cascade; global vulnerability records and audit rows may remain with actor reference nulled.
- **Age:** product is intended for adults 18+. Registration asks a minimal attestation; age is not independently verified.
- **Operator contact:** `SUPPORT_EMAIL` is configurable. No business address/phone/legal entity is invented.
- **Not claimed:** GDPR/CCPA compliance, certification, penetration-test status or absolute security.
