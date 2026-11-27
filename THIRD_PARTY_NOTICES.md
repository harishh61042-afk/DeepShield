# Third-party notices

The application uses the following open-source packages. Confirm license metadata from the exact installed lockfile before redistribution; no third-party package grants a security certification.

| Package or service | Purpose | License / terms reference |
|---|---|---|
| React, React DOM, React Router | Browser application and routing | MIT |
| Vite, TypeScript | Frontend build and type checking | MIT |
| TanStack Query | API request state | MIT |
| Recharts | Dashboard chart rendering | MIT |
| Lucide React | Icons | ISC |
| Tailwind CSS | Utility CSS tooling | MIT |
| FastAPI, Starlette, Pydantic | API and validation | MIT |
| SQLAlchemy, Alembic | Database access and migrations | MIT |
| psycopg | PostgreSQL driver | LGPL-3.0-or-later / chosen wheel terms; verify exact distribution |
| pwdlib and Argon2 backend | Argon2id password hashing | MIT / Argon2 implementation license; verify exact backend |
| HTTPX | Public service HTTP client | BSD-3-Clause |
| defusedxml | Hardened XML parser | PSF-2.0 |
| ReportLab | PDF output | BSD-3-Clause |
| Playwright Test | Development-only browser E2E verification | Apache-2.0 |
| PostgreSQL | Primary database | PostgreSQL License |
| Ollama | Optional local model runtime | MIT; model weights have separate terms |
| OSV.dev, NVD, CISA KEV | Public vulnerability information | Service/data terms apply; review their current terms and rate limits |
| Docker/Compose | Optional local container runtime | Docker Desktop terms apply |

See `docs/THIRD_PARTY_AUDIT.md` for network and data-flow notes. Fonts use system stacks; no remote font service or analytics SDK is configured.
