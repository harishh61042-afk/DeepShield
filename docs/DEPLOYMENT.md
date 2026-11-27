# Deployment

## Docker Compose local mode

`docker compose up --build -d` builds the frontend/API image, starts PostgreSQL, runs Alembic migration as API startup, and starts the worker. PostgreSQL is only exposed on the private Compose network; API and web ports bind to loopback. Compose profiles `mail` and `ai` add Mailpit or Ollama.

Stop with `docker compose down`. Keep the named PostgreSQL volume for local persistence. `docker compose down -v` deletes local database/model volumes and is destructive.

## Native Windows mode

Follow the root README. Run PostgreSQL as an installed service; apply the Alembic migration from `backend/`; run FastAPI, the worker and Vite in separate terminals. The Vite development proxy routes API requests to localhost:8000.

## Linux/macOS

Install Python 3.12+, PostgreSQL 16+, and a Node release accepted by the pinned tooling (22.13+, 24, or 26+). Run `sh ./scripts/setup.sh`, create the PostgreSQL role/database, then follow the Linux/macOS native commands in the root README to migrate and start the API, worker and Vite in separate terminals.

## Production checklist

- Configure a real domain and HTTPS termination; set `APP_ENV=production`, `COOKIE_SECURE=true`, a unique 32+ character `APP_SECRET`, non-default PostgreSQL credentials and an exact allowed-origin list.
- Keep PostgreSQL private, enable encrypted backups, run restore drills, monitor migrations and worker failures.
- Configure SMTP for password reset and operator contact information; do not invent contact details.
- Configure per-service timeouts/rate limits, queue concurrency, retention and log policy.
- Review production CORS, CSP, reverse proxy trusted headers, session cookie domain, host allowlist and password/reset throttling.
- Complete legal/privacy review and release dependency/security audits. Custom domain/hosting is not configured or purchased by this project.

This codebase has not been deployed or tested in Docker in the current environment.
