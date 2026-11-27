#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root/backend"
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check app tests alembic
cd "$root/frontend"
npm test
npm run lint
npm run build
