#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

command -v python3 >/dev/null 2>&1 || { echo 'Python 3.12+ is required.' >&2; exit 1; }
python3 - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit("Python 3.12+ is required.")
PY
command -v node >/dev/null 2>&1 || { echo 'Node.js 22.13+ or 24+ is required.' >&2; exit 1; }
node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit((major === 22 && minor >= 13) || major === 24 || major >= 26 ? 0 : 1)' || { echo 'Use Node.js 22.13+, Node.js 24, or Node.js 26+ with the pinned frontend tooling.' >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo 'npm is required.' >&2; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
  python3 - <<'PY'
from pathlib import Path
import secrets

path = Path(".env")
db_password = secrets.token_hex(24)
text = path.read_text(encoding="utf-8")
text = text.replace("APP_SECRET=replace-this-with-at-least-32-random-bytes", f"APP_SECRET={secrets.token_hex(32)}")
text = text.replace("POSTGRES_PASSWORD=change-me", f"POSTGRES_PASSWORD={db_password}")
text = text.replace("depshield:change-me@localhost", f"depshield:{db_password}@localhost")
path.write_text(text, encoding="utf-8")
PY
  echo 'Created .env with random local secrets. It is excluded from version control.'
else
  echo 'Keeping existing .env.'
fi

if [ ! -d backend/.venv ]; then python3 -m venv backend/.venv; fi
backend/.venv/bin/python -m pip install --upgrade pip
backend/.venv/bin/python -m pip install -r backend/requirements.txt
(cd frontend && npm ci)
echo 'Dependencies are installed. Configure PostgreSQL and follow README.md to migrate and start the services.'
