#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
if [ ! -f .env ]; then echo "Copy .env.example to .env first." >&2; exit 1; fi
docker compose up --build
