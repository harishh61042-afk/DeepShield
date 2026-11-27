$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root 'backend/.venv/Scripts/python.exe'
if (-not (Test-Path $python)) { throw 'Run scripts/setup.ps1 first to install backend dependencies.' }
Push-Location (Join-Path $root 'backend')
try {
  & $python -m pytest -q
  if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }
  & $python -m ruff check app tests alembic
  if ($LASTEXITCODE -ne 0) { throw 'Ruff reported issues.' }
} finally { Pop-Location }
Push-Location (Join-Path $root 'frontend')
try {
  & npm.cmd test
  if ($LASTEXITCODE -ne 0) { throw 'Frontend tests failed.' }
  & npm.cmd run lint
  if ($LASTEXITCODE -ne 0) { throw 'Frontend lint failed.' }
  & npm.cmd run build
  if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
} finally { Pop-Location }
