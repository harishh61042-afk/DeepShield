$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Test-Path (Join-Path $root '.env'))) { throw 'Copy .env.example to .env or run scripts/setup.ps1 first.' }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker Desktop is not available. Use the native VS Code commands in README.md.' }
docker compose up --build
