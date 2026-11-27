$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'Python 3.12+ is required. Install Python and enable the py launcher.' }
& py -3.12 --version
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 was not found.' }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js 22+ is required.' }
$nodeVersion = [version](node -p "process.versions.node")
if (-not (($nodeVersion.Major -eq 22 -and $nodeVersion -ge [version]'22.13.0') -or $nodeVersion.Major -eq 24 -or $nodeVersion.Major -ge 26)) { throw 'Use Node.js 22.13+, Node.js 24, or Node.js 26+ with the pinned frontend tooling.' }
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) { throw 'npm.cmd was not found with Node.js.' }

if (-not (Test-Path (Join-Path $root '.env'))) {
  Copy-Item (Join-Path $root '.env.example') (Join-Path $root '.env')
  $secretBytes = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($secretBytes)
  $secret = [Convert]::ToBase64String($secretBytes)
  $dbBytes = New-Object byte[] 24
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dbBytes)
  $dbPassword = [Convert]::ToBase64String($dbBytes).Replace('+','x').Replace('/','y').TrimEnd('=')
  $envText = Get-Content -Raw -LiteralPath (Join-Path $root '.env')
  $envText = $envText.Replace('APP_SECRET=replace-this-with-at-least-32-random-bytes', "APP_SECRET=$secret")
  $envText = $envText.Replace('POSTGRES_PASSWORD=change-me', "POSTGRES_PASSWORD=$dbPassword")
  $envText = [regex]::Replace($envText, 'DATABASE_URL=postgresql\+psycopg://depshield:[^@]+@localhost', "DATABASE_URL=postgresql+psycopg://depshield:$dbPassword@localhost")
  [IO.File]::WriteAllText((Join-Path $root '.env'), $envText, [Text.UTF8Encoding]::new($false))
  Write-Host 'Created .env with local random secrets. It is excluded from version control.'
} else { Write-Host 'Keeping existing .env.' }

if (-not (Test-Path (Join-Path $root 'backend/.venv'))) { & py -3.12 -m venv (Join-Path $root 'backend/.venv') }
$venvPython = Join-Path $root 'backend/.venv/Scripts/python.exe'
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed.' }
& $venvPython -m pip install -r (Join-Path $root 'backend/requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
Push-Location (Join-Path $root 'frontend')
try { & npm.cmd ci; if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' } } finally { Pop-Location }
Write-Host 'Dependencies are installed. See README.md for database migration and run commands.'
