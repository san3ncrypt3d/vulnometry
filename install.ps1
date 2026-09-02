# Vulnometry installer for Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) {
    Write-Error "Python 3.10+ not found. Install it from https://www.python.org/downloads/"
    exit 1
}

& $python.Source -m venv .venv
& .\.venv\Scripts\Activate.ps1

python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[dev]"

Write-Host "`nRunning the test suite (offline, synthetic data)..."
python -m pytest tests -q

Write-Host @"

Installed.

  .\.venv\Scripts\Activate.ps1   activate in every new terminal
  vulnometry doctor                   check the live feeds
  vulnometry inventory init           describe what you run
  vulnometry compare CVE-2021-44228   see one CVE land differently across your estate

Read QUICKSTART.md for the rest.
"@
