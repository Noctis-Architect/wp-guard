# WP Guard Windows EXE build script
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python not found. Install Python 3.10+ from https://www.python.org/downloads/"
}

$venv = Join-Path $PSScriptRoot ".venv-build"
if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
    Write-Host "Creating build virtual environment..."
    py -3 -m venv $venv
}

& (Join-Path $venv "Scripts\Activate.ps1")

python -m pip install --upgrade pip
pip install -r "..\..\requirements.txt"
pip install -r "requirements-build.txt"

pyinstaller "wp_guard.spec" --noconfirm --clean

Write-Host ""
Write-Host "Build complete: dist\WPGuard\WPGuard.exe"
Write-Host "Zip the dist\WPGuard folder to distribute."
