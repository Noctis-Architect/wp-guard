@echo off
setlocal EnableExtensions

cd /d "%~dp0"

where py >nul 2>&1
if errorlevel 1 (
    echo Python not found. Install Python 3.10+ from https://www.python.org/downloads/
    exit /b 1
)

if not exist ".venv-build\Scripts\python.exe" (
    echo Creating build virtual environment...
    py -3 -m venv .venv-build
)

call ".venv-build\Scripts\activate.bat"

python -m pip install --upgrade pip
pip install -r "..\..\requirements.txt"
pip install -r "requirements-build.txt"

pyinstaller "wp_guard.spec" --noconfirm --clean

if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo.
echo Build complete: dist\WPGuard\WPGuard.exe
echo Zip the dist\WPGuard folder to distribute.
endlocal
