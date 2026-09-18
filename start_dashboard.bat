@echo off
title NEXUS Tactical Command Dashboard
cd /d "%~dp0"

echo =======================================================
echo   NEXUS TACTICAL COMMAND CENTER LAUNCHER
echo =======================================================
echo.

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at venv\Scripts\python.exe
    echo Please create the virtual environment first.
    pause
    exit /b 1
)

echo [1/2] Verifying core configuration and models...
if not exist "genomes\champion.pkl" (
    echo [WARNING] champion.pkl not found! Running evolve.py to build champion...
    .\venv\Scripts\python.exe scripts\evolve.py --generations 10
)

echo [2/2] Launching Tactical Dashboard on http://localhost:8000 ...
start http://localhost:8000

.\venv\Scripts\python.exe scripts\dashboard.py --port 8000

pause
