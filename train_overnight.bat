@echo off
title NEXUS Production Training Engine (16-Core Ray Distributed)
cd /d "%~dp0"

echo =================================================================
echo   NEXUS PRODUCTION TRAINING ENGINE: ACTIVATING TONIGHT
echo =================================================================
echo.

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at venv\Scripts\python.exe
    pause
    exit /b 1
)

echo Select Training Intensity:
echo  [1] High-Intensity Run (30 Generations, ~2-3 Minutes)
echo  [2] Deep Overnight Training Run (100 Generations, Multi-Species)
echo.
set /p choice="Enter choice [1 or 2] (Default: 1): "

if "%choice%"=="2" (
    echo.
    echo [*] Starting Deep Overnight Training Run (100 Generations on 16 CPUs)...
    .\venv\Scripts\python.exe scripts\train_for_real.py --cpus 16 --overnight --live-sniff 150
) else (
    echo.
    echo [*] Starting High-Intensity Training Run (30 Generations on 16 CPUs)...
    .\venv\Scripts\python.exe scripts\train_for_real.py --cpus 16 --generations 30 --live-sniff 150
)

echo.
echo =================================================================
echo   Training Completed! Press any key to exit...
echo =================================================================
pause >nul
