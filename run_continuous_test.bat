@echo off
title NEXUS - Continuous Autonomous Defense Test Runner
echo ================================================================
echo           NEXUS CONTINUOUS AUTONOMOUS DEFENSE TEST RUNNER       
echo ================================================================
echo Starting 3-minute continuous traffic & threat injection test...
echo Open http://localhost:8000 and switch to DECK 3 to watch live!
echo ================================================================
.\venv\Scripts\python.exe scripts/run_continuous_test.py --duration 180 --pps 6.0
pause
