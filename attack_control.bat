@echo off
title PassiveShield AI - Attack Simulation & Telemetry Control Center
color 0B
cls
echo ========================================================================
echo        PASSIVESHIELD AI — MANUAL ATTACK SIMULATION CONTROLLER
echo ========================================================================
echo.
echo Starting interactive attack simulation terminal...
echo Ensure the Next.js Frontend is open at: http://localhost:3000
echo.

python "%~dp0scripts\attack_simulator_cli.py"

pause
