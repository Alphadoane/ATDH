@echo off
:: Check for administrative privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] Already running as Administrator.
    goto :run
) else (
    echo [INFO] Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
    exit /b
)

:run
echo [INFO] Moving to backend directory...
cd /d "d:\cyberSec\backend"
echo [INFO] Starting Live Log Collector...
python -m app.engine.live_collector
pause
