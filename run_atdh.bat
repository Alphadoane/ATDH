@echo off
echo ===================================================
echo   ADAPTIVE THREAT DETECTION PLATFORM (ATDH)
echo ===================================================
echo [STARTING] Launching all components...

:: Start Backend
echo [1/3] Starting Backend API...
start "ATDH_Backend" cmd /c "cd /d "%~dp0backend" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

:: Start Frontend
echo [2/3] Starting Frontend Dashboard...
start "ATDH_Frontend" cmd /c "cd /d "%~dp0frontend" && npm run dev"

:: Wait for Backend to warm up
echo [WAIT] Waiting 5 seconds for services to initialize...
timeout /t 5 /nobreak >nul

:: Start Collector (Elevated)
echo [3/3] Requesting elevation for Live Collector...
start "ATDH_Collector_Launcher" cmd /c "cd /d "%~dp0" && run_collector_admin.bat"

echo ===================================================
echo [SUCCESS] All windows launched.
echo Dashboard: http://localhost:5173
echo Backend:   http://localhost:8000
echo ===================================================
pause
