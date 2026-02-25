@echo off
cd /d "d:\cyberSec\backend"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
