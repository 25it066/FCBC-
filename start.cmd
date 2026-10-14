@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe py -3.12 -m venv .venv
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
if errorlevel 1 goto fail
cd backend
..\.venv\Scripts\python.exe -m alembic upgrade head
if errorlevel 1 goto fail
..\.venv\Scripts\python.exe -m app.setup_account
if errorlevel 1 goto fail
echo Open http://127.0.0.1:8000 in your browser. Press Ctrl+C to stop.
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
pause
exit /b
:fail
echo Setup failed. Read the error above and README.md. Python 3.12 is required by this launcher.
pause
