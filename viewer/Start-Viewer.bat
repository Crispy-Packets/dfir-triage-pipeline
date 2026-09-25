@echo off
REM One-click launcher for the DFIR Triage Viewer.
REM   Double-click: opens the viewer on the runs in samples\.
REM   Drag a run.json onto this file: opens the viewer on that run.
REM First use only: builds the viewer's own environment (.venv) and installs
REM Streamlit -- needs internet, roughly 100 MB. Later uses start in seconds.
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" goto run

echo First run: building the viewer environment (needs internet, ~100 MB)...
REM Python 3.11 on purpose: Streamlit's dependencies (pyarrow) may have no
REM build yet for the newest Python. Fall back to the default only if 3.11
REM is not installed.
py -3.11 -m venv .venv 2>nul || python -m venv .venv
if not exist ".venv\Scripts\python.exe" (
    echo Could not create the environment. Install Python 3.11 from python.org and try again.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Installing the viewer's requirements failed. Check the internet connection and try again.
    pause
    exit /b 1
)

:run
echo Starting the viewer -- your browser opens at http://localhost:8501
echo Close this window to stop the viewer.
if "%~1"=="" (
    ".venv\Scripts\python.exe" -m streamlit run app.py
) else (
    ".venv\Scripts\python.exe" -m streamlit run app.py -- --run "%~1"
)
pause
