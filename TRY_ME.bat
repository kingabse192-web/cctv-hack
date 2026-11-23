@echo off
REM AB Search 😊 — safe demo launcher for Windows
REM Double-click this file, or run: TRY_ME.bat
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (
  python -c "import absearch" >nul 2>nul
  if errorlevel 1 python -m pip install -e . --quiet
  echo Starting SAFE demo dashboard...
  echo Open this address in your browser: http://127.0.0.1:8765/
  python -m absearch --demo --web
) else (
  py -3 -c "import absearch" >nul 2>nul
  if errorlevel 1 py -3 -m pip install -e . --quiet
  echo Starting SAFE demo dashboard...
  echo Open this address in your browser: http://127.0.0.1:8765/
  py -3 -m absearch --demo --web
)
pause
