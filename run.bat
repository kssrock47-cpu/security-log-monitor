@echo off
setlocal
cd /d "%~dp0"
title Security Log Monitor
if exist ".venv\Scripts\python.exe" goto update

echo.
echo  First run: setting things up. This takes a few minutes and needs internet once.
echo.
set "PY="
where py >nul 2>nul && py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=python"
if not defined PY goto nopython

%PY% -m venv .venv
if errorlevel 1 goto setupfail
".venv\Scripts\python.exe" -m pip install -q --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto setupfail
goto start

:update
rem Picks up new packages after an update. Works offline when nothing is missing.
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt
if errorlevel 1 echo  Could not check for new packages (no internet?). Starting anyway.

:start
".venv\Scripts\python.exe" server.py
echo.
echo  The monitor has stopped. Press any key to close this window.
pause >nul
exit /b 0

:nopython
echo  Python 3.10 or newer is needed, and it was not found on this PC.
echo.
echo    1. Download Python from https://www.python.org/downloads/
echo    2. During setup, tick "Add python.exe to PATH".
echo    3. Double-click run.bat again.
echo.
pause
exit /b 1

:setupfail
echo.
echo  Setup did not finish. Check the internet connection and try again.
echo  If it keeps failing, delete the .venv folder in this project and run this file again.
echo.
pause
exit /b 1
