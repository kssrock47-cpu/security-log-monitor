@echo off
cd /d %~dp0
if not exist .venv\Scripts\python.exe (
  echo First run: setting up. This takes a few minutes and needs internet once.
  python -m venv .venv
  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
.venv\Scripts\python.exe -m pip install -q -r requirements.txt
.venv\Scripts\python.exe server.py
pause
