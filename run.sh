#!/usr/bin/env bash
# Security Log Monitor for Mac and Linux. Run with:  bash run.sh
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  PY=""
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
      PY="$c"; break
    fi
  done
  if [ -z "$PY" ]; then
    echo "Python 3.10 or newer is needed and was not found."
    echo "  Mac: install it from https://www.python.org/downloads/"
    echo "  Ubuntu or Debian: sudo apt install python3 python3-venv"
    echo "Then run: bash run.sh"
    exit 1
  fi
  echo "First run: setting things up. This takes a few minutes and needs internet once."
  if ! "$PY" -m venv .venv; then
    echo "Could not create the Python environment. On Ubuntu or Debian: sudo apt install python3-venv"
    exit 1
  fi
  .venv/bin/python -m pip install -q --upgrade pip
  if ! .venv/bin/python -m pip install -r requirements.txt; then
    rm -rf .venv
    echo "Setup did not finish. Check the internet connection and run: bash run.sh"
    exit 1
  fi
else
  .venv/bin/python -m pip install -q -r requirements.txt || echo "Could not check for new packages (no internet?). Starting anyway."
fi
exec .venv/bin/python server.py
