#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
cd backend
../.venv/bin/python -m alembic upgrade head
../.venv/bin/python -m app.setup_account
printf 'Open http://127.0.0.1:8000 in your browser.\n'
exec ../.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
