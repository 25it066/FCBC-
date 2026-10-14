# FCBC Sentinel

A runnable, offline-capable defensive research application: React/TypeScript + FastAPI + SQLAlchemy, with persistent SQLite and optional PostgreSQL configuration. This replaces the earlier browser-only demo. It processes recorded telemetry and never modifies monitored files or terminates processes.

## Start on Windows (recommended for this package)

1. Install **Python 3.12** if it is not already available. The bundled launcher specifically calls `py -3.12`.
2. Extract the ZIP fully. Double-click **start.cmd**.
3. The first run installs Python packages, migrates the database and asks you to choose an administrator username and a password of at least 12 characters. There is no default password.
4. Open **http://127.0.0.1:8000** and sign in. Keep the command window open. Stop with Ctrl+C.

The built frontend is included, so **Node.js is not needed to run the downloaded package**. Internet is needed for initial Python dependency installation; analysis and demonstration run offline after setup. Run start.cmd again to reopen your saved workspace. SQLite data lives in backend/sentinel.db. Back up that database while the application is stopped.

If your laptop prevents installation, the source cannot bypass that restriction. Use an existing Python 3.12 installation, an administrator-approved machine, or a Python-capable hosting service.

### Linux / macOS

With Python 3.12 and venv available, run `sh start.sh`, create the account when prompted, then open http://127.0.0.1:8000.

### Manual setup

From the extracted project root:

```sh
python -m venv .venv
# Activate .venv using your shell, then:
python -m pip install -r backend/requirements.txt
cd backend
python -m alembic upgrade head
python -m app.setup_account
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Create additional accounts from backend with `python -m app.create_user NAME --role analyst` (or viewer/admin). The command securely prompts for the password. Resources are owner-scoped, including for admins; there is no shared-team dataset feature. Viewer roles cannot mutate data.

## College demonstration

1. Sign in → Upload Telemetry → choose **Ransomware-like disruption** → Generate trace.
2. Inspect normalized preview and quality flags. Select **Confirm analysis**.
3. Behavioral Analysis shows actual Python results; pause/reset affects visualization only.
4. File Correlation shows process/file relationships. Select a node to inspect evidence; uncertain rename observations are dashed.
5. Threat Detection exposes each window's contributions, event references and research classification.
6. Alert Investigation → inspect → update status and save analyst notes. Refresh to verify persistence.
7. Reports → download PDF, CSV or JSON. Paths are tokenized in report exports.
8. Repeat with Backup workload or Harmless distributed activity. The engine computes outcomes from events; they are not hardcoded.
9. Evaluation Lab → Run experiment. Compare FCBC, process-count and volume baselines, and three ablations on held-out synthetic executions. Export the manifest.

## Telemetry schema

Required: `event_id`, timezone-aware ISO `timestamp`, `host_id`, `session_id`, `operation`.
Optional canonical fields: `process_id`, `file_id`, `file_namespace`, `path`, `rename_source`, `rename_target`, `quality_flags`, `source_event_id`.

`file_id` and `file_namespace` are required for a record to participate in file correlation; missing values are kept visible and never invented. Use a namespace supplied by the collector (for example, volume ID). Duplicate event IDs are rejected within a host/session. Supported operations: Read, Write, Create, Rename, Delete, Metadata change. Original names and source metadata are retained.

CSV, JSON arrays, `{ "events": [...] }` JSON and JSONL are supported. Upload limit: 10 MiB and 50,000 records. The mapping field accepts canonical-to-source column names, such as `{"timestamp":"TimeCreated"}`. Upload validates and saves a dataset; analysis is a separate confirmation step. Uploaded telemetry is never executed and paths are never opened.

Sample files in `sample_data/` are entirely synthetic. Read **docs/FEATURES.md** before interpreting scores or making research claims.

## Development and tests

Frontend: Node 22+, `cd frontend`, `npm ci`, `npm run dev` (Vite proxies /api to FastAPI). Start FastAPI separately as above. `npm run build` updates the bundled frontend. No external fonts or cloud inference services are needed.

```sh
# In backend, with the virtual environment active:
python -m pytest -q
# In frontend:
npm test
npm run build
```

See **docs/IMPLEMENTATION_STATUS.md** for executed checks and limits. GitHub Actions runs backend tests, DOM navigation tests and the frontend build. Backend dependencies and frontend dependencies are pinned in requirements.txt and package-lock.json.

## API documentation

With the app running, open **http://127.0.0.1:8000/docs** for an offline endpoint index and **http://127.0.0.1:8000/openapi.json** for complete request/response schemas. A copy of the OpenAPI schema is included at docs/openapi.json.

Login returns an HttpOnly session cookie and a CSRF token. Send the cookie on requests and `X-CSRF-Token` on mutations. Session lifetime is eight hours. A logout invalidates the server-side session. Owner checks apply to dataset, run, alert, report and experiment lookups.

Analysis submits a bounded background job and returns HTTP 202; poll `/api/analysis/{id}/status` or use the authenticated WebSocket `/api/analysis/{id}/stream`. The frontend polls status. Analysis runs interrupted by server restart are explicitly marked failed and must be rerun. Use **one server worker**; the local queue is not a distributed durable task service.

## Docker

Copy `.env.example` to `.env`, set your own ADMIN_PASSWORD, then run `docker compose up --build`. Open http://127.0.0.1:8000. The volume persists SQLite data. Docker is provided but was not executed in the build environment.

## Deployment

A Python-capable host or container host is required. The available Sites host runs JavaScript Workers and cannot host this FastAPI service; **no live application was deployed**. Do not publish the frontend alone: it requires the same-origin backend.

Build the frontend, deploy the complete application/container, run Alembic migrations, and persist the database. Set ADMIN_USERNAME and ADMIN_PASSWORD through the host's secret manager for first bootstrap, then remove the bootstrap password after the account is created. Put an HTTPS reverse proxy in front, set COOKIE_SECURE=true, restrict access, and configure backups. If the proxy terminates TLS, configure Uvicorn trusted proxy headers only for that trusted proxy. For non-default development origins set ALLOWED_ORIGINS to a comma-separated allowlist.

For PostgreSQL use `DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/sentinel`, then run migrations. PostgreSQL support uses the same SQLAlchemy schema, but this delivery was tested with SQLite only.

Do not call this production endpoint protection. Independent security review, scalable job processing, realistic load testing and real-world evaluation are still needed. No model makes autonomous remediation decisions.

### Optional browser end-to-end test (not run in this delivery)

Start an isolated local instance first. Install the Playwright Chromium browser on your own development machine (`npx playwright install chromium` from frontend), set FCBC_USERNAME and FCBC_PASSWORD to a test account, then run `npm run test:e2e`. FCBC_URL defaults to http://127.0.0.1:8000. This creates a dataset and review in that account. Browser tests are separate from the DOM tests and were not executed here.
