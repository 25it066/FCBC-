# Implementation and verification status

Build date: 14 October 2026. This is a functioning local research application, not a production-certified protection product.

## Implemented and exercised

- React + TypeScript + Vite frontend, Tailwind CSS, responsive dark workspace, all ten navigation destinations. Charts use stored engine results and begin empty.
- FastAPI REST API, generated OpenAPI contract, offline documentation index, authenticated WebSocket status endpoint; frontend uses status polling.
- SQLAlchemy persistence, SQLite database, Alembic initial migration. Datasets, events, runs, episodes, windows, alerts, reviews, experiments, users, sessions and audit records survive restarts.
- Password hashing with per-user salt and scrypt, session-cookie authentication, CSRF tokens, owner-based access restrictions, admin/analyst/viewer authorization, basic login throttling, upload bounds and response security headers.
- CSV / JSON / JSONL parsing, column mapping, preview, explicit analysis confirmation, timestamp validation, scoped duplicate rejection and original source metadata retention.
- Stable identity boundaries, conservative verified renames, idle-gap episodes, half-open overlapping windows, missing-data eligibility, five documented research features, weighted scoring, explainable alerts and stored configuration hashes.
- Background analysis with bounded local queue, failure reporting, conservative restart handling. No monitored file access, no remediation.
- Actual event exploration, server filtering/pagination/sorting, evidence details, graph filters, analyst status/notes, saved settings, manual dataset retention/deletion and audit index.
- Safe synthetic generator, six workload scenarios, replay controls that affect visualization only.
- Synthetic validation/test experiment runner, process-count/volume baselines, rename/cross-process/benign-context ablations, per-execution confusion matrices and metrics, validation-only threshold selection, saved experiment manifests.
- PDF / CSV / JSON analysis exports, path tokenization, dataset/config hashes and full window evidence. Reports stream on demand; their download is audited.
- Windows and shell launchers; prebuilt frontend included. Docker and CI configuration included.

## Executed checks

| Check | Observed result |
|---|---|
| Pytest on Python 3.12 / SQLite | 43 passed |
| Vitest + jsdom navigation and upload-control checks | 2 passed; all ten pages opened |
| TypeScript check + Vite production build | Passed |
| Alembic upgrade on a fresh SQLite database | Passed |
| Authenticated API integration workflow | Upload → analyze → evidence graph → review → PDF/CSV/JSON export passed |
| Authorization / CSRF / owner isolation | Tested |
| Same-origin frontend and API documentation serving | Tested |
| Report generation | PDF signature/content generation and JSON path-redaction tested; exported PDF page layout was not visually inspected |

Observed non-fatal notices: installed Starlette warns that its httpx TestClient compatibility is deprecated; the frontend build warns about a roughly 944 kB uncompressed JS bundle. Dependencies are pinned to the versions used for these checks.

## Partial or not verified

- **No live deployment.** The available website host cannot execute FastAPI. A Python/container hosting environment is needed; README includes the setup path.
- **No real-world detection claim.** The report leaves exact feature formulas unspecified. The implemented formulas and default settings are explicit research assumptions. No real malware dataset was supplied and no real-world threshold was calibrated.
- **Evaluation is synthetic only.** Importing arbitrary labeled datasets into the comparison runner, training feature weights, and grouped train/validation/test research automation for real corpora remain future work. The supplied synthetic runner fixes weights and uses separate validation/test executions.
- **Browser automation not executed.** No supported browser-QA environment was available. DOM navigation tests passed, but they do not validate visual layout, drag/zoom interactions or browser downloads. A Playwright upload-to-export test is included for running on an isolated local account; it was not executed here.
- **Docker, PostgreSQL and Windows launcher not executed.** The Python application and SQLite migration were tested in Linux. Docker/PostgreSQL deployment configuration and launchers need verification on their target platforms.
- **Database normalization is pragmatic.** Feature vectors, scores, rename evidence and configuration are versioned JSON inside run/window/episode rows. There are no independent feature-vector, rename-link, upload-session or report-file tables. Reports are generated from immutable run results.
- **Research scale.** Single server process, two background worker threads, bounded queue. Running jobs are marked failed after restart, not automatically resumed. This is not a durable distributed job service. Event filtering currently loads the selected bounded dataset in memory.
- **Graph scope.** Up to 100 episodes, process nodes and rename observations. File identity is displayed on episode nodes; windows are selectable filters rather than separate graph nodes. There is no cross-file-ID lineage proof scheme.
- **Event export** currently exports the visible filtered page as JSON. Full source metadata is available through paginated APIs; score reports support CSV/JSON/PDF.
- **Security review pending.** No penetration test, SSO, MFA, encrypted-at-rest storage, distributed rate limiter, automatic retention scheduler, or hardened internet deployment is claimed. SQLite and PostgreSQL credentials/storage should be protected by the host. Roles do not provide cross-user sharing.
- **Telemetry semantics.** Namespace stability, file-ID reuse/generation boundaries and collector completeness must be guaranteed by the source. No live endpoint collector, watermark-based streaming, or content/entropy inspection is included.

These limitations are visible rather than hidden behind placeholder metrics. See FEATURES.md for exact score semantics and README.md for reproducible setup.
