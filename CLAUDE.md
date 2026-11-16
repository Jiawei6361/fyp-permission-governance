# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

The project is an APU final year project: a platform that scans SharePoint permissions, maps Power Automate flow dependencies, scores oversharing risk, and previews (never executes) remediation. It runs against a simulated tenant (the fictional "Lumira Trading"). The LLM explanation and real remediation/rollback described in the project brief are not built.

Flat layout, Python 3.12:

- **Milestone 1:** `backend/models.py` (SQLAlchemy 2, SQLite at `backend/fyp_governance.db`; tables `users`, `files`, `permissions`, `flows`, `assessments`), `backend/seed.py` (deterministic seed 42, writes `backend/ground_truth.json`), `backend/schemas.py` (Graph v1.0 permission and flow models, plus API response models), `backend/adapter.py` (`TenantAdapter`, `SimulatorAdapter`, stub `LiveGraphAdapter`), `backend/verify_milestone1.py`.
- **Milestone 2:** `backend/scanner.py` (risk scoring, weights in the `WEIGHTS` dict), `backend/flow_mapper.py` (flow dependencies, `BREAKAGE_CRITICAL` / `SAFE_TO_REVOKE` / `KEEP_REQUIRED`), `backend/main.py` (FastAPI), `backend/evaluate_benchmark.py` (writes `backend/benchmark_results.json`), `backend/tests/` (`test_milestone2.py`, `test_milestone3.py`).
- **Milestone 3:** `frontend/` (React 18 + Vite 6 + TypeScript + Tailwind 3, npm): KPI bar and scan trigger, IT Security Admin / Business Manager views, dry-run modal, "Evaluation & Proof" benchmark tab. Manager review decisions are browser-only (localStorage per `scan_id`); nothing writes to the tenant.

No Makefile, Alembic, simulator HTTP service, saga/remediation executor, job queue, LLM layer or YAML config exists.

### Data and API facts

- Seeded dataset: 50 users, 100 files (10 sites x 10), 25 flows, 337 permissions. `ground_truth.json` records 12 overshared files, 15 stale-safe-to-revoke permissions, 12 workflow-breaking permissions and 2 benign broad grants. The tests assert these counts, so changing `build_dataset()` is a breaking change.
- The scanner reads the tenant tables of the SQLite database through `load_snapshot(session)`. It does not call `adapter.py` yet; only `verify_milestone1.py` and the tests use the adapter.
- Risk score is 0-100, the sum of the `WEIGHTS` in `scanner.py`, with `OVERSHARE_THRESHOLD = 50` and `STALE_DAYS = 90`. These are Python constants, exposed read-only at `GET /api/config/scoring`.
- Scans are immutable snapshots: each `POST /api/scan/run` appends `assessments` rows under a new `scan_id`. Reference time is the fixed `seed.NOW`.
- Routes (all in `main.py`, app built by `create_app()`): `GET /api/config/scoring`, `GET /api/benchmark`, `POST /api/scan/run`, `GET /api/assessments` (`classification`, `role=admin|manager`, `scan_id` query params), `GET /api/assessments/{id}`, `POST /api/assessments/{id}/dry-run`. Dry-run only describes the Graph `DELETE` request and is `blocked` unless the classification is `SAFE_TO_REVOKE`. No auth; `role` is a presentation switch only.
- CORS allows `http://localhost:5173` and `http://127.0.0.1:5173`; `FYP_CORS_ORIGINS` (comma-separated) overrides.

## Commands

On this Windows machine always use `py`, never `python`. Run everything from the project root.

- API: `py -m uvicorn backend.main:app --reload` (port 8000; `FYP_DB_PATH` overrides the database file)
- Tests: `py -m pytest` (`pytest.ini` sets `testpaths = backend/tests`, `pythonpath = .`)
- Benchmark: `py backend/evaluate_benchmark.py`
- Reseed the database: `py backend/seed.py`
- Milestone 1 checks: `py backend/verify_milestone1.py` (this reseeds `fyp_governance.db`)
- Frontend (run inside `frontend/`, uses `npm`): `npm install`, `npm run dev` (port 5173, API at `VITE_API_BASE`, default `http://127.0.0.1:8000`), `npm run build` (`tsc --noEmit && vite build`). Deep links: `#benchmark`, `?role=manager`, `?preview=<assessment id>`.
- Running a scan writes `assessments` rows into whichever database the API uses. To demo without touching the committed `fyp_governance.db`, copy it and set `FYP_DB_PATH`.
- Backend dependencies are pinned in `backend/requirements.txt`.

## Import structure

`backend` is a package (`backend/__init__.py`). All internal imports are absolute, for example `from backend.models import File`. Never use flat imports such as `from models import ...`; they break `backend.main:app`. Scripts that are run by file path (`seed.py`, `evaluate_benchmark.py`, `verify_milestone1.py`) insert the project root into `sys.path` when `__package__` is empty, before their `backend.*` imports. Any new runnable script needs the same guard.

## Target design

Decisions for where the project goes next. These are intent, not current behaviour.

- Keep the flat `backend/` layout. Do not migrate to `backend/app/`.
- `ARCHITECTURE.md` and `ROADMAP.md` are reference ideas only, not the plan. Do not treat anything in them as a requirement or cite them as the spec.
- All tenant reads and writes must go through `backend/adapter.py`. Today `scanner.py` still reads the tenant tables directly, so new code must use the adapter and existing direct reads should be moved behind it.
- Tenant data and app data live in two separate SQLite files. Today both share `fyp_governance.db` (`users`, `files`, `permissions`, `flows` are tenant data; `assessments` is app data). New app tables go in the app database, not the tenant one.
