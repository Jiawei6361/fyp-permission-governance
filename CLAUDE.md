# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

The project is an APU final year project: a platform that scans SharePoint permissions, maps Power Automate flow dependencies, scores oversharing risk, previews remediation, and executes and rolls back approved remediation plans. It runs against a stateful simulated tenant (the fictional "Lumira Trading") only. The LLM explanation described in the project brief is not built.

Flat layout, Python 3.12:

- **Milestone 1:** `backend/models.py` (SQLAlchemy 2, two SQLite files: the simulator's `backend/tenant_sim.db` with `users`, `files`, `permissions`, `flows`, `connections` on `TenantBase`, and the app's `backend/fyp_governance.db` with `assessments`, `remediation_plans`, `remediation_steps` on `AppBase`), `backend/seed.py` (deterministic seed 42, writes `tenant_sim.db` and `backend/ground_truth.json`), `backend/schemas.py` (Graph v1.0 permission and flow models, plus API response models), `backend/adapter.py` (`TenantAdapter`, stateful `SimulatorAdapter`, stub `LiveGraphAdapter` with the same method list), `backend/verify_milestone1.py`.
- **Milestone 2:** `backend/scanner.py` (risk scoring, weights in the `WEIGHTS` dict), `backend/flow_mapper.py` (flow dependencies, `BREAKAGE_CRITICAL` / `UNKNOWN_DEPENDENCY` / `SAFE_TO_REVOKE` / `KEEP_REQUIRED`), `backend/main.py` (FastAPI), `backend/evaluate_benchmark.py` (writes `backend/benchmark_results.json`), `backend/tests/` (`test_milestone2.py`, `test_milestone3.py`, `test_adapter.py`, `test_remediation.py`).
- **Remediation:** `backend/remediation.py` (plan state machine, five-step executor, rollback), routes in `main.py`, `frontend/src/components/RemediationsView.tsx`.
- **Milestone 3:** `frontend/` (React 18 + Vite 6 + TypeScript + Tailwind 3, npm): KPI bar and scan trigger, IT Security Admin / Business Manager views, dry-run modal, "Evaluation & Proof" benchmark tab. Manager review decisions are browser-only (localStorage per `scan_id`). A Remediations tab lists plans with a step timeline; plans are created from the admin dry-run modal.

No Makefile, Alembic, simulator HTTP service, job queue, LLM layer or YAML config exists. Plan execution is synchronous inside the request.

### Data and API facts

- Seeded dataset: 50 users, 100 files (10 sites x 10), 30 flows, 339 permissions, 23 connections. `ground_truth.json` records 12 overshared files, 15 stale-safe-to-revoke permissions, 14 workflow-breaking permissions, 2 benign broad grants and 5 `flow_path_cases`. The tests assert these counts, so changing `build_dataset()` is a breaking change.
- `flow_path_cases` are flow-26 to flow-30: three flows whose action path is a runtime expression (hr, it-infra, and payroll on the service principal) and two whose path is URL-encoded twice (contracts, operations). Each case records its expected result. A seeded scan gives 8 `BREAKAGE_CRITICAL`, 5 `UNKNOWN_DEPENDENCY`, 19 `SAFE_TO_REVOKE`, 307 `KEEP_REQUIRED`.
- `flow_mapper.parse_flow(flow, connections, files_by_path)` uses only the served flow resource and connection resources: identity comes from `properties.connectionReferences` -> `connectionName` -> connection -> `authenticatedUser` / `servicePrincipal`, and paths are URL-decoded twice. An action whose file cannot be worked out (no path, an expression such as `@{...}`, no matching file, or an unknown connection) is unresolved; nothing is guessed. The `flows` columns `owner_user_id`, `target_file_id` and `connection_type` are simulator bookkeeping that the adapter never serves; `FlowFacts` has no such fields (a test enforces this).
- `UNKNOWN_DEPENDENCY`: a flagged permission on a site where an active, non-service-principal flow has an unresolved action. It takes precedence over `BREAKAGE_CRITICAL`; `dependent_flows` then lists proven dependencies first and unresolved ones (with `unresolved_reason`) after.
- All tenant access goes through `backend/adapter.py`. `scanner.load_snapshot(adapter)` builds its facts from the Graph payloads, and `main.py` holds the adapter in `app.state.adapter` (`create_app(db_path, adapter)`). Only `adapter.py`, `seed.py` and `verify_milestone1.py` open `tenant_sim.db`; `scanner.py` must not import `sqlalchemy` or `backend.models` (a test enforces this).
- Adapter reads: `list_users`, `list_files`, `list_item_permissions`, `list_item_activity` (last-access time per permission), `list_flows`, `get_flow`, `list_connections` (per `connectionName`: `properties.authType` and the identity, `authenticatedUser.id` or `servicePrincipal.id`). Writes: `delete_item_permission`, `add_item_grant`, `update_flow_connection`; they raise `TenantError` (status, code) on bad requests. Simulator only: `run_flow`, `reset()`, `state_checksum()`.
- `SimulatorAdapter.run_flow(flow_id)` is the independent breakage check: `Succeeded` only if the connection identity has the required role on every file the flow's SharePoint actions touch, otherwise `Failed` with a 403 `accessDenied` error. A service-principal connection always passes. It decodes double-encoded paths itself and evaluates a dynamic path to the flow's `target_file_id`, which the engine is never told. `adapter.py` must never import `flow_mapper.py`.
- `tenant_sim.db` is gitignored; `SimulatorAdapter` seeds it when it is missing. Flow business criticality has no Power Automate source, so the simulator adds it to each flow resource as `simulatorAnnotations.isBusinessCritical`.
- `backend/tests/golden_classifications.json` is the scan output of the seeded tenant; `test_adapter.py` asserts the scan still matches it. It was regenerated when the flow path cases were seeded.
- Risk score is 0-100, the sum of the `WEIGHTS` in `scanner.py`, with `OVERSHARE_THRESHOLD = 50` and `STALE_DAYS = 90`. These are Python constants, exposed read-only at `GET /api/config/scoring`.
- Scans are immutable snapshots: each `POST /api/scan/run` appends `assessments` rows under a new `scan_id`. Reference time is the fixed `seed.NOW`.
- Routes (all in `main.py`, app built by `create_app()`): `GET /api/config/scoring`, `GET /api/benchmark`, `POST /api/scan/run`, `GET /api/assessments` (`classification`, `role=admin|manager`, `scan_id` query params), `GET /api/assessments/{id}`, `POST /api/assessments/{id}/dry-run`. Dry-run only describes the Graph `DELETE` request and is `blocked` unless the classification is `SAFE_TO_REVOKE`. `UNKNOWN_DEPENDENCY` is blocked with its own warning and lists the flows in `unresolved` instead of `breakage`. No auth; `role` is a presentation switch only.
- Remediation routes: `POST /api/remediations` (body `assessment_id`, `strategy`, `created_by`, `override_reason`; creates a DRAFT; an `UNKNOWN_DEPENDENCY` assessment returns 422 without a non-blank `override_reason`), `GET /api/remediations` (`state` filter), `GET /api/remediations/{id}`, and `POST /api/remediations/{id}/submit|approve|reject|execute|rollback`. Out-of-order transitions return 409. Only `execute` and `rollback` change the tenant.
- Plan states: `DRAFT -> PENDING_APPROVAL -> APPROVED -> EXECUTING -> COMPLETED`, plus `REJECTED`, `ROLLING_BACK`, `ROLLED_BACK`, `ROLLBACK_FAILED`. Steps always run in the order `SNAPSHOT, PROTECT_FLOW, PREFLIGHT, REMOVE_BROAD_GRANT, POSTFLIGHT` (`remediation.STEP_ORDER`). `REMOVE_BROAD_GRANT` is the only step that removes access and refuses to run unless `PREFLIGHT` succeeded; a test asserts the call order. Any step failure undoes completed steps in reverse from `before_state`. Unresolved flows are not changed by `PROTECT_FLOW` but are run in `PREFLIGHT` and `POSTFLIGHT`, so a plan that really breaks one rolls back.
- Strategies for `PROTECT_FLOW`: `service_principal` (rebind the flow to `seed.SP_CONNECTION` and grant the `seed.SP_APP` application on the file) or `scoped_identity_grant` (direct grant to the flow's current identity with only the role it needs). In the simulator a service-principal connection passes `run_flow` with or without that grant.
- `init_db` adds the nullable `remediation_plans.override_reason` column to an app database created before it existed (there is no Alembic).
- `remediation_plans.exposed_before` / `exposed_after` are nullable and always empty: exposed user counts are not computed yet.
- CORS allows `http://localhost:5173` and `http://127.0.0.1:5173`; `FYP_CORS_ORIGINS` (comma-separated) overrides.

## Commands

On this Windows machine always use `py`, never `python`. Run everything from the project root.

- API: `py -m uvicorn backend.main:app --reload` (port 8000; `FYP_DB_PATH` overrides the app database file, `FYP_TENANT_DB_PATH` the simulator file)
- Tests: `py -m pytest` (`pytest.ini` sets `testpaths = backend/tests`, `pythonpath = .`)
- Benchmark: `py backend/evaluate_benchmark.py`
- Reseed the simulator tenant: `py backend/seed.py`
- Milestone 1 checks: `py backend/verify_milestone1.py` (this reseeds `tenant_sim.db`)
- Frontend (run inside `frontend/`, uses `npm`): `npm install`, `npm run dev` (port 5173, API at `VITE_API_BASE`, default `http://127.0.0.1:8000`), `npm run build` (`tsc --noEmit && vite build`). Deep links: `#remediations`, `#benchmark`, `?role=manager`, `?preview=<assessment id>`, `?plan=<plan id>`.
- Running a scan writes `assessments` rows into whichever app database the API uses. To demo without touching the committed `fyp_governance.db`, copy it and set `FYP_DB_PATH`. Executing a plan changes `tenant_sim.db`; `py backend/seed.py` puts the seeded tenant back.
- Backend dependencies are pinned in `backend/requirements.txt`.

## Import structure

`backend` is a package (`backend/__init__.py`). All internal imports are absolute, for example `from backend.models import File`. Never use flat imports such as `from models import ...`; they break `backend.main:app`. Scripts that are run by file path (`seed.py`, `evaluate_benchmark.py`, `verify_milestone1.py`) insert the project root into `sys.path` when `__package__` is empty, before their `backend.*` imports. Any new runnable script needs the same guard.

## Target design

Decisions for where the project goes next. These are intent, not current behaviour.

- Keep the flat `backend/` layout. Do not migrate to `backend/app/`.
- `ARCHITECTURE.md` and `ROADMAP.md` are reference ideas only, not the plan. Do not treat anything in them as a requirement or cite them as the spec.
- All tenant reads and writes must go through `backend/adapter.py`. This is now true of the code; keep it that way.
- Tenant data and app data live in two separate SQLite files (done). New app tables go on `AppBase` in the app database, not the tenant one.
