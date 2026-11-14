# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

The project is an APU final year project: a platform that scans SharePoint permissions, maps Power Automate flow dependencies, scores oversharing risk, explains findings through an LLM, and remediates with rollback. It runs against a simulated tenant (the fictional "Lumira Trading").

`ARCHITECTURE.md` and `ROADMAP.md` are the long-term spec (cite sections as "A 7.3"; Grep for headings rather than reading them whole). The code built so far is a simpler flat layout than those documents describe:

- **Milestone 1:** `backend/models.py` (SQLAlchemy, SQLite at `backend/fyp_governance.db`), `backend/seed.py` (deterministic seed 42, writes `backend/ground_truth.json`), `backend/schemas.py` (Graph v1.0 permission and flow models), `backend/adapter.py`, `backend/verify_milestone1.py`.
- **Milestone 2:** `backend/scanner.py` (risk scoring, weights in `WEIGHTS`), `backend/flow_mapper.py` (flow dependencies and `BREAKAGE_CRITICAL` / `SAFE_TO_REVOKE` / `KEEP_REQUIRED`), `backend/main.py` (FastAPI), `backend/evaluate_benchmark.py` (writes `backend/benchmark_results.json`), `backend/tests/`.

No frontend, Makefile, Alembic or simulator HTTP service exists yet.

## Commands

On this Windows machine always use `py`, never `python`. Run everything from the project root.

- API: `py -m uvicorn backend.main:app --reload` (port 8000; `FYP_DB_PATH` overrides the database file)
- Tests: `py -m pytest` (`pytest.ini` sets `testpaths = backend/tests`, `pythonpath = .`)
- Benchmark: `py backend/evaluate_benchmark.py`
- Reseed the database: `py backend/seed.py`
- Milestone 1 checks: `py backend/verify_milestone1.py` (this reseeds `fyp_governance.db`)

## Import structure

`backend` is a package (`backend/__init__.py`). All internal imports are absolute, for example `from backend.models import File`. Never use flat imports such as `from models import ...`; they break `backend.main:app`. Scripts that are run by file path (`seed.py`, `evaluate_benchmark.py`, `verify_milestone1.py`) insert the project root into `sys.path` when `__package__` is empty, before their `backend.*` imports. Any new runnable script needs the same guard.

## Planned commands (from ROADMAP.md, not yet implemented)

`make setup | seed | sim | api | web | dev | db-reset | sim-reset | test | verify-mN`. Processes: simulator :8001, FastAPI backend :8000, Vite frontend :5173. Stack: Python 3.12, FastAPI, SQLAlchemy 2, Alembic, uv, pytest on the backend; React, TypeScript, Vite, pnpm, Vitest, Playwright on the frontend.

## Architecture rules that span many files

- **Backend never touches the tenant directly.** All access goes through the `TenantGateway` port (`backend/app/gateway/port.py`). `SimulatorAdapter` and `LiveGraphAdapter` share `base_http.py` (paging via `@odata.nextLink`, 429/5xx retry, error mapping) and differ only in base URLs and token acquisition, selected by `ADAPTER_MODE`.
- **The simulator mimics Microsoft Graph v1.0 and the Power Automate admin API on the wire**, with the same paths and JSON. It is stateful: deleting a permission changes later responses, and a flow test run fails when its connection identity loses access. That statefulness is what makes "zero broken workflows" measurable. `/_sim/*` routes exist only for the evaluation harness and tests, never for adapter code that also runs live. `/_sim/health` returns a `state_checksum` that tests use to prove a call changed nothing or a rollback restored everything.
- **Mock data is deterministic** (`generate.py`, seed 42) and committed under `mock_data/tenant/`. `ground_truth.json` holds 12 planted oversharing scenarios (P01-P12) plus 2 benign grants. Counts such as 50 users, 15 sites, 10 flows, 14 findings, 9 impact rows (5 BREAKS, 3 SAFE, 1 UNKNOWN) and a naive baseline of 6 broken flows are asserted by the tests, so changing the generator is a breaking change.
- **Scans are immutable snapshots** keyed by `scan_id`. Findings have a stable `fingerprint` so `dismissed` and `accepted_risk` carry over to later scans.
- **Risk = impact x likelihood**, with all weights, bands and floors in `backend/app/scoring_config.yaml` and exposed via `GET /config/scoring`. Do not hardcode them. `backend/tests/golden/scores.json` is compared exactly once it exists, so a weight change must regenerate it in the same commit.
- **Remediation is a saga** (A 9). Additive steps run first (grant service principal, rebind flow, preflight verify, add replacement grants), and the single destructive step `REMOVE_BROAD_GRANT` runs only after preflight succeeds. Every step has a compensation, and a failed verification triggers automatic rollback. Steps carry `idempotency_key = plan_id:seq`. Execution is single-flight through an optimistic `version` check. Stale snapshots return 409 `SNAPSHOT_STALE`.
- **The LLM sees structured metadata only, never file content.** The deterministic `template` provider is the default and must pass every check with no API key. LLM output goes through `validator.py`, and invalid output falls back to the template.
- **Background work** uses FastAPI background tasks plus a `jobs` table with heartbeats. There is no message broker. On startup, stale scans become `failed` and stale remediations roll back.
- **Roles:** `admin` runs scans and executes plans. `owner` is scoped by department, can approve or reject, and cannot execute. Owners get 404 on other departments' findings.
- **The API contract is frozen** from the milestone that introduces each route, enforced by Schemathesis and snapshot tests. Alembic migrations are one per milestone (`0001_m1`..`0006_m6`) and only add tables or columns.
- **Live writes** stay off unless `LIVE_WRITES_ENABLED=true`. The `service_principal` strategy models a real-tenant limitation: the standard SharePoint connector needs user context (A 1.1). `scoped_identity_grant` is the fallback.
