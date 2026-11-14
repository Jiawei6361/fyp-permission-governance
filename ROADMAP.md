# ROADMAP.md

Build plan for the permission governance platform specified in `ARCHITECTURE.md`. Six vertical slices. Each slice cuts through simulator, backend, database and frontend, ends in something a person can run and see, and adds a regression gate that every later slice must keep green.

Section numbers such as "A 7.3" refer to `ARCHITECTURE.md`.

## How the milestones protect each other

Three rules apply to every milestone.

1. `make verify-mN` runs `verify-m1` through `verify-m(N-1)` first, then the new checks. A milestone is finished only when `make verify-mN` exits 0 from a clean checkout.
2. Database changes ship as one Alembic migration per milestone (`0001_m1` to `0006_m6`). Migrations only add tables and columns. `make db-reset` followed by `alembic upgrade head` must work at every milestone.
3. The API contract in A 6 is frozen from the milestone that introduces each route. A contract test (Schemathesis against `/openapi.json`, plus response snapshot tests) fails the build when a response shape changes.

At the end of each milestone, tag the commit (`m1` to `m6`) and record a two-minute screen capture of the browser check. The captures become evidence for the FYP report and the supervisor log sheet.

## Common commands

| Command | Effect |
| --- | --- |
| `make setup` | Installs backend packages with uv and frontend packages with pnpm, copies `.env.example` to `.env` |
| `make seed` | Runs `mock_data/generator/generate.py --seed 42`, rewrites `mock_data/tenant/*.json` and `manifest.json` |
| `make sim` | Starts the simulator on port 8001 |
| `make api` | Runs `alembic upgrade head`, seeds dashboard users, starts the backend on port 8000 |
| `make web` | Starts the Vite dev server on port 5173 |
| `make dev` | Starts simulator, backend and frontend together |
| `make db-reset` | Deletes the development database |
| `make sim-reset` | Calls `POST http://localhost:8001/_sim/reset` |
| `make test` | Runs all pytest, Vitest and Playwright suites |
| `make verify-mN` | Runs the automated acceptance checks for milestones 1 to N |

Shell variables used in the verification steps:

```bash
SIM=http://localhost:8001
API=http://localhost:8000/api/v1
SIMTOKEN=$(curl -s -X POST $SIM/7d3f0c1e-0000-4000-8000-000000000001/oauth2/v2.0/token \
  -d 'grant_type=client_credentials&client_id=sim&client_secret=sim&scope=https://graph.microsoft.com/.default' \
  | jq -r .access_token)
TOKEN=$(curl -s -X POST $API/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@lumira.example","password":"ChangeMe!123"}' | jq -r .access_token)
OWNER=$(curl -s -X POST $API/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"hr.owner@lumira.example","password":"ChangeMe!123"}' | jq -r .access_token)
H="Authorization: Bearer $TOKEN"
```

## Overview

| Milestone | Slice | Runnable result | Effort estimate |
| --- | --- | --- | --- |
| 1 | Simulated tenant, adapter, walking skeleton | Log in and see live tenant counts served through the adapter | 6 days |
| 2 | Scan and permission inventory | Run a scan, browse sites, folders, permissions and effective access | 6 days |
| 3 | Risk scoring and findings | Ranked findings with factor breakdown; ground-truth detection report | 5 days |
| 4 | Flow dependency mapping and breakage detection | Dependency graph, workflow conflict alerts, what-if simulation | 6 days |
| 5 | Plain-language explanations and owner decision cards | Owner logs in, reads a card, approves or rejects a plan | 6 days |
| 6 | Remediation, verification, rollback, evaluation | Execute a plan end to end with zero broken flows, undo it, compare against the naive baseline | 8 days |

The estimates assume one developer working full days and total 37 days. Treat them as a planning guess to revise after milestone 1.

## Milestone 1: simulated tenant, adapter and walking skeleton

Goal: a deterministic fake Microsoft 365 tenant that answers Graph-shaped requests, a backend that reaches it only through the `TenantGateway` port, and a dashboard shell with login.

### Build

Mock data and simulator

- `company_spec.yaml` with the departments, 15 sites, 10 flows, 12 planted scenarios and 2 benign grants from A 4.4.
- `generator/generate.py`, deterministic with seed 42, writing every file under `mock_data/tenant/` plus `manifest.json` (counts, sha256 per file) and `ground_truth.json`.
- Simulator read routes from A 4.3: token, users, groups, transitive members, sites, drives, children, item permissions, site application permissions, sensitivity labels, audit query, SharePoint site groups, flows, flow detail, runs, connections, and `/_sim/health`, `/_sim/reset`.
- Paging through `@odata.nextLink`, Graph error bodies, optional 429 mode.

Backend

- App factory, config, error envelope, SQLAlchemy setup, migration `0001_m1` (`app_users`, `audit_log`, `jobs`).
- `gateway/port.py`, `base_http.py`, `simulator.py`, `live_graph.py` (read methods; live adapter compiled and unit-tested against recorded responses, not run against a real tenant), `factory.py`.
- Routes 1 to 3 (login, me, health). Seeded dashboard users.
- A development-only route `GET /api/v1/_debug/tenant-counts` that calls the gateway and returns counts. It is removed in milestone 2.

Frontend

- Vite project, router, login page, token storage, protected layout with navigation, Overview page showing adapter mode and tenant counts.

### Automated checks added to `make verify-m1`

- Generator determinism: running `make seed` twice gives identical `manifest.json` checksums.
- Seed invariants: 50 users, 12 groups, 15 sites, 10 flows, exactly 14 broad grants, every planted scenario in `ground_truth.json` points at an existing permission.
- Schema parity: every simulator response validates against JSON Schemas written from the Microsoft Graph v1.0 resource definitions (`user`, `group`, `site`, `drive`, `driveItem`, `permission`) and against one recorded flow definition sample.
- Adapter contract tests: the same test suite runs against `SimulatorAdapter` (live simulator) and `LiveGraphAdapter` (respx-mocked Graph), proving both satisfy the port.
- Paging and retry: a 250-item collection is fully read; a 429 with `Retry-After: 1` is retried.

### Verify from the command line

```bash
make setup && make seed
make sim &      # terminal 1
make api &      # terminal 2

curl -s $SIM/_sim/health | jq .status
# "ok"

curl -s "$SIM/v1.0/users?\$top=999" -H "Authorization: Bearer $SIMTOKEN" | jq '.value | length'
# 50

curl -s "$SIM/v1.0/sites?search=*" -H "Authorization: Bearer $SIMTOKEN" | jq '.value | length'
# 15

curl -s "$SIM/providers/Microsoft.ProcessSimple/scopes/admin/environments/Default-7d3f0c1e/v2/flows?api-version=2016-11-01" \
  -H "Authorization: Bearer $SIMTOKEN" | jq '.value | length'
# 10

curl -s "$SIM/v1.0/users?\$top=10" -H "Authorization: Bearer $SIMTOKEN" | jq 'has("@odata.nextLink")'
# true

curl -s -o /dev/null -w '%{http_code}\n' "$SIM/v1.0/users"
# 401

curl -s $API/health | jq '{status, adapter_mode, tenant_gateway}'
# {"status":"ok","adapter_mode":"simulator","tenant_gateway":"ok"}

curl -s $API/_debug/tenant-counts -H "$H" | jq -c .
# {"users":50,"groups":12,"sites":15,"flows":10}

make verify-m1
# exit code 0
```

### Verify in the browser

1. Open `http://localhost:5173`. The login page appears.
2. Sign in as `admin@lumira.example` with `ChangeMe!123`. The Overview page shows "Adapter: simulator" and the four counts 50, 12, 15, 10.
3. Stop the simulator and reload. The Overview page shows a "Tenant unreachable" banner, and the page does not crash.
4. Sign out. Visiting `/overview` redirects to `/login`.

### Done when

`make verify-m1` passes, the browser steps pass, and switching `ADAPTER_MODE=live` with no credentials makes `/health` report `"tenant_gateway": "error"` while the app still starts.

## Milestone 2: scan and permission inventory

Goal: one click takes a full snapshot of the tenant into the database, and an administrator can answer "who can open this folder, and through which grant".

### Build

Backend

- Migration `0002_m2`: `scans`, `principals`, `group_memberships`, `sites`, `resources`, `permissions`, `access_events`.
- `jobs/runner.py` with heartbeat and startup recovery for stale scans.
- `pipeline/scanner.py`: phases `identity`, `inventory`, `audit`; progress updates; role normalisation; `inherited_from` resolution; `has_unique_permissions`.
- `pipeline/effective_access.py`: expansion of groups, site groups, Everyone principals and redeemed link identities; maximum role per user per resource, with the grant paths.
- Routes 5 to 12 (scans, sites, resources, effective access). `scan_id=latest` resolution. Removal of the debug route from milestone 1.

Frontend

- Scans page with a "Run scan" button, progress bar and history.
- Sites page (table), Site detail page (folder tree), Resource page (permission table with an "inherited from" column, effective access table with search).

### Automated checks added to `make verify-m2`

- Scan stats equal `manifest.json` for users, groups, sites, resources, permissions and access events.
- Effective access unit tests on hand-built fixtures: nested groups, a disabled user excluded, a guest excluded from "Everyone except external users", inherited versus unique permissions, link redeemers only.
- For all 12 planted scenarios, the effective-access count on the resource equals the `audience_count` recorded in `ground_truth.json`.
- A second scan creates a second snapshot and leaves the first unchanged.
- Starting a scan while one is running returns 409 `SCAN_ALREADY_RUNNING`.
- A scan killed mid-run is marked `failed` after backend restart.

### Verify from the command line

```bash
SCAN=$(curl -s -X POST $API/scans -H "$H" -H 'Content-Type: application/json' \
  -d '{"site_ids":null,"audit_lookback_days":90}' | jq -r .id)

watch -n1 "curl -s $API/scans/$SCAN -H '$H' | jq -c '{status,phase,progress_pct}'"
# ends at {"status":"completed","phase":null,"progress_pct":100}

curl -s $API/scans/$SCAN -H "$H" | jq -c '.stats | {users,groups,sites,flows}'
# {"users":50,"groups":12,"sites":15,"flows":null}   (flows arrive in milestone 4)

diff <(curl -s $API/scans/$SCAN -H "$H" | jq '.stats.resources, .stats.permissions') \
     <(jq '.counts.drive_items, .counts.permissions' mock_data/tenant/manifest.json)
# no output

curl -s "$API/sites?sort=name" -H "$H" | jq '.total'
# 15

PAYROLL=$(curl -s "$API/sites" -H "$H" | jq -r '.items[] | select(.name=="payroll") | .id')
RUNS=$(curl -s "$API/sites/$PAYROLL/resources" -H "$H" | jq -r '.items[] | select(.name=="Monthly Runs") | .id')
curl -s "$API/resources/$RUNS" -H "$H" | jq -c '[.permissions[] | select(.grant_kind=="everyone") | .role]'
# ["read"]

curl -s "$API/resources/$RUNS/effective-access?page_size=100" -H "$H" | jq '.total'
# 48

make verify-m2
```

### Verify in the browser

1. On Scans, press "Run scan". The progress bar moves through identity, inventory and audit, then shows "Completed".
2. Open Sites. 15 rows appear. Open "payroll", then "Monthly Runs".
3. The permission table lists "Everyone except external users, read, defined here". The effective access table lists 48 people, and searching for a guest's name returns nothing.
4. Open a file inside "Monthly Runs". The same grant appears with "inherited from Monthly Runs".
5. Reload the page. All data comes from the database: stop the simulator and the pages still load.

### Done when

`make verify-m2` passes and a completed scan can be browsed with the simulator stopped.

## Milestone 3: risk scoring and findings

Goal: every broad grant becomes a scored, explainable finding, and the system proves its detection accuracy against the planted ground truth.

### Build

Backend

- Migration `0003_m3`: `findings`, plus `is_broad` on `permissions` and `risk_score`, `risk_band` on `sites`.
- `scoring_config.yaml` with the weights, bands and floors from A 7.3. `pipeline/risk_scorer.py` implementing the five finding types, the sets in A 7.2, the formula and the floors.
- Scanner phase `analysis` (scoring part). Fingerprints, and carry-over of `dismissed` and `accepted_risk` status from the previous scan.
- Routes 4, 16, 17, 18, 31 and 33 (scoring config, findings list and detail, status change, metrics summary, ground-truth report with the detection and band sections).

Frontend

- Overview page with band counts, `exposure_pairs`, and a top-sites chart.
- Findings page with filters (band, site, type, status) and sorting.
- Finding detail page with a factor bar for S, E, A, X, H, the exposed-by-department breakdown and the status control.
- Evaluation page showing precision, recall and per-scenario band checks.

### Automated checks added to `make verify-m3`

- Formula unit tests for each row of every table in A 7.3, both floors, the tag floor on S, and the two worked examples (P01 scores 79, the benign intranet grant scores Low).
- Property test: the score is always between 0 and 100 and never decreases when S, E, A, X or H increases.
- Ground truth: 14 findings in total, recall 1.0 and precision 1.0 at Medium or above, every planted scenario at or above its minimum band, both benign grants Low.
- Golden file: `backend/tests/golden/scores.json` is created at the end of this milestone and compared exactly from then on. A deliberate weight change requires regenerating it in the same commit.
- Carry-over: a finding marked `accepted_risk` keeps that status after a second scan.
- Changing a weight in `scoring_config.yaml` changes `GET /config/scoring` and the next scan's scores, with no code change.

### Verify from the command line

```bash
make sim-reset
SCAN=$(curl -s -X POST $API/scans -H "$H" -H 'Content-Type: application/json' -d '{}' | jq -r .id)
sleep 30

curl -s "$API/findings?page_size=100" -H "$H" | jq '.total'
# 14

curl -s "$API/findings?band=Low&page_size=100" -H "$H" | jq '.total'
# 2

curl -s "$API/findings?sort=-score&page_size=1" -H "$H" | jq -c '.items[0] | {band, type: .finding_type}'
# {"band":"Critical","type":"ANONYMOUS_LINK"}

F1=$(curl -s "$API/findings?page_size=100" -H "$H" | jq -r '.items[] | select(.resource.name=="Monthly Runs") | .id')
curl -s "$API/findings/$F1" -H "$H" | jq -c '{score, band, s: .factors.s, e: .factors.e}'
# {"score":79,"band":"Critical","s":1,"e":0.9}   (score fixed by the golden file)

curl -s "$API/evaluation/ground-truth" -H "$H" | jq -c '.detection | {planted, detected, precision, recall}'
# {"planted":12,"detected":12,"precision":1,"recall":1}

INTRANET=$(curl -s "$API/findings?band=Low&page_size=100" -H "$H" | jq -r '.items[] | select(.site.name=="intranet") | .id')
curl -s -X PATCH "$API/findings/$INTRANET" -H "$H" -H 'Content-Type: application/json' \
  -d '{"status":"accepted_risk","reason":"Intranet content is meant for all staff."}' | jq -r .status
# accepted_risk

make verify-m3
```

### Verify in the browser

1. Open Overview. The band tiles add up to 14 and the top site is one with a Critical finding.
2. Open Findings, filter to Critical. Five rows appear (P01, P05, P08, P09, P10).
3. Open the "Monthly Runs" finding. The factor bar shows S 1.00, E 0.90, A 1.00, X about 0.9, H 0, and the text "44 people would lose access, 4 used it in the last 90 days" matches the numbers in the API response.
4. Mark the intranet finding as accepted risk with a reason. It leaves the default "open" filter. Run a new scan and confirm it is still accepted.
5. Open Evaluation. Every scenario row shows a pass.

### Done when

`make verify-m3` passes and the golden score file is committed.

## Milestone 4: flow dependency mapping and breakage detection

Goal: for every finding, the system states which Power Automate flows would break if the grant were removed, shows why, and lets the user test a fix without changing anything.

### Build

Mock data and simulator

- `simulator/access_engine.py` and the flow run engine: a run succeeds only when the connection identity holds the required role on every resource the flow touches, evaluated against current simulator state. F09's dynamic folder resolves to "Board Packs" at run time.
- Routes `POST /_sim/flows/{flow}/test-run`, run history, and resubmit.

Backend

- Migration `0004_m4`: `flows`, `flow_connections`, `flow_dependencies`, `finding_flow_impacts`, plus `recommendation` on `findings`.
- Scanner phase `flows`. `pipeline/flow_parser.py` (recursive walk, double URL decoding, operation-to-role table, expression detection), `dependency_graph.py`, `breakage_detector.py`, `recommender.py` per A 7.4 to 7.6.
- Routes 13, 14, 15 and 19 (flows, flow detail, dependency graph, simulate). Findings routes gain `impact_summary`, `flow_impacts`, `recommendation` and the `has_flow_impact` and `impact` filters. The ground-truth report gains `impact_checks` and `flows`.

Frontend

- Flows page and Flow detail page (connections, dependencies, findings that affect the flow).
- Dependency graph page built with React Flow: flow, identity, resource and grant nodes, with broad grants and BREAKS paths highlighted.
- Finding detail page: a "Workflow impact" panel with a BREAKS, SAFE or UNKNOWN chip per flow and the reason, and a "What if we remove this?" panel that calls the simulate route.

### Automated checks added to `make verify-m4`

- Parser unit tests on fixture definitions: nested `Scope`, `If`, `Foreach` and `Switch`; double-encoded folder ids; trigger dependencies; an `Http` action; an expression path giving `unresolved`; an unknown `operationId` treated as write.
- All 10 seeded flows parse, and each flow's extracted dependencies equal the list in `ground_truth.json`.
- Impact rows: 9 in total with 5 BREAKS, 3 SAFE and 1 UNKNOWN, each matching the expected value per scenario.
- Detector unit tests: alternate path through a group gives SAFE; read remaining with write required gives BREAKS with reason `INSUFFICIENT_ROLE_AFTER_REMOVAL`; a dependency on a sibling folder is skipped; a dependency on a descendant that inherits the grant is included.
- Oracle test: for each planted scenario, delete the grant directly in the simulator, test-run the dependent flow, and confirm the simulator's actual result equals the detector's prediction (UNKNOWN must correspond to an actual failure for P05). Reset afterwards.
- Simulate is side-effect free: simulator state checksum is identical before and after the call.
- Milestone 3 golden scores are unchanged.

### Verify from the command line

```bash
make sim-reset
curl -s -X POST $API/scans -H "$H" -H 'Content-Type: application/json' -d '{}' >/dev/null; sleep 30

curl -s "$API/flows" -H "$H" | jq '.total'
# 10

curl -s "$API/scans?page_size=1" -H "$H" | jq -c '.items[0].stats.impacts'
# {"BREAKS":5,"SAFE":3,"UNKNOWN":1}

curl -s "$API/findings?impact=BREAKS&page_size=100" -H "$H" | jq '.total'
# 5

F1=$(curl -s "$API/findings?page_size=100" -H "$H" | jq -r '.items[] | select(.resource.name=="Monthly Runs") | .id')
curl -s "$API/findings/$F1" -H "$H" | jq -c '.flow_impacts[0] | {flow: .flow.display_name, impact, remaining_role, reason}'
# {"flow":"Payroll export to bank folder","impact":"BREAKS","remaining_role":"none","reason":"ONLY_PATH_IS_TARGET_GRANT"}

curl -s -X POST "$API/findings/$F1/simulate" -H "$H" -H 'Content-Type: application/json' \
  -d '{"strategy":"service_principal","keep_principal_graph_ids":[],"replacement_group_graph_id":"g-hr"}' \
  | jq -c '{exposed_after, outcome: .flow_outcomes[0] | {without_mitigation, with_plan}}'
# {"exposed_after":0,"outcome":{"without_mitigation":"BREAKS","with_plan":"SAFE"}}

PHX=$(curl -s "$API/findings?impact=UNKNOWN" -H "$H" | jq -r '.items[0].id')
curl -s -X POST "$API/findings/$PHX/simulate" -H "$H" -H 'Content-Type: application/json' \
  -d '{"strategy":"service_principal","keep_principal_graph_ids":[]}' | jq -c '.blocking[0].code'
# "UNKNOWN_IMPACT"

curl -s "$API/dependency-graph" -H "$H" | jq '[.nodes[] | select(.type=="flow")] | length'
# 10

curl -s "$API/evaluation/ground-truth" -H "$H" | jq '[.impact_checks[] | select(.pass==false)] | length'
# 0

make verify-m4
```

### Verify in the browser

1. Open Flows. 10 rows appear, and "Payroll export to bank folder" shows "1 finding puts this flow at risk".
2. Open Dependency graph and filter to the payroll site. The path svc-automation, Everyone except external users, Monthly Runs is drawn in the warning colour.
3. Open the "Monthly Runs" finding. The Workflow impact panel reads "Payroll export to bank folder would break: its account reaches this folder only through this grant."
4. In "What if we remove this?", choose HR Team as the replacement and press Simulate. The panel shows the before and after exposed counts and "Workflow keeps running after migration".
5. Open the Board Packs finding. The impact chip reads UNKNOWN with the explanation that the flow builds its folder path at run time.
6. Open the finance Invoices finding. The chip reads SAFE with "access continues through Finance Team".

### Done when

`make verify-m4` passes, including the oracle test, which is the strongest evidence for the project's unique contribution.

## Milestone 5: plain-language explanations and owner decision cards

Goal: a business owner with no security training logs in, reads a short explanation of each finding for their department, and approves or rejects a remediation plan. Nothing in the tenant changes yet.

### Build

Backend

- Migration `0005_m5`: `explanations`, `remediation_plans`, `remediation_steps`, `rollback_snapshots`.
- `llm/` package: provider protocol, template provider, Anthropic provider, OpenAI-compatible provider, prompts, validator, cache, fallback (A 8).
- `remediation/state_machine.py` and `planner.py`: states and guards up to `APPROVED`, plus `REJECTED`, `CANCELLED`, `BLOCKED` and the override. The planner writes the ordered steps as `pending`.
- Role and department scoping for owners on findings, plans and sites.
- Routes 20 to 28 (explanations; create, list, get, submit, approve, reject, cancel) and route 32 (audit log).

Frontend

- Decision cards page for owners: one card per finding at Medium or above in their department, with headline, three short paragraphs, the workflow warning, and Approve and Reject buttons with a comment box. A "Show the details" toggle reveals the factor bar.
- Finding detail page for admins: "Create remediation plan" dialog (strategy, keep list with last-access dates, replacement group), explanation panel with audience switch.
- Remediations page and Remediation detail page with the step list (all pending) and the state history.
- Audit log page.

### Automated checks added to `make verify-m5`

- Template provider: explanations for all 12 planted findings pass the validator, and every number in the text appears in the facts.
- Validator unit tests: an invented number, an unknown flow name, an over-length field, and "no workflows affected" alongside a BREAKS impact are each rejected.
- Fallback: a stub provider that returns invalid output twice results in a stored explanation with `provider = "template"`.
- Cache: a second POST with `regenerate=false` makes no provider call.
- State machine: table-driven test of every allowed and disallowed transition up to `APPROVED`; version conflict returns 409; a second plan for the same resource returns 409 `ACTIVE_PLAN_EXISTS`; self-approval is refused when `REQUIRE_SEPARATE_APPROVER=true`.
- Blocking: a plan for the Board Packs finding starts `BLOCKED` and moves to `IMPACT_ANALYSED` only with an override reason of 20 or more characters.
- Scoping: the HR owner receives 404 for a finance finding and cannot call `/scans` (403).
- Simulator state checksum is unchanged by everything in this milestone.

### Verify from the command line

```bash
F1=$(curl -s "$API/findings?page_size=100" -H "$H" | jq -r '.items[] | select(.resource.name=="Monthly Runs") | .id')

curl -s -X POST "$API/findings/$F1/explanation" -H "$H" -H 'Content-Type: application/json' \
  -d '{"audience":"owner","regenerate":false}' | jq -c '{provider, passed: .validation.passed, headline: .content.headline}'
# {"provider":"template","passed":true,"headline":"48 staff can open payroll files; 4 of them needed to in the last 90 days."}

PLAN=$(curl -s -X POST $API/remediations -H "$H" -H 'Content-Type: application/json' \
  -d "{\"finding_id\":\"$F1\",\"strategy\":\"service_principal\",\"keep_principal_graph_ids\":[],\"replacement_group_graph_id\":\"g-hr\"}" | jq -r .id)
curl -s "$API/remediations/$PLAN" -H "$H" | jq -c '{state, steps: [.steps[].action]}'
# {"state":"IMPACT_ANALYSED","steps":["SNAPSHOT","GRANT_SP_SITE_ACCESS","REBIND_FLOW_CONNECTION","PREFLIGHT_VERIFY","ADD_REPLACEMENT_GRANTS","REMOVE_BROAD_GRANT","POSTFLIGHT_VERIFY"]}

curl -s -X POST "$API/remediations/$PLAN/submit" -H "$H" -H 'Content-Type: application/json' -d '{"expected_version":1}' | jq -r .state
# PENDING_APPROVAL

curl -s -o /dev/null -w '%{http_code}\n' -X POST "$API/remediations/$PLAN/approve" -H "$H" \
  -H 'Content-Type: application/json' -d '{"expected_version":2,"comment":"self approve"}'
# 403

curl -s -X POST "$API/remediations/$PLAN/approve" -H "Authorization: Bearer $OWNER" \
  -H 'Content-Type: application/json' -d '{"expected_version":2,"comment":"Approved, payroll should be HR only."}' | jq -r .state
# APPROVED

curl -s -o /dev/null -w '%{http_code}\n' "$API/scans" -H "Authorization: Bearer $OWNER"
# 403

curl -s "$API/audit-log?entity_id=$PLAN" -H "$H" | jq -c '[.items[].action]'
# ["plan.approved","plan.submitted","plan.created"]

curl -s $SIM/_sim/health | jq -r .state_checksum      # run before and after this block
# identical values

make verify-m5
```

Optional check with a real model: set `LLM_PROVIDER` and `LLM_API_KEY`, restart, call the explanation route with `"regenerate": true`, and confirm `provider` is the chosen one and `validation.passed` is true.

### Verify in the browser

1. Sign in as admin, open the "Monthly Runs" finding and create a plan with HR Team as the replacement. Submit it for approval.
2. Sign out and sign in as `hr.owner@lumira.example`. Only Decision cards and Remediations appear in the navigation.
3. The payroll card has a headline, three short paragraphs and an amber "1 workflow depends on this" notice. No permission jargon appears on the card.
4. Press Approve and enter a comment. The card moves to "Approved, waiting for IT".
5. Sign in as `finance.owner@lumira.example`. The payroll card is not listed.
6. Sign in as admin. The plan shows state APPROVED, the approver's name and comment, seven pending steps, and the Audit log page lists the three plan events.

This milestone is the right point to run the usability sessions for objective 4 (SUS questionnaire and timed decision task against a plain permission report), because the decision card is complete and stable.

### Done when

`make verify-m5` passes and the simulator checksum proves no tenant change has happened.

## Milestone 6: remediation, verification, rollback and evaluation

Goal: an approved plan executes against the tenant in the safe order, verifies that every dependent flow still runs, rolls back on failure or on request, and the evaluation page reports the numbers for objective 4.

### Build

Mock data and simulator

- Write routes from A 4.3: grant and revoke site application permission, `invite`, `createLink`, delete permission, `PATCH` flow connection references.
- Fault injection for tests: `POST /_sim/faults` with `{route, status, count}` makes the next matching calls fail; `{flow, force_fail: true}` makes a flow's runs fail.

Backend

- Migration `0006_m6`: indexes and the partial unique index on active plans. No new tables.
- Gateway write methods in both adapters. `LIVE_WRITES_ENABLED` guard.
- `remediation/executor.py` and `rollback.py`: freshness check, step journal, idempotency checks, verification polling, automatic rollback, manual rollback, retry of failed compensations, startup recovery (A 9.3 to 9.5).
- Routes 29, 30, 34 and 35 (execute, rollback, naive baseline, simulator reset). Metrics summary gains `plans_by_state` and the trend across scans.
- Docker Compose with PostgreSQL; the full suite runs on both databases.

Frontend

- Remediation detail page: live step timeline polling every 2 seconds, Execute and Roll back buttons with confirmation text, failure panel with the outstanding action when rollback fails.
- Evaluation page: before and after `exposure_pairs`, flows succeeding, comparison with the naive baseline, export of the figures as CSV for the report.

### Automated checks added to `make verify-m6`

- Happy path for each BREAKS scenario (P01, P02, P03, P04, P06): plan, approve, execute, state `COMPLETED`, broad grant gone from the simulator, flow test-run succeeds, `exposed_after_actual` no greater than expected.
- Strategy `scoped_identity_grant` on P02: the flow keeps its user connection, receives a direct read grant on "Active", and still runs.
- SAFE path (P07) and no-flow path (P08): steps 2 to 4 are `skipped`, the plan completes.
- Override path (P05): with an override the plan migrates F09 and completes with the flow running.
- Step order invariant: in every journal, `REMOVE_BROAD_GRANT` starts after every `PREFLIGHT_VERIFY` has succeeded.
- Automatic rollback: a fault on the pre-flight run moves the plan to `ROLLED_BACK`, and the simulator state checksum equals the checksum before execution.
- Rollback after the destructive step: a fault on post-flight verification restores the broad grant and the original connection; the flow runs again.
- Manual rollback from `COMPLETED` restores the original state checksum.
- Rollback failure: a persistent fault on a compensation gives `ROLLBACK_FAILED`; clearing the fault and calling rollback again gives `ROLLED_BACK`.
- Idempotency: running the executor twice on the same plan makes no duplicate gateway writes.
- Staleness: changing the target permission in the simulator after approval makes execute return 409 `SNAPSHOT_STALE` and the plan return to `DRAFT`.
- Crash recovery: killing the backend during step 5 and restarting leads to `ROLLED_BACK`.
- Concurrency: two simultaneous execute calls give one 202 and one 409.
- Full evaluation run: remediate all 12 planted findings, rescan, expect 0 open findings at Medium or above, 10 of 10 flows succeeding, and a naive baseline of 6 broken flows.
- End-to-end Playwright test covering admin scan, plan creation, owner approval, admin execution and rollback.
- The complete suite passes with `DATABASE_URL` pointing at PostgreSQL.

### Verify from the command line

```bash
make sim-reset && make db-reset && make api &
curl -s -X POST $API/scans -H "$H" -H 'Content-Type: application/json' -d '{}' >/dev/null; sleep 30
BEFORE=$(curl -s $API/metrics/summary -H "$H" | jq .exposure_pairs)

# plan, approve and execute the payroll finding
F1=$(curl -s "$API/findings?page_size=100" -H "$H" | jq -r '.items[] | select(.resource.name=="Monthly Runs") | .id')
PLAN=$(curl -s -X POST $API/remediations -H "$H" -H 'Content-Type: application/json' \
  -d "{\"finding_id\":\"$F1\",\"strategy\":\"service_principal\",\"keep_principal_graph_ids\":[],\"replacement_group_graph_id\":\"g-hr\"}" | jq -r .id)
curl -s -X POST "$API/remediations/$PLAN/submit"  -H "$H" -H 'Content-Type: application/json' -d '{"expected_version":1}' >/dev/null
curl -s -X POST "$API/remediations/$PLAN/approve" -H "Authorization: Bearer $OWNER" -H 'Content-Type: application/json' \
  -d '{"expected_version":2,"comment":"Approved."}' >/dev/null
curl -s -X POST "$API/remediations/$PLAN/execute" -H "$H" -H 'Content-Type: application/json' -d '{"expected_version":3}' | jq -r .state
# EXECUTING

sleep 15
curl -s "$API/remediations/$PLAN" -H "$H" | jq -c '{state, steps: [.steps[] | .status] | unique, exposed_after_actual}'
# {"state":"COMPLETED","steps":["succeeded"],"exposed_after_actual":0}

# the tenant really changed, and the flow really runs
curl -s -X POST "$SIM/_sim/flows/f02-payroll-export/test-run" | jq -r .status
# Succeeded
curl -s "$SIM/providers/Microsoft.ProcessSimple/environments/Default-7d3f0c1e/flows/f02-payroll-export?api-version=2016-11-01" \
  -H "Authorization: Bearer $SIMTOKEN" | jq -r '.properties.connectionReferences.shared_sharepointonline.connectionName'
# shared-sp-remediator

# rescan: the finding is gone and exposure dropped
curl -s -X POST $API/scans -H "$H" -H 'Content-Type: application/json' -d '{}' >/dev/null; sleep 30
AFTER=$(curl -s $API/metrics/summary -H "$H" | jq .exposure_pairs)
test "$AFTER" -lt "$BEFORE" && echo "exposure reduced"
# exposure reduced

# manual rollback restores the original tenant state
V=$(curl -s "$API/remediations/$PLAN" -H "$H" | jq .version)
curl -s -X POST "$API/remediations/$PLAN/rollback" -H "$H" -H 'Content-Type: application/json' \
  -d "{\"expected_version\":$V,\"reason\":\"Verification of rollback for milestone 6.\"}" >/dev/null
sleep 10
curl -s "$API/remediations/$PLAN" -H "$H" | jq -r .state
# ROLLED_BACK
curl -s $SIM/_sim/health | jq -r .state_checksum
# equals the checksum printed right after `make sim-reset`

# comparison for objective 4
curl -s -X POST $API/evaluation/naive-baseline -H "$H" | jq -c '{grants_removed, flows_broken}'
# {"grants_removed":12,"flows_broken":6}

make verify-m6
# includes the full 12-finding evaluation run: 0 flows broken, 10 of 10 succeeding

docker compose up -d db && DATABASE_URL=postgresql+psycopg://fyp:fyp@localhost:5432/fyp make verify-m6
# exit code 0
```

### Verify in the browser

1. As admin, open the approved payroll plan and press Execute. Type the site name to confirm. The seven steps turn green one at a time, and the state ends at COMPLETED with "Exposed before 44, after 0" (numbers match the API).
2. Open Flows. "Payroll export to bank folder" shows a new successful run and a connection labelled as the service principal.
3. Run a scan. The payroll finding is no longer in the open list, and the Overview trend chart shows a lower exposure value for the new scan.
4. Open the plan and press Roll back, give a reason. The steps show "compensated" in reverse order and the state ends at ROLLED_BACK. A new scan brings the finding back.
5. For a failure demonstration, inject a fault (`curl -X POST $SIM/_sim/faults -d '{"flow":"f04-contract-expiry","force_fail":true}' -H 'Content-Type: application/json'`), then plan, approve and execute the contracts finding. The timeline stops at PREFLIGHT_VERIFY in red, compensations run, the state ends at ROLLED_BACK, and the page states that the broad grant was never removed.
6. Open Evaluation. The table shows this platform at 0 broken flows and the naive baseline at 6 of 10, with the exposure figures before and after, and the CSV export downloads.

### Done when

`make verify-m6` passes on SQLite and PostgreSQL, the Playwright run is green, and the Evaluation page shows the three figures objective 4 needs: exposure before and after, broken flows for the platform, broken flows for the naive baseline.

## After milestone 6

These items are outside the six slices and can be claimed as future work or attempted if time allows.

- Run the read-only scan against a real tenant with `ADAPTER_MODE=live`, if a Microsoft 365 developer or trial tenant becomes available. Writes stay disabled.
- Scheduled scans and email digests for owners.
- Sensitivity detection from content rather than labels and tags.
- Recalibration of the scoring weights from survey and interview results.

## Risks to the schedule

| Risk | Effect | Response |
| --- | --- | --- |
| Simulator drifts from real Graph shapes | The adapter claim in the report weakens | Milestone 1 schema parity tests use schemas taken from Microsoft's published resource definitions; keep recorded real samples in `mock_data/tests/` when any become available |
| Supervisor does not accept a simulated tenant | Evaluation design changes | Raise it at the next meeting (already listed in the project brief); the live adapter and the read-only scan are the fallback evidence |
| The SharePoint connector's lack of service principal sign-in is questioned | The `service_principal` strategy looks unrealistic | A 1.1 documents the constraint; strategy `scoped_identity_grant` is implemented and tested in milestone 6 |
| LLM output is unreliable or no API budget exists | Milestone 5 stalls | The template provider is the default and passes all checks alone; a hosted or local model is optional |
| Flow parser misses a definition pattern | Wrong SAFE verdict | Unknown operations default to write, expressions default to UNKNOWN, and the milestone 4 oracle test compares predictions with actual simulator outcomes |
| Milestone 6 overruns | Rollback is incomplete at submission | Build order inside milestone 6: happy path, automatic rollback, manual rollback, recovery, PostgreSQL. Each is demonstrable without the next |
