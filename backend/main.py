"""FastAPI app: scan, assessment listing, non-destructive dry-run preview, remediation plans
(approval, guarded execution, rollback), benchmark results, and CORS for the Vite dashboard.

Run from the project root:  py -m uvicorn backend.main:app --reload

The dry-run endpoint only describes a Graph request. Only executing or rolling back a
remediation plan (`backend/remediation.py`) changes the tenant, and only through the adapter.

Two stores: the app database (`assessments`, opened here) and the tenant, which is reached
only through the `TenantAdapter` held in `app.state.adapter`.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from backend.adapter import SimulatorAdapter, TenantAdapter
from backend.flow_mapper import BREAKAGE_CRITICAL, KEEP_REQUIRED, SAFE_TO_REVOKE, classify
from backend import remediation
from backend.models import DB_PATH, Assessment, RemediationPlan, init_db, make_engine
from backend.scanner import (EVERYONE, OVERSHARE_THRESHOLD, SENSITIVE_LABELS, STALE_DAYS, WEIGHTS, FileFacts,
                     UserFacts, load_files, load_snapshot, load_users, risk_band, scan_permissions)
from backend.schemas import (ActorIn, AssessmentList, AssessmentOut, Classification, DryRunPreview,
                     GraphRequestPreview, ManagerCard, PlanState, RemediationCreate, RemediationPlanList,
                     RemediationPlanOut, RemediationStepOut, ScanSummary, ViewRole)
from backend.seed import NOW as REFERENCE_TIME

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
BENCHMARK_PATH = Path(__file__).resolve().parent / "benchmark_results.json"
# Vite dev server (Milestone 3 dashboard). FYP_CORS_ORIGINS (comma-separated) overrides.
DEFAULT_CORS_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")


# ---------------------------------------------------------------- app / session wiring
def create_app(db_path: Path | str | None = None, adapter: TenantAdapter | None = None) -> FastAPI:
    """`db_path` is the app database. `adapter` defaults to the simulator (FYP_TENANT_DB_PATH or tenant_sim.db)."""
    db_path = db_path or os.environ.get("FYP_DB_PATH") or DB_PATH
    engine = make_engine(db_path)
    init_db(engine)  # adds `assessments` if missing
    app = FastAPI(title="Lumira Oversharing Governance API", version="0.2.0")
    app.state.sessionmaker = sessionmaker(engine, expire_on_commit=False)
    app.state.adapter = adapter or SimulatorAdapter()
    origins = os.environ.get("FYP_CORS_ORIGINS")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in origins.split(",")] if origins else list(DEFAULT_CORS_ORIGINS),
        allow_methods=["GET", "POST"], allow_headers=["*"])
    _register_routes(app)
    return app


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


# ---------------------------------------------------------------- scan
def run_scan(session: Session, adapter: TenantAdapter, now: datetime = REFERENCE_TIME) -> ScanSummary:
    snapshot = load_snapshot(adapter)
    assessed, profiles = classify(scan_permissions(snapshot, now), snapshot)
    scan_id = f"scan-{uuid4().hex[:12]}"
    scanned_at = datetime.now(UTC).replace(tzinfo=None)
    session.add_all(
        Assessment(
            scan_id=scan_id, scanned_at=scanned_at, reference_time=now,
            permission_id=a.risk.permission.permission_id, file_id=a.risk.file.id, drive_id=a.risk.file.drive_id,
            principal_id=a.risk.permission.principal_id, principal_type=a.risk.permission.principal_type,
            roles_json=list(a.risk.permission.roles), link_scope=a.risk.permission.link_scope,
            exposure=a.risk.exposure, risk_score=a.risk.score, score_breakdown=a.risk.breakdown,
            reasons=a.risk.reasons, is_overshared=a.risk.is_overshared, is_stale=a.risk.is_stale,
            days_since_access=a.risk.days_since_access, classification=a.classification,
            dependent_flows=[d.to_dict() for d in a.dependencies], mitigation=a.mitigation)
        for a in assessed)
    session.commit()
    counts = Counter(a.classification for a in assessed)
    return ScanSummary(
        scan_id=scan_id, reference_time=now,
        files_scanned=len(snapshot.files), permissions_scanned=len(snapshot.permissions),
        flows_analysed=len(profiles),
        active_delegated_flows=sum(p.is_active and p.uses_delegated_identity for p in profiles),
        overshared_permissions=sum(a.risk.is_overshared for a in assessed),
        overshared_files=len({a.risk.file.id for a in assessed if a.risk.is_overshared}),
        stale_permissions=sum(a.risk.is_stale for a in assessed),
        flagged_for_revocation=sum(a.risk.flagged for a in assessed),
        by_classification={c: counts.get(c, 0) for c in (BREAKAGE_CRITICAL, SAFE_TO_REVOKE, KEEP_REQUIRED)},
        flows_at_risk=sorted({d.flow_id for a in assessed if a.classification == BREAKAGE_CRITICAL
                              for d in a.dependencies}),
    )


def _latest_scan_id(session: Session) -> str | None:
    row = session.execute(select(Assessment.scan_id).order_by(Assessment.id.desc()).limit(1)).first()
    return row[0] if row else None


# ---------------------------------------------------------------- presentation helpers
def _principal_display(a: Assessment, users: dict[str, UserFacts]) -> str:
    if a.principal_type == "user":
        u = users.get(a.principal_id)
        return u.display_name if u else a.principal_id
    if a.principal_type == EVERYONE:
        return "Everyone except external users"
    if a.principal_type == "application":
        return f"Service principal ({a.principal_id})"
    if a.principal_type == "link":
        return {"anonymous": "Anyone with the link (no sign-in)",
                "organization": "Anyone in Lumira with the link"}.get(a.link_scope or "", "Specific people with the link")
    if a.principal_id == "g-all-staff":
        return "All Staff"
    return f"{a.principal_id.removeprefix('g-').title()} Team"


def _to_out(a: Assessment, f: FileFacts, users: dict[str, UserFacts], inherited_from: str | None = None) -> AssessmentOut:
    return AssessmentOut(
        id=a.id, scan_id=a.scan_id, permission_id=a.permission_id, file_id=a.file_id, file_name=f.file_name,
        file_path=f.file_path, site_name=f.site_name, sensitivity_label=f.sensitivity_label,
        is_copilot_indexed=f.is_copilot_indexed, drive_id=a.drive_id, principal_id=a.principal_id,
        principal_type=a.principal_type, principal_display=_principal_display(a, users), roles=a.roles_json,
        link_scope=a.link_scope, inherited_from=inherited_from, exposure=a.exposure, risk_score=a.risk_score, risk_band=risk_band(a.risk_score),
        score_breakdown=a.score_breakdown, reasons=a.reasons, is_overshared=a.is_overshared, is_stale=a.is_stale,
        days_since_access=a.days_since_access, classification=a.classification,
        dependent_flows=a.dependent_flows, mitigation=a.mitigation)


_AUDIENCE = {
    "anonymous_link": "anyone on the internet who has the link, without signing in",
    "organization_link": "anyone at Lumira who has the link",
    "org_wide_group": "the whole company",
}


def _manager_card(a: Assessment, f: FileFacts, users: dict[str, UserFacts]) -> ManagerCard:
    who = _principal_display(a, users)
    flows = ", ".join(f"'{d['flow_name']}'" for d in a.dependent_flows)
    if a.is_overshared:
        headline = f"'{f.file_name}' ({f.sensitivity_label}) is open to {_AUDIENCE[a.exposure]}"
        why = "People with no business need can open this file."
        if f.is_copilot_indexed and f.sensitivity_label in SENSITIVE_LABELS:
            why += " Because Copilot indexes it, its contents can also appear in AI-generated answers."
    elif a.is_stale:
        idle = "has never opened it" if a.days_since_access is None else f"has not opened it in {a.days_since_access} days"
        headline = f"{who} can still open '{f.file_name}' but {idle}"
        why = ("Unused access is a standing risk: if the account is compromised or the person has changed "
               "role, the file is exposed for no business benefit.")
    else:
        headline = f"{who} has normal, in-use access to '{f.file_name}'"
        why = "This access matches how the file is used today."
    if a.classification == SAFE_TO_REVOKE:
        action = "Remove this access. No automated workflow depends on it, so nothing will break."
    elif a.classification == BREAKAGE_CRITICAL:
        action = (f"Do not remove this access yet. The automated workflow {flows} needs it to run. "
                  "IT will first move that workflow onto a dedicated service account, then remove the access.")
    elif a.dependent_flows:
        action = f"Keep this access. The automated workflow {flows} relies on it."
    else:
        action = "No action needed."
    found = "; ".join(a.reasons) if a.reasons else "No risk factors found."
    return ManagerCard(id=a.id, classification=a.classification, risk_level=risk_band(a.risk_score),
                       risk_score=a.risk_score, file_name=f.file_name, site_name=f.site_name, headline=headline,
                       what_we_found=found + ".", why_it_matters=why, recommended_action=action,
                       safe_to_fix_now=a.classification == SAFE_TO_REVOKE)


def _get_assessment(session: Session, adapter: TenantAdapter, assessment_id: int) -> tuple[Assessment, FileFacts]:
    a = session.get(Assessment, assessment_id)
    if a is None:
        raise HTTPException(404, f"assessment {assessment_id} not found")
    return a, load_files(adapter)[a.file_id]


def _inherited_paths(adapter: TenantAdapter, file_ids: set[str]) -> dict[str, str]:
    """permission id -> inheritedFrom.path, for the inherited permissions on these files."""
    return {p["id"]: p["inheritedFrom"]["path"] for file_id in file_ids
            for p in adapter.list_item_permissions(file_id) if p.get("inheritedFrom")}


def _plan_out(plan: RemediationPlan, session: Session, files: dict[str, FileFacts],
              users: dict[str, UserFacts]) -> RemediationPlanOut:
    a = session.get(Assessment, plan.assessment_id)
    f = files[plan.file_id]
    return RemediationPlanOut(
        id=plan.id, state=plan.state, assessment_id=a.id, scan_id=a.scan_id, permission_id=plan.permission_id,
        file_id=plan.file_id, file_name=f.file_name, site_name=f.site_name,
        principal_display=_principal_display(a, users), classification=a.classification, risk_score=a.risk_score,
        dependent_flows=a.dependent_flows, strategy=plan.strategy, exposed_before=plan.exposed_before,
        exposed_after=plan.exposed_after, created_by=plan.created_by, approved_by=plan.approved_by,
        executed_by=plan.executed_by, created_at=plan.created_at, approved_at=plan.approved_at,
        executed_at=plan.executed_at, finished_at=plan.finished_at,
        steps=[RemediationStepOut(seq=s.seq, action=s.action, status=s.status, before_state=s.before_state,
                                  result=s.result, error=s.error) for s in plan.steps])


# ---------------------------------------------------------------- routes
def _register_routes(app: FastAPI) -> None:
    adapter: TenantAdapter = app.state.adapter

    @app.get("/api/config/scoring")
    def scoring_config() -> dict:
        return {"weights": WEIGHTS, "overshare_threshold": OVERSHARE_THRESHOLD, "stale_days": STALE_DAYS,
                "sensitive_labels": sorted(SENSITIVE_LABELS), "reference_time": REFERENCE_TIME}

    @app.get("/api/benchmark")
    def benchmark() -> dict:
        """Serves the output of evaluate_benchmark.py (baseline vs proposed engine)."""
        if not BENCHMARK_PATH.exists():
            raise HTTPException(404, "benchmark_results.json not found; run py backend/evaluate_benchmark.py")
        return json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))

    @app.post("/api/scan/run", response_model=ScanSummary)
    def scan_run(session: Session = Depends(get_db)) -> ScanSummary:
        return run_scan(session, adapter)

    @app.get("/api/assessments", response_model=AssessmentList)
    def list_assessments(
        classification: Classification | None = Query(None),
        role: ViewRole = Query("admin"),
        scan_id: str | None = Query(None, description="defaults to the latest scan"),
        session: Session = Depends(get_db),
    ) -> AssessmentList:
        scan_id = scan_id or _latest_scan_id(session)
        if scan_id is None:
            raise HTTPException(404, "no scan has been run yet; POST /api/scan/run first")
        stmt = select(Assessment).where(Assessment.scan_id == scan_id)
        if classification:
            stmt = stmt.where(Assessment.classification == classification)
        rows = list(session.scalars(stmt.order_by(Assessment.risk_score.desc(), Assessment.id)))
        if not rows and session.scalar(select(func.count()).where(Assessment.scan_id == scan_id)) == 0:
            raise HTTPException(404, f"scan {scan_id} not found")
        files, users = load_files(adapter), load_users(adapter)
        if role == "manager":
            items = [_manager_card(a, files[a.file_id], users) for a in rows]
        else:
            inherited = _inherited_paths(adapter, {a.file_id for a in rows})
            items = [_to_out(a, files[a.file_id], users, inherited.get(a.permission_id)) for a in rows]
        return AssessmentList(scan_id=scan_id, role=role, total=len(rows), items=items)

    @app.get("/api/assessments/{assessment_id}", response_model=AssessmentOut)
    def get_assessment(assessment_id: int, session: Session = Depends(get_db)) -> AssessmentOut:
        a, f = _get_assessment(session, adapter, assessment_id)
        return _to_out(a, f, load_users(adapter), _inherited_paths(adapter, {a.file_id}).get(a.permission_id))

    @app.post("/api/assessments/{assessment_id}/dry-run", response_model=DryRunPreview)
    def dry_run(assessment_id: int, session: Session = Depends(get_db)) -> DryRunPreview:
        a, f = _get_assessment(session, adapter, assessment_id)
        path = f"/drives/{a.drive_id}/items/{a.file_id}/permissions/{a.permission_id}"
        flows = ", ".join(f"'{d['flow_name']}' ({d['flow_id']}, action {d['action_name']})" for d in a.dependent_flows)
        if a.classification == BREAKAGE_CRITICAL:
            warning = (f"BLOCKED: revoking this permission would break active Power Automate flow(s) {flows}. "
                       f"{a.mitigation}.")
            pre = [f"{d['mitigation']} (flow {d['flow_id']})" for d in a.dependent_flows]
        elif a.classification == KEEP_REQUIRED:
            warning = "BLOCKED: this permission is not flagged for revocation (legitimate active access)."
            if a.dependent_flows:
                warning += f" It is the only access path for flow(s) {flows}."
            pre = []
        else:
            warning, pre = None, []
        return DryRunPreview(
            assessment_id=a.id, scan_id=a.scan_id, classification=a.classification,
            blocked=a.classification != SAFE_TO_REVOKE,
            request=GraphRequestPreview(method="DELETE", url=GRAPH_BASE + path, path=path,
                                        headers={"Authorization": "Bearer <redacted>"}, expected_status=204),
            target={"drive_id": a.drive_id, "item_id": a.file_id, "permission_id": a.permission_id,
                    "file_path": f.file_path, "principal_id": a.principal_id, "principal_type": a.principal_type},
            warning=warning, breakage=a.dependent_flows if a.classification == BREAKAGE_CRITICAL else [],
            preconditions=pre)

    # ---- remediation plans (these are the only routes that change the tenant)
    def plan_response(plan: RemediationPlan, session: Session) -> RemediationPlanOut:
        return _plan_out(plan, session, load_files(adapter), load_users(adapter))

    def plan_action(plan_id: int, session: Session, action) -> RemediationPlanOut:
        plan = session.get(RemediationPlan, plan_id)
        if plan is None:
            raise HTTPException(404, f"remediation plan {plan_id} not found")
        try:
            action(plan)
        except remediation.RemediationError as exc:
            raise HTTPException(exc.status, exc.message) from exc
        return plan_response(plan, session)

    @app.post("/api/remediations", response_model=RemediationPlanOut, status_code=201)
    def create_remediation(body: RemediationCreate, session: Session = Depends(get_db)) -> RemediationPlanOut:
        a = session.get(Assessment, body.assessment_id)
        if a is None:
            raise HTTPException(404, f"assessment {body.assessment_id} not found")
        try:
            plan = remediation.create_plan(session, a, body.strategy, body.created_by)
        except remediation.RemediationError as exc:
            raise HTTPException(exc.status, exc.message) from exc
        return plan_response(plan, session)

    @app.get("/api/remediations", response_model=RemediationPlanList)
    def list_remediations(state: PlanState | None = Query(None), session: Session = Depends(get_db)) -> RemediationPlanList:
        stmt = select(RemediationPlan).order_by(RemediationPlan.id.desc())
        if state:
            stmt = stmt.where(RemediationPlan.state == state)
        files, users = load_files(adapter), load_users(adapter)
        items = [_plan_out(p, session, files, users) for p in session.scalars(stmt)]
        return RemediationPlanList(total=len(items), items=items)

    @app.get("/api/remediations/{plan_id}", response_model=RemediationPlanOut)
    def get_remediation(plan_id: int, session: Session = Depends(get_db)) -> RemediationPlanOut:
        return plan_action(plan_id, session, lambda plan: None)

    @app.post("/api/remediations/{plan_id}/submit", response_model=RemediationPlanOut)
    def submit_remediation(plan_id: int, session: Session = Depends(get_db)) -> RemediationPlanOut:
        return plan_action(plan_id, session, lambda plan: remediation.submit_plan(session, plan))

    @app.post("/api/remediations/{plan_id}/approve", response_model=RemediationPlanOut)
    def approve_remediation(plan_id: int, body: ActorIn | None = None,
                            session: Session = Depends(get_db)) -> RemediationPlanOut:
        actor = (body or ActorIn()).actor
        return plan_action(plan_id, session, lambda plan: remediation.approve_plan(session, plan, actor))

    @app.post("/api/remediations/{plan_id}/reject", response_model=RemediationPlanOut)
    def reject_remediation(plan_id: int, session: Session = Depends(get_db)) -> RemediationPlanOut:
        return plan_action(plan_id, session, lambda plan: remediation.reject_plan(session, plan))

    @app.post("/api/remediations/{plan_id}/execute", response_model=RemediationPlanOut)
    def execute_remediation(plan_id: int, body: ActorIn | None = None,
                            session: Session = Depends(get_db)) -> RemediationPlanOut:
        """Runs the five steps now. The response state is COMPLETED, ROLLED_BACK or ROLLBACK_FAILED."""
        actor = (body or ActorIn()).actor
        return plan_action(plan_id, session, lambda plan: remediation.execute_plan(session, adapter, plan, actor))

    @app.post("/api/remediations/{plan_id}/rollback", response_model=RemediationPlanOut)
    def rollback_remediation(plan_id: int, session: Session = Depends(get_db)) -> RemediationPlanOut:
        return plan_action(plan_id, session, lambda plan: remediation.rollback_plan(session, adapter, plan))


app = create_app()
