"""Remediation plans: approval workflow, guarded execution and rollback (simulator only).

A plan removes one flagged permission without breaking the flows that depend on it. It is a
saga of five steps, always in this order:

  1. SNAPSHOT            save the permission payload and each dependent flow's connection
  2. PROTECT_FLOW        give each dependent flow another way to reach the file
  3. PREFLIGHT           every dependent flow must run successfully
  4. REMOVE_BROAD_GRANT  delete the permission (the only step that removes access)
  5. POSTFLIGHT          every dependent flow still runs and the permission is gone

A flow whose action could not be analysed (an UNKNOWN_DEPENDENCY plan) is not changed in step 2,
because there is nothing known to protect, but steps 3 and 5 still run it. If removing the
permission breaks it, step 5 fails and the permission is put back.

Step 4 never runs unless step 3 succeeded. If any step fails, the completed steps are undone
in reverse order from their saved `before_state`. A COMPLETED plan can be rolled back by hand.

All tenant access goes through the `TenantAdapter`; plans and steps live in the app database.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.adapter import TenantAdapter
from backend.flow_mapper import UNKNOWN_DEPENDENCY
from backend.models import Assessment, RemediationPlan, RemediationStep
from backend.seed import NOW as REFERENCE_TIME

# ---- plan states
DRAFT, PENDING_APPROVAL, APPROVED, EXECUTING, COMPLETED = "DRAFT", "PENDING_APPROVAL", "APPROVED", "EXECUTING", "COMPLETED"
REJECTED, ROLLING_BACK, ROLLED_BACK, ROLLBACK_FAILED = "REJECTED", "ROLLING_BACK", "ROLLED_BACK", "ROLLBACK_FAILED"
OPEN_STATES = (DRAFT, PENDING_APPROVAL, APPROVED, EXECUTING, ROLLING_BACK)

# ---- steps
SNAPSHOT, PROTECT_FLOW, PREFLIGHT, REMOVE_BROAD_GRANT, POSTFLIGHT = (
    "SNAPSHOT", "PROTECT_FLOW", "PREFLIGHT", "REMOVE_BROAD_GRANT", "POSTFLIGHT")
STEP_ORDER = (SNAPSHOT, PROTECT_FLOW, PREFLIGHT, REMOVE_BROAD_GRANT, POSTFLIGHT)
PENDING, SUCCEEDED, FAILED, SKIPPED = "PENDING", "SUCCEEDED", "FAILED", "SKIPPED"

# ---- strategies for PROTECT_FLOW
SERVICE_PRINCIPAL, SCOPED_IDENTITY_GRANT = "service_principal", "scoped_identity_grant"
STRATEGIES = (SERVICE_PRINCIPAL, SCOPED_IDENTITY_GRANT)

SHAREPOINT_API = "shared_sharepointonline"


class RemediationError(Exception):
    """A request the workflow refuses; `status` is the HTTP status the API returns."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class StepFailed(Exception):
    """A step did not achieve its goal; execution stops and the plan is rolled back."""


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ---------------------------------------------------------------- workflow
def create_plan(session: Session, assessment: Assessment, strategy: str, actor: str,
                override_reason: str | None = None) -> RemediationPlan:
    if strategy not in STRATEGIES:
        raise RemediationError(422, f"unknown strategy '{strategy}'")
    override_reason = (override_reason or "").strip() or None
    if assessment.classification == UNKNOWN_DEPENDENCY and override_reason is None:
        raise RemediationError(422, "this permission has an unknown flow dependency; an override_reason is "
                                    "required to create a remediation plan for it")
    if not (assessment.is_overshared or assessment.is_stale):
        raise RemediationError(409, "this permission is not flagged for revocation, so there is nothing to remediate")
    clash = session.scalar(select(RemediationPlan).where(RemediationPlan.permission_id == assessment.permission_id,
                                                         RemediationPlan.state.in_(OPEN_STATES)))
    if clash is not None:
        raise RemediationError(409, f"plan {clash.id} for this permission is already open ({clash.state})")
    plan = RemediationPlan(state=DRAFT, assessment_id=assessment.id, permission_id=assessment.permission_id,
                           file_id=assessment.file_id, strategy=strategy, override_reason=override_reason,
                           created_by=actor, created_at=_utcnow())
    plan.steps = [RemediationStep(seq=i, action=action, status=PENDING) for i, action in enumerate(STEP_ORDER, 1)]
    session.add(plan)
    session.commit()
    return plan


def _move(plan: RemediationPlan, allowed_from: str, to: str, verb: str) -> None:
    if plan.state != allowed_from:
        raise RemediationError(409, f"cannot {verb} a plan in state {plan.state}; it must be {allowed_from}")
    plan.state = to


def submit_plan(session: Session, plan: RemediationPlan) -> RemediationPlan:
    _move(plan, DRAFT, PENDING_APPROVAL, "submit")
    session.commit()
    return plan


def approve_plan(session: Session, plan: RemediationPlan, actor: str) -> RemediationPlan:
    _move(plan, PENDING_APPROVAL, APPROVED, "approve")
    plan.approved_by, plan.approved_at = actor, _utcnow()
    session.commit()
    return plan


def reject_plan(session: Session, plan: RemediationPlan) -> RemediationPlan:
    _move(plan, PENDING_APPROVAL, REJECTED, "reject")
    plan.finished_at = _utcnow()
    session.commit()
    return plan


# ---------------------------------------------------------------- execution
def execute_plan(session: Session, adapter: TenantAdapter, plan: RemediationPlan, actor: str,
                 now: datetime = REFERENCE_TIME) -> RemediationPlan:
    """Run the five steps in order. Ends COMPLETED, or ROLLED_BACK / ROLLBACK_FAILED if a step fails."""
    _move(plan, APPROVED, EXECUTING, "execute")
    plan.executed_by, plan.executed_at = actor, _utcnow()
    session.commit()
    run = _Run(session, adapter, plan, now)
    for step in plan.steps:
        try:
            run.handlers[step.action](step)
        except Exception as exc:  # noqa: BLE001 - any failure, including a tenant error, triggers the rollback
            step.status, step.error = FAILED, str(exc)
            for later in plan.steps:
                if later.status == PENDING:
                    later.status = SKIPPED
            session.commit()
            return _roll_back(session, adapter, plan)
        step.status = SUCCEEDED
        session.commit()
    plan.state, plan.finished_at = COMPLETED, _utcnow()
    session.commit()
    return plan


def rollback_plan(session: Session, adapter: TenantAdapter, plan: RemediationPlan) -> RemediationPlan:
    """Manual rollback of a COMPLETED plan: restore the permission and the flows' connections."""
    if plan.state != COMPLETED:
        raise RemediationError(409, f"cannot roll back a plan in state {plan.state}; it must be {COMPLETED}")
    return _roll_back(session, adapter, plan)


class _Run:
    """The step handlers for one execution of one plan."""

    def __init__(self, session: Session, adapter: TenantAdapter, plan: RemediationPlan, now: datetime):
        self.session, self.adapter, self.plan, self.now = session, adapter, plan, now
        assessment = session.get(Assessment, plan.assessment_id)
        # flow id -> role its actions need on the file ("write" wins over "read"): the flows to protect
        self.flows: dict[str, str] = {}
        # every flow to run in PREFLIGHT and POSTFLIGHT, including those that could not be analysed
        self.watched: list[str] = []
        for dep in assessment.dependent_flows:
            if dep["flow_id"] not in self.watched:
                self.watched.append(dep["flow_id"])
            if dep.get("unresolved_reason"):
                continue  # nothing known to protect; it is only run
            if self.flows.get(dep["flow_id"]) != "write":
                self.flows[dep["flow_id"]] = dep["required_role"]
        self.handlers = {SNAPSHOT: self.snapshot, PROTECT_FLOW: self.protect_flow, PREFLIGHT: self.preflight,
                         REMOVE_BROAD_GRANT: self.remove_broad_grant, POSTFLIGHT: self.postflight}

    def _step(self, action: str) -> RemediationStep:
        return next(s for s in self.plan.steps if s.action == action)

    def _connections(self) -> dict[str, dict]:
        return {c["name"]: c["properties"] for c in self.adapter.list_connections()}

    # ---- 1
    def snapshot(self, step: RemediationStep) -> None:
        file_id, pid = self.plan.file_id, self.plan.permission_id
        permission = next((p for p in self.adapter.list_item_permissions(file_id) if p["id"] == pid), None)
        if permission is None:
            raise StepFailed(f"permission {pid} is no longer on item {file_id}; run a new scan")
        last = self.adapter.list_item_activity(file_id).get(pid)
        step.before_state = {
            "file_id": file_id, "permission": permission,
            "last_accessed_at": last.isoformat() if last else None,
            "flow_connections": {fid: _sharepoint_connection(self.adapter.get_flow(fid)) for fid in self.flows},
        }

    # ---- 2
    def protect_flow(self, step: RemediationStep) -> None:
        done: list[dict] = []

        def record(entry: dict) -> None:
            """Persist what was changed straight after each tenant write, so a partial step can be undone."""
            if entry not in done:
                done.append(entry)
            step.before_state = {"flows": [dict(e) for e in done]}
            self.session.commit()

        step.before_state = {"flows": []}
        connections = self._connections()
        for flow_id, role in self.flows.items():
            current = _sharepoint_connection(self.adapter.get_flow(flow_id))
            entry = {"flow_id": flow_id, "previous_connection": current, "rebound_to": None, "added_permission_id": None}
            if self.plan.strategy == SERVICE_PRINCIPAL:
                sp_name, sp = next(((n, c["servicePrincipal"]) for n, c in connections.items() if "servicePrincipal" in c),
                                   (None, None))
                if sp is None:
                    raise StepFailed("the tenant has no service principal connection to migrate flows onto")
                if current != sp_name:
                    self.adapter.update_flow_connection(flow_id, sp_name)
                    entry["rebound_to"] = sp_name
                    record(entry)
                grantee = {"application": {"id": sp["id"], "displayName": sp["displayName"]}}
            else:
                user_id = ((connections.get(current) or {}).get("authenticatedUser") or {}).get("id")
                if user_id is None:  # already on a service principal: no user identity to grant
                    record(entry)
                    continue
                user = next(u for u in self.adapter.list_users() if u["id"] == user_id)
                grantee = {"user": {"id": user["id"], "displayName": user["display_name"], "email": user["email"]}}
            if not self._has_direct_grant(grantee, role):
                created = self.adapter.add_item_grant(self.plan.file_id, {"roles": [role], "grantedToV2": grantee},
                                                      last_accessed_at=self.now)
                entry["added_permission_id"] = created["id"]
            record(entry)

    def _has_direct_grant(self, grantee: dict, role: str) -> bool:
        """Is there already a direct grant to this identity, other than the one being removed, with enough role?"""
        kind, identity = next(iter(grantee.items()))
        for p in self.adapter.list_item_permissions(self.plan.file_id):
            if p["id"] == self.plan.permission_id or p.get("inheritedFrom") or p.get("link"):
                continue
            if ((p.get("grantedToV2") or {}).get(kind) or {}).get("id") == identity["id"] \
                    and (role == "read" or {"write", "owner"} & set(p["roles"])):
                return True
        return False

    # ---- 3 and 5
    def _run_flows(self, step: RemediationStep) -> list[str]:
        runs = [self.adapter.run_flow(fid) for fid in self.watched]
        step.result = {"runs": runs}
        return [f"{r['flow_id']}: {r['error']['message']}" for r in runs if r["status"] != "Succeeded"]

    def preflight(self, step: RemediationStep) -> None:
        failures = self._run_flows(step)
        if failures:
            raise StepFailed("preflight run failed, the permission was not removed. " + " ".join(failures))

    # ---- 4
    def remove_broad_grant(self, step: RemediationStep) -> None:
        if self._step(PREFLIGHT).status != SUCCEEDED:  # the rule: never remove access before preflight passes
            raise StepFailed("REMOVE_BROAD_GRANT refused: PREFLIGHT has not succeeded")
        saved = self._step(SNAPSHOT).before_state
        self.adapter.delete_item_permission(saved["file_id"], saved["permission"]["id"])
        step.before_state = {k: saved[k] for k in ("file_id", "permission", "last_accessed_at")}

    def postflight(self, step: RemediationStep) -> None:
        failures = self._run_flows(step)
        still_there = any(p["id"] == self.plan.permission_id
                          for p in self.adapter.list_item_permissions(self.plan.file_id))
        step.result = {**step.result, "permission_removed": not still_there}
        if still_there:
            failures.append(f"permission {self.plan.permission_id} is still on the item")
        if failures:
            raise StepFailed("postflight check failed. " + " ".join(failures))


# ---------------------------------------------------------------- rollback
def _roll_back(session: Session, adapter: TenantAdapter, plan: RemediationPlan) -> RemediationPlan:
    """Undo every tenant change the plan made, newest first. Keeps going after an undo error."""
    plan.state = ROLLING_BACK
    session.commit()
    clean = True
    for step in reversed(plan.steps):
        undo = {REMOVE_BROAD_GRANT: _undo_remove, PROTECT_FLOW: _undo_protect}.get(step.action)
        # A failed PROTECT_FLOW may have changed some flows before failing; its undo log says which.
        if undo is None or not step.before_state or step.status not in (SUCCEEDED, FAILED):
            continue
        try:
            undo(adapter, plan, step.before_state)
            if step.status == SUCCEEDED:
                step.status = ROLLED_BACK
        except Exception as exc:  # noqa: BLE001
            clean = False
            step.status = ROLLBACK_FAILED
            step.error = f"{step.error + ' | ' if step.error else ''}rollback failed: {exc}"
        session.commit()
    plan.state, plan.finished_at = (ROLLED_BACK if clean else ROLLBACK_FAILED), _utcnow()
    session.commit()
    return plan


def _undo_remove(adapter: TenantAdapter, plan: RemediationPlan, before: dict) -> None:
    last = before["last_accessed_at"]
    adapter.add_item_grant(before["file_id"], before["permission"],
                           last_accessed_at=datetime.fromisoformat(last) if last else None)


def _undo_protect(adapter: TenantAdapter, plan: RemediationPlan, before: dict) -> None:
    for entry in reversed(before["flows"]):
        if entry["added_permission_id"]:
            adapter.delete_item_permission(plan.file_id, entry["added_permission_id"])
        if entry["rebound_to"]:
            adapter.update_flow_connection(entry["flow_id"], entry["previous_connection"])


def _sharepoint_connection(flow: dict) -> str | None:
    refs = (flow.get("properties") or {}).get("connectionReferences") or {}
    return next((r["connectionName"] for k, r in refs.items()
                 if SHAREPOINT_API in k or SHAREPOINT_API in str(r.get("id", ""))), None)
