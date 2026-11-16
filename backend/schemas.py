"""Pydantic models for the Microsoft Graph v1.0 driveItem `permission` resource
(plus the Power Automate flow properties we rely on)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Identity(_Strict):
    id: str
    displayName: str
    email: str | None = None


class SharePointIdentity(Identity):
    loginName: str | None = None


class SharePointIdentitySet(_Strict):
    user: Identity | None = None
    group: Identity | None = None
    application: Identity | None = None
    siteUser: SharePointIdentity | None = None
    siteGroup: SharePointIdentity | None = None

    @model_validator(mode="after")
    def _one_identity(self):
        if not any(v is not None for v in self.__dict__.values()):
            raise ValueError("identity set is empty")
        return self


class SharingLink(_Strict):
    type: Literal["view", "edit", "embed"]
    scope: Literal["anonymous", "organization", "users"]
    webUrl: str
    preventsDownload: bool = False


class ItemReference(_Strict):
    driveId: str
    id: str
    path: str


class Permission(_Strict):
    id: str
    roles: list[Literal["read", "write", "owner"]]
    grantedToV2: SharePointIdentitySet | None = None
    grantedToIdentitiesV2: list[SharePointIdentitySet] | None = None
    link: SharingLink | None = None
    inheritedFrom: ItemReference | None = None
    hasPassword: bool | None = None

    @model_validator(mode="after")
    def _has_grantee(self):
        if not self.roles:
            raise ValueError("roles must not be empty")
        if self.link is None and self.grantedToV2 is None and not self.grantedToIdentitiesV2:
            raise ValueError("permission needs a link or a grantee")
        return self


class FlowConnectionReference(_Strict):
    connectionName: str
    id: str
    displayName: str
    tier: str


class FlowProperties(BaseModel):
    model_config = ConfigDict(extra="allow")
    displayName: str
    state: Literal["Started", "Stopped", "Suspended"]
    connectionReferences: dict[str, FlowConnectionReference]
    definition: dict


class FlowResource(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    id: str
    type: Literal["Microsoft.ProcessSimple/environments/flows"]
    properties: FlowProperties


# ================================================================ Milestone 2 API schemas
Classification = Literal["BREAKAGE_CRITICAL", "SAFE_TO_REVOKE", "KEEP_REQUIRED"]
ViewRole = Literal["admin", "manager"]


class FlowDependencyOut(BaseModel):
    flow_id: str
    flow_name: str
    action_name: str
    operation_id: str
    required_role: str
    connection_identity: str
    connection_name: str | None
    is_critical_flow: bool
    mitigation: str


class ScanSummary(BaseModel):
    scan_id: str
    reference_time: datetime
    files_scanned: int
    permissions_scanned: int
    flows_analysed: int
    active_delegated_flows: int
    overshared_permissions: int
    overshared_files: int
    stale_permissions: int
    flagged_for_revocation: int
    by_classification: dict[str, int]
    flows_at_risk: list[str]


class AssessmentOut(BaseModel):
    id: int
    scan_id: str
    permission_id: str
    file_id: str
    file_name: str
    file_path: str
    site_name: str
    sensitivity_label: str
    is_copilot_indexed: bool
    drive_id: str
    principal_id: str
    principal_type: str
    principal_display: str
    roles: list[str]
    link_scope: str | None
    inherited_from: str | None = None  # Graph inheritedFrom.path; None for direct grants
    exposure: str | None
    risk_score: int
    risk_band: str
    score_breakdown: dict[str, int]
    reasons: list[str]
    is_overshared: bool
    is_stale: bool
    days_since_access: int | None
    classification: Classification
    dependent_flows: list[FlowDependencyOut]
    mitigation: str | None


class ManagerCard(BaseModel):
    """Plain-language explanation for a business owner. No raw permission ids."""
    id: int
    classification: Classification
    risk_level: str
    risk_score: int
    file_name: str
    site_name: str
    headline: str
    what_we_found: str
    why_it_matters: str
    recommended_action: str
    safe_to_fix_now: bool


class AssessmentList(BaseModel):
    scan_id: str
    role: ViewRole
    total: int
    items: list[AssessmentOut] | list[ManagerCard]


PlanState = Literal["DRAFT", "PENDING_APPROVAL", "APPROVED", "EXECUTING", "COMPLETED",
                    "REJECTED", "ROLLING_BACK", "ROLLED_BACK", "ROLLBACK_FAILED"]
Strategy = Literal["service_principal", "scoped_identity_grant"]


class RemediationCreate(BaseModel):
    assessment_id: int
    strategy: Strategy = "service_principal"
    created_by: str = "it-admin"


class ActorIn(BaseModel):
    """Who is acting. There is no authentication, so this is recorded as given."""
    actor: str = "it-admin"


class RemediationStepOut(BaseModel):
    seq: int
    action: str
    status: str
    before_state: dict | None
    result: dict | None
    error: str | None


class RemediationPlanOut(BaseModel):
    id: int
    state: PlanState
    assessment_id: int
    scan_id: str
    permission_id: str
    file_id: str
    file_name: str
    site_name: str
    principal_display: str
    classification: Classification
    risk_score: int
    dependent_flows: list[FlowDependencyOut]
    strategy: Strategy
    exposed_before: int | None
    exposed_after: int | None
    created_by: str
    approved_by: str | None
    executed_by: str | None
    created_at: datetime
    approved_at: datetime | None
    executed_at: datetime | None
    finished_at: datetime | None
    steps: list[RemediationStepOut]


class RemediationPlanList(BaseModel):
    total: int
    items: list[RemediationPlanOut]


class GraphRequestPreview(BaseModel):
    method: Literal["DELETE"]
    url: str
    path: str
    headers: dict[str, str]
    expected_status: int


class DryRunPreview(BaseModel):
    assessment_id: int
    scan_id: str
    classification: Classification
    dry_run: Literal[True] = True
    executed: Literal[False] = False
    blocked: bool
    request: GraphRequestPreview
    target: dict[str, str | None]
    warning: str | None
    breakage: list[FlowDependencyOut]
    preconditions: list[str]
