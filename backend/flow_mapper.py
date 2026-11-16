"""Power Automate flow dependency detector and remediation-safety classifier (Milestone 2).

For every active flow that runs on a delegated (user) SharePoint connection, the detector
parses `raw_definition_json` (connectionReferences / $connections and every SharePoint
OpenApiConnection action, including actions nested in scopes and conditions), resolves the
file each action touches, and works out which permissions give the connection identity
enough access to run the action.

A revocation candidate is BREAKAGE_CRITICAL when revoking all candidates would leave a
flow action with no sufficient access path. Service-principal connections do not depend on
user permissions and are ignored.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from backend.scanner import (EVERYONE, ORG_WIDE_GROUPS, FlowFacts, PermissionFacts, RiskResult, TenantSnapshot,
                             UserFacts)

SHAREPOINT_API = "shared_sharepointonline"
WRITE_OPERATIONS = frozenset({"UpdateFile", "CreateFile", "DeleteFile", "CopyFileAsync", "MoveFileAsync",
                              "PatchItem", "PostItem", "DeleteItem", "UpdateFileProperties"})
MITIGATION = "Migrate flow connection to Service Principal before revoking user access"

BREAKAGE_CRITICAL = "BREAKAGE_CRITICAL"
SAFE_TO_REVOKE = "SAFE_TO_REVOKE"
KEEP_REQUIRED = "KEEP_REQUIRED"
CLASSIFICATIONS = (BREAKAGE_CRITICAL, SAFE_TO_REVOKE, KEEP_REQUIRED)


@dataclass(frozen=True)
class FlowAction:
    action_name: str
    operation_id: str
    file_id: str | None
    file_path: str | None
    required_role: str  # read | write


@dataclass
class FlowProfile:
    flow_id: str
    flow_name: str
    state: str
    is_critical: bool
    connection_type: str
    connection_name: str | None
    identity_user_id: str | None  # None for service-principal connections
    actions: list[FlowAction]

    @property
    def is_active(self) -> bool:
        return self.state == "Started"

    @property
    def uses_delegated_identity(self) -> bool:
        return self.identity_user_id is not None


@dataclass(frozen=True)
class FlowDependency:
    flow_id: str
    flow_name: str
    action_name: str
    operation_id: str
    required_role: str
    connection_identity: str
    connection_name: str | None
    is_critical_flow: bool
    mitigation: str = MITIGATION

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- definition parsing
def _sharepoint_connection_keys(props: dict) -> dict[str, str]:
    """Map connection-reference key -> connectionName for SharePoint references."""
    refs: dict[str, dict] = dict(props.get("connectionReferences") or {})
    conns = ((props.get("definition") or {}).get("parameters") or {}).get("$connections") or {}
    refs.update((conns.get("value") or {}) if isinstance(conns, dict) else {})
    return {k: v.get("connectionName") for k, v in refs.items()
            if SHAREPOINT_API in k or SHAREPOINT_API in str(v.get("id", "")) or SHAREPOINT_API in str(v.get("apiId", ""))}


def _walk_actions(actions: dict):
    for name, action in (actions or {}).items():
        yield name, action
        yield from _walk_actions(action.get("actions") or {})
        else_branch = action.get("else") or {}
        yield from _walk_actions(else_branch.get("actions") or {})
        for case in (action.get("cases") or {}).values():
            yield from _walk_actions(case.get("actions") or {})


def parse_flow(flow: FlowFacts, files_by_path: dict[str, str]) -> FlowProfile:
    raw = flow.raw_definition_json
    props = raw.get("properties", {})
    sp_refs = _sharepoint_connection_keys(props)
    actions: list[FlowAction] = []
    for name, action in _walk_actions((props.get("definition") or {}).get("actions") or {}):
        if action.get("type") != "OpenApiConnection":
            continue
        inputs = action.get("inputs") or {}
        host = inputs.get("host") or {}
        ref_key = host.get("connectionName") or (host.get("connection") or {}).get("name", "")
        if SHAREPOINT_API not in str(host.get("apiId", "")) and ref_key not in sp_refs:
            continue
        params = inputs.get("parameters") or {}
        path = params.get("path") or params.get("file")
        file_id = files_by_path.get(path) if path else None
        if file_id is None and params.get("id") in files_by_path.values():
            file_id = params["id"]
        op = host.get("operationId", "")
        actions.append(FlowAction(name, op, file_id, path, "write" if op in WRITE_OPERATIONS else "read"))
    # Fallback: a definition we cannot resolve still depends on its declared target file.
    if not any(a.file_id for a in actions):
        actions.append(FlowAction("(unresolved action)", "", flow.target_file_id, None, "read"))

    sp_conn_name = next(iter(sp_refs.values()), None)
    # A delegated connection runs as the user it is signed in as; a service principal has no user identity.
    identity = flow.connection_user_id if flow.connection_type == "user" else None
    return FlowProfile(flow.id, flow.flow_name, props.get("state", "Unknown"), bool(flow.is_critical),
                       flow.connection_type, sp_conn_name, identity, actions)


# ---------------------------------------------------------------- access-path analysis
def grants_access(p: PermissionFacts, user: UserFacts) -> bool:
    """Does permission `p` give `user` access to its file? Mirrors the ground-truth access model."""
    internal = user.department != "External"
    if p.principal_type == "user":
        return p.principal_id == user.id
    if p.principal_type == "group":
        return p.principal_id == f"g-{user.department.lower()}" or (internal and p.principal_id in ORG_WIDE_GROUPS)
    if p.principal_type == EVERYONE:
        return internal
    if p.principal_type == "link":
        # Anonymous links are not used by a delegated connector session.
        return internal and p.link_scope == "organization"
    return False


def role_sufficient(p: PermissionFacts, required: str) -> bool:
    return bool({"write", "owner"} & set(p.roles)) if required == "write" else bool(p.roles)


def map_dependencies(snapshot: TenantSnapshot, candidate_ids: set[str]
                     ) -> tuple[list[FlowProfile], dict[str, list[FlowDependency]], dict[str, list[FlowDependency]]]:
    """Return (flow profiles, breaking deps of candidates, sole-path deps of non-candidates)."""
    files_by_path = {f.file_path: f.id for f in snapshot.files.values()}
    perms_by_file = snapshot.permissions_by_file
    profiles = [parse_flow(fl, files_by_path) for fl in snapshot.flows]
    breaking: dict[str, list[FlowDependency]] = {}
    required: dict[str, list[FlowDependency]] = {}
    for prof in profiles:
        if not (prof.is_active and prof.uses_delegated_identity):
            continue
        user = snapshot.users.get(prof.identity_user_id)
        if user is None:
            continue
        for act in prof.actions:
            if act.file_id is None:
                continue
            paths = [p for p in perms_by_file.get(act.file_id, [])
                     if grants_access(p, user) and role_sufficient(p, act.required_role)]
            dep = FlowDependency(prof.flow_id, prof.flow_name, act.action_name, act.operation_id,
                                 act.required_role, user.id, prof.connection_name, prof.is_critical)
            surviving = [p for p in paths if p.permission_id not in candidate_ids]
            if not surviving:
                for p in paths:  # every candidate path is needed once the others are revoked too
                    breaking.setdefault(p.permission_id, []).append(dep)
            if len(paths) == 1 and paths[0].permission_id not in candidate_ids:
                required.setdefault(paths[0].permission_id, []).append(dep)
    return profiles, breaking, required


# ---------------------------------------------------------------- classification
@dataclass
class Assessed:
    risk: RiskResult
    classification: str
    dependencies: list[FlowDependency]
    mitigation: str | None


def classify(results: list[RiskResult], snapshot: TenantSnapshot) -> tuple[list[Assessed], list[FlowProfile]]:
    candidates = {r.permission.permission_id for r in results if r.flagged}
    profiles, breaking, required = map_dependencies(snapshot, candidates)
    out: list[Assessed] = []
    for r in results:
        pid = r.permission.permission_id
        if r.flagged and pid in breaking:
            out.append(Assessed(r, BREAKAGE_CRITICAL, breaking[pid], MITIGATION))
        elif r.flagged:
            out.append(Assessed(r, SAFE_TO_REVOKE, [], None))
        else:
            out.append(Assessed(r, KEEP_REQUIRED, required.get(pid, []), None))
    return out, profiles
