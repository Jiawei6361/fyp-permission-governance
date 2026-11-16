"""Power Automate flow dependency detector and remediation-safety classifier (Milestone 2).

The detector uses only what the tenant serves: the flow resource and the connection
resources. For every flow it

  * finds the identity the SharePoint actions run as by following
    `properties.connectionReferences` -> `connectionName` -> connection -> identity;
  * resolves the file of every SharePoint OpenApiConnection action (including actions
    nested in scopes, conditions and switch cases) from its path parameter, URL-decoded
    twice because the SharePoint connector double-encodes it;
  * works out which permissions give the connection identity enough access to run it.

An action whose file cannot be worked out (no path, a runtime expression such as `@{...}`,
or a path that matches no scanned file) is recorded as *unresolved*: nothing is guessed.

A flagged permission is
  * UNKNOWN_DEPENDENCY when an active flow on the same site has an unresolved action, so the
    flow may or may not need it. This takes precedence over BREAKAGE_CRITICAL;
  * BREAKAGE_CRITICAL  when revoking all candidates would leave a flow action with no
    sufficient access path;
  * SAFE_TO_REVOKE     otherwise.
Service-principal connections do not depend on item permissions and are ignored.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import unquote

from backend.scanner import (EVERYONE, ORG_WIDE_GROUPS, FlowFacts, PermissionFacts, RiskResult, TenantSnapshot,
                             UserFacts)

SHAREPOINT_API = "shared_sharepointonline"
WRITE_OPERATIONS = frozenset({"UpdateFile", "CreateFile", "DeleteFile", "CopyFileAsync", "MoveFileAsync",
                              "PatchItem", "PostItem", "DeleteItem", "UpdateFileProperties"})
MITIGATION = "Migrate flow connection to Service Principal before revoking user access"
UNKNOWN_MITIGATION = ("Confirm which files the flow's unresolved action touches (run history or the flow owner) "
                      "before revoking")

BREAKAGE_CRITICAL = "BREAKAGE_CRITICAL"
UNKNOWN_DEPENDENCY = "UNKNOWN_DEPENDENCY"
SAFE_TO_REVOKE = "SAFE_TO_REVOKE"
KEEP_REQUIRED = "KEEP_REQUIRED"
CLASSIFICATIONS = (BREAKAGE_CRITICAL, UNKNOWN_DEPENDENCY, SAFE_TO_REVOKE, KEEP_REQUIRED)

USER, SERVICE_PRINCIPAL, UNKNOWN_IDENTITY = "user", "service_principal", "unknown"

_SITE = re.compile(r"/sites/([^/?#]+)")


@dataclass(frozen=True)
class FlowAction:
    action_name: str
    operation_id: str
    file_id: str | None            # None when unresolved
    file_path: str | None          # the path parameter after decoding
    site_name: str | None          # from the `dataset` site URL (or the path); None if neither names a site
    required_role: str             # read | write
    unresolved_reason: str | None  # why file_id is None

    @property
    def is_resolved(self) -> bool:
        return self.file_id is not None


@dataclass
class FlowProfile:
    flow_id: str
    flow_name: str
    state: str
    is_critical: bool
    connection_type: str           # user | service_principal | unknown (connection not found)
    connection_name: str | None
    identity_user_id: str | None   # only for a delegated (user) connection
    actions: list[FlowAction]

    @property
    def is_active(self) -> bool:
        return self.state == "Started"

    @property
    def uses_delegated_identity(self) -> bool:
        return self.identity_user_id is not None

    @property
    def unresolved_actions(self) -> list[FlowAction]:
        return [a for a in self.actions if not a.is_resolved]


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
    unresolved_reason: str | None = None  # set when the action's file could not be worked out

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
        yield from _walk_actions((action.get("else") or {}).get("actions") or {})
        yield from _walk_actions((action.get("default") or {}).get("actions") or {})
        for case in (action.get("cases") or {}).values():
            yield from _walk_actions(case.get("actions") or {})


def decode_path(value: str) -> str:
    """The SharePoint connector stores path values URL-encoded twice; a plain path is left unchanged."""
    return unquote(unquote(value))


def _is_expression(value: str) -> bool:
    """A workflow expression (`@{...}` inline, or a whole-value `@...`) is only known at run time."""
    return "@{" in value or value.startswith("@")


def _site_name(*values: object) -> str | None:
    for value in values:
        match = _SITE.search(decode_path(value)) if isinstance(value, str) else None
        if match and not _is_expression(match.group(1)):
            return match.group(1)
    return None


def _resolve_file(params: dict, files_by_path: dict[str, str]) -> tuple[str | None, str | None, str | None]:
    """(file id, decoded path, reason it is unresolved). Never guesses."""
    raw = next((params[k] for k in ("path", "file", "id") if isinstance(params.get(k), str) and params[k]), None)
    if raw is None:
        return None, None, "the action has no file path parameter"
    path = decode_path(raw)
    if _is_expression(path):
        return None, path, "the file path is an expression that is only known when the flow runs"
    if path in files_by_path:
        return files_by_path[path], path, None
    if raw in files_by_path.values():  # an item id instead of a path
        return raw, path, None
    return None, path, "the file path does not match any scanned file"


def connection_identity(connection: dict | None) -> tuple[str, str | None]:
    """(connection type, user id) of a Power Platform connection resource."""
    props = (connection or {}).get("properties") or {}
    user_id = (props.get("authenticatedUser") or {}).get("id")
    if user_id:
        return USER, user_id
    if props.get("servicePrincipal"):
        return SERVICE_PRINCIPAL, None
    return UNKNOWN_IDENTITY, None


def parse_flow(flow: FlowFacts, connections: dict[str, dict], files_by_path: dict[str, str]) -> FlowProfile:
    """Build a flow's profile from its resource and the tenant's connection resources only."""
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
        file_id, path, reason = _resolve_file(params, files_by_path)
        op = host.get("operationId", "")
        actions.append(FlowAction(name, op, file_id, path, _site_name(params.get("dataset"), path),
                                  "write" if op in WRITE_OPERATIONS else "read", reason))

    # connectionReferences -> connectionName -> connection -> identity
    conn_name = next(iter(sp_refs.values()), None)
    conn_type, identity = connection_identity(connections.get(conn_name)) if conn_name else (UNKNOWN_IDENTITY, None)
    return FlowProfile(flow.id, flow.flow_name, props.get("state", "Unknown"), bool(flow.is_critical),
                       conn_type, conn_name, identity, actions)


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


@dataclass
class DependencyMap:
    profiles: list[FlowProfile]
    breaking: dict[str, list[FlowDependency]]           # candidate permission id -> flows it would break
    required: dict[str, list[FlowDependency]]           # kept permission id -> flows it is the sole path of
    unresolved: dict[str | None, list[FlowDependency]]  # site name (None = site unknown) -> unresolved actions


def map_dependencies(snapshot: TenantSnapshot, candidate_ids: set[str]) -> DependencyMap:
    files_by_path = {f.file_path: f.id for f in snapshot.files.values()}
    perms_by_file = snapshot.permissions_by_file
    out = DependencyMap([parse_flow(fl, snapshot.connections, files_by_path) for fl in snapshot.flows], {}, {}, {})
    for prof in out.profiles:
        if not prof.is_active or prof.connection_type == SERVICE_PRINCIPAL:
            continue
        user = snapshot.users.get(prof.identity_user_id) if prof.identity_user_id else None
        for act in prof.actions:
            reason = act.unresolved_reason or (None if user else "the flow's connection identity could not be resolved")
            if reason:
                out.unresolved.setdefault(act.site_name, []).append(FlowDependency(
                    prof.flow_id, prof.flow_name, act.action_name, act.operation_id, act.required_role,
                    user.id if user else UNKNOWN_IDENTITY, prof.connection_name, prof.is_critical,
                    UNKNOWN_MITIGATION, reason))
                continue
            paths = [p for p in perms_by_file.get(act.file_id, [])
                     if grants_access(p, user) and role_sufficient(p, act.required_role)]
            dep = FlowDependency(prof.flow_id, prof.flow_name, act.action_name, act.operation_id,
                                 act.required_role, user.id, prof.connection_name, prof.is_critical)
            surviving = [p for p in paths if p.permission_id not in candidate_ids]
            if not surviving:
                for p in paths:  # every candidate path is needed once the others are revoked too
                    out.breaking.setdefault(p.permission_id, []).append(dep)
            if len(paths) == 1 and paths[0].permission_id not in candidate_ids:
                out.required.setdefault(paths[0].permission_id, []).append(dep)
    return out


# ---------------------------------------------------------------- classification
@dataclass
class Assessed:
    risk: RiskResult
    classification: str
    dependencies: list[FlowDependency]
    mitigation: str | None


def classify(results: list[RiskResult], snapshot: TenantSnapshot) -> tuple[list[Assessed], list[FlowProfile]]:
    candidates = {r.permission.permission_id for r in results if r.flagged}
    deps = map_dependencies(snapshot, candidates)
    tenant_wide = deps.unresolved.get(None, [])  # unresolved actions whose site is not known either
    out: list[Assessed] = []
    for r in results:
        pid = r.permission.permission_id
        unknown = deps.unresolved.get(r.file.site_name, []) + tenant_wide
        if r.flagged and unknown:
            # Proven dependencies first, then the flows that could not be analysed.
            out.append(Assessed(r, UNKNOWN_DEPENDENCY, deps.breaking.get(pid, []) + unknown, UNKNOWN_MITIGATION))
        elif r.flagged and pid in deps.breaking:
            out.append(Assessed(r, BREAKAGE_CRITICAL, deps.breaking[pid], MITIGATION))
        elif r.flagged:
            out.append(Assessed(r, SAFE_TO_REVOKE, [], None))
        else:
            out.append(Assessed(r, KEEP_REQUIRED, deps.required.get(pid, []), None))
    return out, deps.profiles
