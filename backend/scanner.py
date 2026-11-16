"""Context-aware oversharing scanner and deterministic risk scoring (Milestone 2).

Every permission is normalised into `PermissionFacts` from the Graph v1.0 facets
(`grantedToV2`, `roles`, `link.scope`, `inheritedFrom`) plus the access-log timestamp
`last_accessed_at`, then scored 0-100 with the explicit weights in `WEIGHTS`.

Two independent revocation candidates come out of a scan:
  * overshared  - a broad grant (anonymous link, organization link, Everyone-except-external
                  or an org-wide group) whose risk score is >= OVERSHARE_THRESHOLD.
  * stale       - a direct (non-inherited) user grant unused for > STALE_DAYS or never used.

Whether a candidate is actually safe to revoke is decided by flow_mapper.py.

Tenant data comes only from a `TenantAdapter` (`load_snapshot`); this module never opens
the tenant database.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from backend.adapter import TenantAdapter
from backend.seed import permission_row

SENSITIVE_LABELS = frozenset({"Highly Confidential", "Confidential", "Restricted", "PII"})
EVERYONE = "everyone_except_external"
ORG_WIDE_GROUPS = frozenset({"g-all-staff"})
ELEVATED_ROLES = frozenset({"write", "owner"})

WEIGHTS: dict[str, int] = {
    "anonymous_link": 45,     # link.scope == anonymous
    "organization_link": 35,  # link.scope == organization
    "org_wide_group": 30,     # Everyone except external users / All Staff group
    "sensitive_label": 25,    # sensitivity_label in SENSITIVE_LABELS
    "copilot_indexed": 15,    # Copilot-indexed AND sensitive (Copilot surfacing public content is not a risk)
    "stale_access": 15,       # last_accessed_at older than STALE_DAYS or null
    "write_on_broad": 10,     # write/owner role on a broad grant
}
OVERSHARE_THRESHOLD = 50
STALE_DAYS = 90
MAX_SCORE = 100


@dataclass(frozen=True)
class FileFacts:
    id: str
    site_name: str
    file_name: str
    file_path: str
    sensitivity_label: str
    is_copilot_indexed: bool

    @property
    def drive_id(self) -> str:
        # Each simulated site has one document library; mirrors inheritedFrom.driveId in seed.py.
        return f"drv-{self.site_name}"

    @classmethod
    def from_adapter(cls, f: dict) -> "FileFacts":
        return cls(f["id"], f["site_name"], f["file_name"], f["file_path"], f["sensitivity_label"],
                   bool(f["is_copilot_indexed"]))


@dataclass(frozen=True)
class UserFacts:
    id: str
    display_name: str
    department: str
    is_active: bool


@dataclass
class FlowFacts:
    """One Power Automate flow, with its connection resolved to an identity."""
    id: str
    flow_name: str
    owner_user_id: str | None        # properties.creator
    target_file_id: str | None       # first file a SharePoint action resolves to
    connection_type: str             # user | service_principal
    connection_user_id: str | None   # identity the SharePoint connection runs as; None for a service principal
    is_critical: bool
    raw_definition_json: dict


@dataclass(frozen=True)
class PermissionFacts:
    permission_id: str
    file_id: str
    principal_id: str
    principal_type: str  # user | group | link | everyone_except_external | application
    roles: tuple[str, ...]
    link_scope: str | None
    inherited_from: str | None
    last_accessed_at: datetime | None

    @classmethod
    def from_graph(cls, payload: dict, file_id: str, last_accessed_at: datetime | None) -> "PermissionFacts":
        """Build facts straight from a Graph v1.0 permission resource (same mapping the seeder uses)."""
        r = permission_row(payload, file_id, last_accessed_at)
        return cls(r["id"], file_id, r["principal_id"], r["principal_type"], tuple(r["roles_json"]),
                   r["link_scope"], r["inherited_from"], r["last_accessed_at"])


@dataclass
class RiskResult:
    permission: PermissionFacts
    file: FileFacts
    score: int
    breakdown: dict[str, int]
    exposure: str | None
    is_overshared: bool
    is_stale: bool
    days_since_access: int | None
    reasons: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.is_overshared or self.is_stale


def broad_exposure(p: PermissionFacts) -> str | None:
    if p.link_scope == "anonymous":
        return "anonymous_link"
    if p.link_scope == "organization":
        return "organization_link"
    if p.principal_type == EVERYONE or (p.principal_type == "group" and p.principal_id in ORG_WIDE_GROUPS):
        return "org_wide_group"
    return None


def score_permission(p: PermissionFacts, f: FileFacts, now: datetime) -> RiskResult:
    breakdown: dict[str, int] = {}
    reasons: list[str] = []
    exposure = broad_exposure(p)
    if exposure:
        breakdown[exposure] = WEIGHTS[exposure]
        reasons.append({"anonymous_link": "Anonymous sharing link: anyone with the URL can open it",
                        "organization_link": "Organization-wide sharing link",
                        "org_wide_group": "Granted to an organization-wide principal"}[exposure])
    sensitive = f.sensitivity_label in SENSITIVE_LABELS
    if sensitive:
        breakdown["sensitive_label"] = WEIGHTS["sensitive_label"]
        reasons.append(f"Sensitivity label '{f.sensitivity_label}'")
        if f.is_copilot_indexed:
            breakdown["copilot_indexed"] = WEIGHTS["copilot_indexed"]
            reasons.append("Indexed by Microsoft 365 Copilot, so it can surface in AI answers")
    days = None if p.last_accessed_at is None else (now - p.last_accessed_at).days
    stale_access = days is None or days > STALE_DAYS
    if stale_access:
        breakdown["stale_access"] = WEIGHTS["stale_access"]
        reasons.append("Never accessed" if days is None else f"Not accessed for {days} days")
    if exposure and ELEVATED_ROLES & set(p.roles):
        breakdown["write_on_broad"] = WEIGHTS["write_on_broad"]
        reasons.append("Broad grant carries edit rights")
    score = min(MAX_SCORE, sum(breakdown.values()))
    is_overshared = exposure is not None and score >= OVERSHARE_THRESHOLD
    # Inherited grants cannot be revoked on the item itself, so only direct user grants are stale candidates.
    is_stale = p.principal_type == "user" and p.inherited_from is None and stale_access
    return RiskResult(p, f, score, breakdown, exposure, is_overshared, is_stale, days, reasons)


@dataclass
class TenantSnapshot:
    files: dict[str, FileFacts]
    permissions: list[PermissionFacts]
    flows: list[FlowFacts]
    users: dict[str, UserFacts]

    @property
    def permissions_by_file(self) -> dict[str, list[PermissionFacts]]:
        out: dict[str, list[PermissionFacts]] = {}
        for p in self.permissions:
            out.setdefault(p.file_id, []).append(p)
        return out


def load_files(adapter: TenantAdapter) -> dict[str, FileFacts]:
    return {f["id"]: FileFacts.from_adapter(f) for f in sorted(adapter.list_files(), key=lambda f: f["id"])}


def load_users(adapter: TenantAdapter) -> dict[str, UserFacts]:
    return {u["id"]: UserFacts(u["id"], u["display_name"], u["department"], bool(u["is_active"]))
            for u in adapter.list_users()}


def _first_file_id(node, files_by_path: dict[str, str]) -> str | None:
    """Depth-first search of a flow definition for the first `path` parameter naming a known file."""
    if isinstance(node, dict):
        path = node.get("path")
        if isinstance(path, str) and path in files_by_path:
            return files_by_path[path]
        node = list(node.values())
    if isinstance(node, list):
        return next((hit for child in node if (hit := _first_file_id(child, files_by_path))), None)
    return None


def _flow_facts(resource: dict, connections: dict[str, dict], files_by_path: dict[str, str]) -> FlowFacts:
    props = resource.get("properties") or {}
    ref = next((r for k, r in (props.get("connectionReferences") or {}).items()
                if "shared_sharepointonline" in k or "shared_sharepointonline" in str(r.get("id", ""))), {})
    conn = (connections.get(ref.get("connectionName")) or {}).get("properties") or {}
    user_id = (conn.get("authenticatedUser") or {}).get("id")
    return FlowFacts(
        id=resource["name"], flow_name=props.get("displayName", resource["name"]),
        owner_user_id=(props.get("creator") or {}).get("userId"),
        target_file_id=_first_file_id(props.get("definition") or {}, files_by_path),
        connection_type="user" if user_id else "service_principal", connection_user_id=user_id,
        is_critical=bool((resource.get("simulatorAnnotations") or {}).get("isBusinessCritical")),
        raw_definition_json=resource)


def load_snapshot(adapter: TenantAdapter) -> TenantSnapshot:
    """Read the whole tenant through the adapter, building facts from the Graph payloads."""
    files = load_files(adapter)
    perms: list[PermissionFacts] = []
    for file_id in files:
        last_access = adapter.list_item_activity(file_id)
        perms.extend(PermissionFacts.from_graph(g, file_id, last_access.get(g["id"]))
                     for g in sorted(adapter.list_item_permissions(file_id), key=lambda g: g["id"]))
    connections = {c["name"]: c for c in adapter.list_connections()}
    files_by_path = {f.file_path: f.id for f in files.values()}
    flows = [_flow_facts(r, connections, files_by_path) for r in sorted(adapter.list_flows(), key=lambda r: r["name"])]
    return TenantSnapshot(files, perms, flows, load_users(adapter))


def scan_permissions(snapshot: TenantSnapshot, now: datetime) -> list[RiskResult]:
    return [score_permission(p, snapshot.files[p.file_id], now) for p in snapshot.permissions]


def risk_band(score: int) -> str:
    return "High" if score >= 75 else "Medium" if score >= OVERSHARE_THRESHOLD else "Low"
