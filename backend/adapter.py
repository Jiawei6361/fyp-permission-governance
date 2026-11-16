"""Pluggable tenant data adapter. Pipeline code may only talk to `TenantAdapter`.

`SimulatorAdapter` owns the simulator database (`tenant_sim.db`) and serves the Lumira
tenant in Graph v1.0 / Power Automate shapes. It is stateful: the write methods change
what later `list_*` calls return, `run_flow` executes a flow against the current state,
and `reset()` puts the seeded dataset back.

`LiveGraphAdapter` is a placeholder with the same method list; live access is out of scope.

This module must not import `flow_mapper`: `run_flow` is the independent check that the
engine's dependency analysis is measured against.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from backend.models import TENANT_DB_PATH, Connection, File, Flow, Permission, User, make_engine
from backend.schemas import Permission as GraphPermission
from backend.seed import ALL_STAFF, SP_APP, build_dataset, permission_row, write_tenant_data

SHAREPOINT_API = "shared_sharepointonline"
CONNECTIONS_API = f"/providers/Microsoft.PowerApps/apis/{SHAREPOINT_API}"
# SharePoint connector operations that modify the file; every other operation only reads it.
_WRITE_OPERATIONS = frozenset({"UpdateFile", "CreateFile", "DeleteFile", "CopyFileAsync", "MoveFileAsync",
                               "PatchItem", "PostItem", "DeleteItem", "UpdateFileProperties"})
_EVERYONE_LOGIN = "spo-grid-all-users"


class TenantError(Exception):
    """A request the tenant rejects, carrying the HTTP status and Graph error code."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class TenantAdapter(ABC):
    # ---- reads
    @abstractmethod
    def list_users(self) -> list[dict]: ...

    @abstractmethod
    def list_files(self) -> list[dict]: ...

    @abstractmethod
    def list_item_permissions(self, file_id: str) -> list[dict]:
        """Graph v1.0 `GET /drives/{d}/items/{i}/permissions` value[] for one file."""

    @abstractmethod
    def list_item_activity(self, file_id: str) -> dict[str, datetime | None]:
        """Access log for one file: permission id -> when that grant was last used (None = never)."""

    @abstractmethod
    def list_flows(self) -> list[dict]:
        """Power Automate flow resources (with connectionReferences and definition)."""

    @abstractmethod
    def get_flow(self, flow_id: str) -> dict: ...

    @abstractmethod
    def list_connections(self) -> list[dict]:
        """Power Platform connection resources, one per connectionName.

        `properties` holds the identity the connection runs as: `authenticatedUser.id` (a user,
        delegated auth) or `servicePrincipal.id` (an application), and `authType` says which.
        """

    # ---- writes
    @abstractmethod
    def delete_item_permission(self, file_id: str, permission_id: str) -> None:
        """Graph v1.0 `DELETE /drives/{d}/items/{i}/permissions/{p}`."""

    @abstractmethod
    def add_item_grant(self, file_id: str, permission: dict, last_accessed_at: datetime | None = None) -> dict:
        """Create a direct permission on a file from a Graph permission body; returns the created resource."""

    @abstractmethod
    def update_flow_connection(self, flow_id: str, connection_name: str) -> dict:
        """Point the flow's SharePoint connection reference at another connection; returns the flow."""

    # ---- execution
    @abstractmethod
    def run_flow(self, flow_id: str) -> dict:
        """Run the flow once. Returns {"flow_id", "status": "Succeeded" | "Failed", "error"}."""


class SimulatorAdapter(TenantAdapter):
    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path or os.environ.get("FYP_TENANT_DB_PATH") or TENANT_DB_PATH)
        self._engine = make_engine(self.db_path)
        if "users" not in inspect(self._engine).get_table_names():
            self.reset()

    # ---------------------------------------------------------------- reads
    def list_users(self) -> list[dict]:
        with Session(self._engine) as s:
            return [{"id": u.id, "display_name": u.display_name, "email": u.email, "department": u.department,
                     "job_title": u.job_title, "is_active": u.is_active}
                    for u in s.scalars(select(User).order_by(User.id))]

    def list_files(self) -> list[dict]:
        with Session(self._engine) as s:
            return [{"id": f.id, "site_name": f.site_name, "file_name": f.file_name, "file_path": f.file_path,
                     "sensitivity_label": f.sensitivity_label, "is_copilot_indexed": f.is_copilot_indexed}
                    for f in s.scalars(select(File).order_by(File.id))]

    def list_item_permissions(self, file_id: str) -> list[dict]:
        with Session(self._engine) as s:
            return [copy.deepcopy(p.graph_json) for p in self._file_permissions(s, file_id)]

    def list_item_activity(self, file_id: str) -> dict[str, datetime | None]:
        with Session(self._engine) as s:
            return {p.id: p.last_accessed_at for p in self._file_permissions(s, file_id)}

    def list_flows(self) -> list[dict]:
        with Session(self._engine) as s:
            return [self._flow_resource(fl) for fl in s.scalars(select(Flow).order_by(Flow.id))]

    def get_flow(self, flow_id: str) -> dict:
        with Session(self._engine) as s:
            return self._flow_resource(self._flow(s, flow_id))

    def list_connections(self) -> list[dict]:
        with Session(self._engine) as s:
            return [self._connection_resource(c) for c in s.scalars(select(Connection).order_by(Connection.name))]

    # ---------------------------------------------------------------- writes
    def delete_item_permission(self, file_id: str, permission_id: str) -> None:
        with Session(self._engine) as s:
            p = s.get(Permission, permission_id)
            if p is None or p.file_id != file_id:
                raise TenantError(404, "itemNotFound", f"permission {permission_id} not found on item {file_id}")
            if p.inherited_from is not None:
                # Graph only deletes permissions whose inheritedFrom is null.
                raise TenantError(400, "invalidRequest", "an inherited permission cannot be deleted on the item")
            s.delete(p)
            s.commit()

    def add_item_grant(self, file_id: str, permission: dict, last_accessed_at: datetime | None = None) -> dict:
        body = copy.deepcopy(permission)
        body.setdefault("id", f"sim-{uuid4().hex}")
        if body.get("inheritedFrom"):
            raise TenantError(400, "invalidRequest", "an inherited permission cannot be created on the item")
        try:
            GraphPermission.model_validate(body)
            row = permission_row(body, file_id, last_accessed_at)
        except (ValidationError, ValueError) as exc:
            raise TenantError(400, "invalidRequest", str(exc)) from exc
        with Session(self._engine) as s:
            if s.get(File, file_id) is None:
                raise TenantError(404, "itemNotFound", f"item {file_id} not found")
            if s.get(Permission, body["id"]) is not None:
                raise TenantError(409, "nameAlreadyExists", f"permission {body['id']} already exists")
            s.add(Permission(**row, graph_json=body))
            s.commit()
        return copy.deepcopy(body)

    def update_flow_connection(self, flow_id: str, connection_name: str) -> dict:
        with Session(self._engine) as s:
            fl = self._flow(s, flow_id)
            conn = s.get(Connection, connection_name)
            if conn is None:
                raise TenantError(404, "ConnectionNotFound", f"connection {connection_name} not found")
            raw = copy.deepcopy(fl.raw_definition_json)
            refs = [r for k, r in raw["properties"]["connectionReferences"].items() if _is_sharepoint_ref(k, r)]
            if not refs:
                raise TenantError(400, "invalidRequest", f"flow {flow_id} has no SharePoint connection reference")
            for ref in refs:
                ref["connectionName"] = connection_name
            fl.raw_definition_json = raw  # reassigned so the JSON column is written
            fl.connection_type = conn.connection_type
            s.commit()
            return self._flow_resource(fl)

    # ---------------------------------------------------------------- execution
    def run_flow(self, flow_id: str) -> dict:
        """Succeeds only if every SharePoint action can reach its file with the role it needs.

        Evaluated against the current simulator state, action by action, as the connection
        identity. A service-principal connection holds a tenant-wide application permission,
        so it does not depend on item permissions. Flow state (Started/Stopped) is ignored:
        this is a manual test run.
        """
        with Session(self._engine) as s:
            fl = self._flow(s, flow_id)
            props = fl.raw_definition_json.get("properties") or {}
            refs = props.get("connectionReferences") or {}
            files_by_path = {f.file_path: f for f in s.scalars(select(File))}
            for name, action in _iter_actions((props.get("definition") or {}).get("actions") or {}):
                if action.get("type") != "OpenApiConnection":
                    continue
                inputs = action.get("inputs") or {}
                host = inputs.get("host") or {}
                ref = refs.get(host.get("connectionName"))
                if not (SHAREPOINT_API in str(host.get("apiId", "")) or (ref and _is_sharepoint_ref("", ref))):
                    continue
                conn = s.get(Connection, ref["connectionName"]) if ref else None
                if conn is None:
                    return _failed(flow_id, 401, "ConnectionNotFound", name, None,
                                   f"Action '{name}' has no usable SharePoint connection.")
                params = inputs.get("parameters") or {}
                # The connector stores the path URL-encoded twice; decoding a plain path changes nothing.
                path = unquote(unquote(params.get("path") or params.get("file") or ""))
                if "@{" in path or path.startswith("@"):
                    # A runtime expression. The simulator knows what it evaluates to: the flow's target file.
                    file = s.get(File, fl.target_file_id)
                else:
                    file = files_by_path.get(path) if path else s.get(File, params.get("id") or "")
                if file is None:
                    return _failed(flow_id, 404, "itemNotFound", name, None,
                                   f"Action '{name}' targets '{path}', which does not exist.")
                if conn.connection_type != "user":
                    continue
                user = s.get(User, conn.user_id)
                required = "write" if host.get("operationId") in _WRITE_OPERATIONS else "read"
                if not any(_grants(p.graph_json, user) and _role_ok(p.graph_json["roles"], required)
                           for p in self._file_permissions(s, file.id)):
                    return _failed(flow_id, 403, "accessDenied", name, file.id,
                                   f"Action '{name}' failed: 403 Forbidden. {user.display_name} ({user.id}) does not "
                                   f"have {required} access to '{file.file_path}'.")
            return {"flow_id": flow_id, "status": "Succeeded", "error": None}

    # ---------------------------------------------------------------- state control
    def reset(self) -> None:
        """Put the deterministic seeded dataset back, discarding every write."""
        write_tenant_data(self._engine, build_dataset())

    def state_checksum(self) -> str:
        """SHA-256 over the whole tenant state; equal checksums mean identical state."""
        with Session(self._engine) as s:
            perms = [{"file_id": p.file_id, "graph": p.graph_json,
                      "last_accessed_at": p.last_accessed_at.isoformat() if p.last_accessed_at else None}
                     for p in s.scalars(select(Permission).order_by(Permission.id))]
        state = {"users": self.list_users(), "files": self.list_files(), "permissions": perms,
                 "flows": self.list_flows(), "connections": self.list_connections()}
        return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _file_permissions(s: Session, file_id: str) -> list[Permission]:
        return list(s.scalars(select(Permission).where(Permission.file_id == file_id).order_by(Permission.id)))

    @staticmethod
    def _flow(s: Session, flow_id: str) -> Flow:
        fl = s.get(Flow, flow_id)
        if fl is None:
            raise TenantError(404, "FlowNotFound", f"flow {flow_id} not found")
        return fl

    @staticmethod
    def _flow_resource(fl: Flow) -> dict:
        # Business criticality has no Power Automate source; the simulator carries it as an annotation.
        return {**copy.deepcopy(fl.raw_definition_json), "simulatorAnnotations": {"isBusinessCritical": fl.is_critical}}

    @staticmethod
    def _connection_resource(c: Connection) -> dict:
        identity = ({"authenticatedUser": {"id": c.user_id}} if c.connection_type == "user"
                    else {"servicePrincipal": dict(SP_APP)})
        return {"name": c.name, "id": f"{CONNECTIONS_API}/connections/{c.name}",
                "type": "Microsoft.PowerApps/apis/connections",
                "properties": {"apiId": CONNECTIONS_API, "displayName": "SharePoint",
                               "authType": "oauth" if c.connection_type == "user" else "servicePrincipal",
                               **identity}}


# ---------------------------------------------------------------- run_flow access rules
def _is_sharepoint_ref(key: str, ref: dict) -> bool:
    return SHAREPOINT_API in key or SHAREPOINT_API in str(ref.get("id", ""))


def _iter_actions(actions: dict) -> Iterator[tuple[str, dict]]:
    """Every action, including those nested in scopes, conditions and switch cases."""
    for name, action in actions.items():
        yield name, action
        yield from _iter_actions(action.get("actions") or {})
        yield from _iter_actions((action.get("else") or {}).get("actions") or {})
        yield from _iter_actions((action.get("default") or {}).get("actions") or {})
        for case in (action.get("cases") or {}).values():
            yield from _iter_actions(case.get("actions") or {})


def _grants(perm: dict, user: User) -> bool:
    """Does this Graph permission resource let `user` open the file through a delegated connection?"""
    internal = user.department != "External"
    link = perm.get("link")
    if link:
        if link["scope"] == "organization":
            return internal
        if link["scope"] == "users":
            return any((i.get("user") or {}).get("id") == user.id for i in perm.get("grantedToIdentitiesV2") or [])
        return False  # an anonymous link is not redeemed by a signed-in connector session
    granted = perm.get("grantedToV2") or {}
    if granted.get("user"):
        return granted["user"]["id"] == user.id
    if granted.get("group"):
        gid = granted["group"]["id"]
        return gid == f"g-{user.department.lower()}" or (internal and gid == ALL_STAFF)
    if granted.get("siteUser"):
        return internal and _EVERYONE_LOGIN in str(granted["siteUser"].get("loginName", ""))
    return False


def _role_ok(roles: list[str], required: str) -> bool:
    return bool({"write", "owner"} & set(roles)) if required == "write" else bool(roles)


def _failed(flow_id: str, status: int, code: str, action: str, file_id: str | None, message: str) -> dict:
    return {"flow_id": flow_id, "status": "Failed",
            "error": {"status": status, "code": code, "action": action, "file_id": file_id, "message": message}}


class LiveGraphAdapter(TenantAdapter):
    def _nope(self, *_a, **_k):
        raise NotImplementedError("LiveGraphAdapter is a stub: live tenant access is not implemented")

    list_users = list_files = list_item_permissions = list_item_activity = _nope
    list_flows = get_flow = list_connections = _nope
    delete_item_permission = add_item_grant = update_flow_connection = _nope
    run_flow = reset = state_checksum = _nope


def get_adapter(mode: str = "simulator") -> TenantAdapter:
    return {"simulator": SimulatorAdapter, "live": LiveGraphAdapter}[mode]()
