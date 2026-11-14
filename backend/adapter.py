"""Pluggable tenant data adapter. Pipeline code may only talk to `TenantAdapter`.

`SimulatorAdapter` serves the seeded Lumira dataset in Graph v1.0 / Power Automate shapes.
`LiveGraphAdapter` is a placeholder: live access is out of scope for Milestone 1.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class TenantAdapter(ABC):
    @abstractmethod
    def list_users(self) -> list[dict]: ...

    @abstractmethod
    def list_files(self) -> list[dict]: ...

    @abstractmethod
    def list_item_permissions(self, file_id: str) -> list[dict]:
        """Graph v1.0 `GET /drives/{d}/items/{i}/permissions` value[] for one file."""

    @abstractmethod
    def list_flows(self) -> list[dict]:
        """Power Automate flow resources (with connectionReferences and definition)."""

    @abstractmethod
    def get_flow(self, flow_id: str) -> dict: ...


class SimulatorAdapter(TenantAdapter):
    def __init__(self, dataset: dict | None = None):
        from backend.seed import build_dataset  # local import: seed imports models, not adapter

        ds = dataset or build_dataset()
        self._users = ds["users"]
        self._files = ds["files"]
        self._flows = {f["id"]: f["raw_definition_json"] for f in ds["flows"]}
        self._perms: dict[str, list[dict]] = {}
        for p in ds["permissions"]:
            self._perms.setdefault(p["file_id"], []).append(p["graph"])

    def list_users(self) -> list[dict]:
        return list(self._users)

    def list_files(self) -> list[dict]:
        return list(self._files)

    def list_item_permissions(self, file_id: str) -> list[dict]:
        return list(self._perms.get(file_id, []))

    def list_flows(self) -> list[dict]:
        return list(self._flows.values())

    def get_flow(self, flow_id: str) -> dict:
        return self._flows[flow_id]


class LiveGraphAdapter(TenantAdapter):
    def _nope(self, *_a, **_k):
        raise NotImplementedError("LiveGraphAdapter is not implemented in Milestone 1")

    list_users = list_files = list_item_permissions = list_flows = get_flow = _nope


def get_adapter(mode: str = "simulator") -> TenantAdapter:
    return {"simulator": SimulatorAdapter, "live": LiveGraphAdapter}[mode]()
