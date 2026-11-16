"""Stateful simulator: writes, run_flow, reset/checksum, and scan parity through the adapter."""
from __future__ import annotations

import inspect as pyinspect
import json
from pathlib import Path

import pytest
from sqlalchemy import inspect

from backend import seed
from backend.adapter import LiveGraphAdapter, SimulatorAdapter, TenantAdapter, TenantError
from backend.flow_mapper import classify
from backend.models import make_engine
from backend.scanner import load_snapshot, scan_permissions
from backend.seed import SP_CONNECTION

GOLDEN = Path(__file__).parent / "golden_classifications.json"


def _public_methods(cls) -> set[str]:
    return {n for n, _ in pyinspect.getmembers(cls, callable) if not n.startswith("_")}


def _sole_direct(truth) -> dict:
    return next(x for x in truth["workflow_breaking_permissions"] if x["kind"] == "sole_direct_grant")


# ---------------------------------------------------------------- run_flow
def test_every_flow_succeeds_on_the_seeded_tenant(adapter):
    runs = [adapter.run_flow(f["name"]) for f in adapter.list_flows()]
    assert len(runs) == 25
    assert all(r["status"] == "Succeeded" and r["error"] is None for r in runs)


def test_deleting_sole_permission_of_flow_owner_makes_run_flow_fail(adapter, truth):
    for x in truth["workflow_breaking_permissions"]:  # 8 direct grants and 4 broad grants
        (flow_id,) = x["flow_ids"]
        assert adapter.run_flow(flow_id)["status"] == "Succeeded"
        adapter.delete_item_permission(x["file_id"], x["permission_id"])
        run = adapter.run_flow(flow_id)
        assert run["status"] == "Failed"
        assert run["error"]["status"] == 403 and run["error"]["code"] == "accessDenied"
        assert run["error"]["action"] == "Process_file" and run["error"]["file_id"] == x["file_id"]
        assert "403" in run["error"]["message"]


def test_deleting_a_stale_safe_permission_breaks_no_flow(adapter, truth):
    for x in truth["stale_safe_to_revoke"]:
        adapter.delete_item_permission(x["file_id"], x["permission_id"])
    assert all(adapter.run_flow(f["name"])["status"] == "Succeeded" for f in adapter.list_flows())


def test_write_action_needs_a_write_role(adapter, truth):
    x = next(x for x in truth["workflow_breaking_permissions"] if x["kind"] == "sole_direct_grant"
             and adapter.get_flow(x["flow_ids"][0])["properties"]["definition"]["actions"]["Process_file"]
             ["inputs"]["host"]["operationId"] == "UpdateFile")
    grant = next(p for p in adapter.list_item_permissions(x["file_id"]) if p["id"] == x["permission_id"])
    adapter.delete_item_permission(x["file_id"], x["permission_id"])
    adapter.add_item_grant(x["file_id"], {**grant, "roles": ["read"]})
    assert adapter.run_flow(x["flow_ids"][0])["error"]["status"] == 403
    adapter.delete_item_permission(x["file_id"], x["permission_id"])
    adapter.add_item_grant(x["file_id"], grant)
    assert adapter.run_flow(x["flow_ids"][0])["status"] == "Succeeded"


def test_moving_flow_to_service_principal_survives_revocation(adapter, truth):
    x = _sole_direct(truth)
    (flow_id,) = x["flow_ids"]
    flow = adapter.update_flow_connection(flow_id, SP_CONNECTION)
    assert flow["properties"]["connectionReferences"]["shared_sharepointonline"]["connectionName"] == SP_CONNECTION
    assert adapter.get_flow(flow_id) == flow
    adapter.delete_item_permission(x["file_id"], x["permission_id"])
    assert adapter.run_flow(flow_id)["status"] == "Succeeded"
    # and the scanner, reading through the adapter, no longer sees a delegated dependency
    snap = load_snapshot(adapter)
    fl = next(f for f in snap.flows if f.id == flow_id)
    assert fl.connection_type == "service_principal" and fl.connection_user_id is None


# ---------------------------------------------------------------- writes change later reads
def test_delete_and_add_change_list_item_permissions(adapter, truth):
    x = truth["stale_safe_to_revoke"][0]
    before = adapter.list_item_permissions(x["file_id"])
    grant = next(p for p in before if p["id"] == x["permission_id"])
    adapter.delete_item_permission(x["file_id"], x["permission_id"])
    assert adapter.list_item_permissions(x["file_id"]) == [p for p in before if p["id"] != x["permission_id"]]
    assert x["permission_id"] not in adapter.list_item_activity(x["file_id"])

    created = adapter.add_item_grant(x["file_id"], {"roles": ["read"], "grantedToV2": grant["grantedToV2"]})
    assert created["id"] != x["permission_id"]
    assert created in adapter.list_item_permissions(x["file_id"])
    assert adapter.list_item_activity(x["file_id"])[created["id"]] is None


def test_writes_are_visible_to_a_second_adapter_on_the_same_file(adapter, tenant_db_path, truth):
    x = truth["stale_safe_to_revoke"][0]
    adapter.delete_item_permission(x["file_id"], x["permission_id"])
    other = SimulatorAdapter(tenant_db_path)
    assert x["permission_id"] not in {p["id"] for p in other.list_item_permissions(x["file_id"])}
    assert other.state_checksum() == adapter.state_checksum()


def test_write_methods_reject_bad_requests(adapter, truth):
    x = truth["stale_safe_to_revoke"][0]
    inherited = next(p for p in adapter.list_item_permissions(x["file_id"]) if "inheritedFrom" in p)
    cases = [
        (404, lambda: adapter.delete_item_permission(x["file_id"], "missing")),
        (404, lambda: adapter.delete_item_permission("f-001" if x["file_id"] != "f-001" else "f-002", x["permission_id"])),
        (400, lambda: adapter.delete_item_permission(x["file_id"], inherited["id"])),
        (400, lambda: adapter.add_item_grant(x["file_id"], {"roles": ["read"]})),
        (400, lambda: adapter.add_item_grant(x["file_id"], {**inherited, "id": "new"})),
        (404, lambda: adapter.add_item_grant("f-999", {"roles": ["read"], "grantedToV2": inherited["grantedToV2"]})),
        (409, lambda: adapter.add_item_grant(x["file_id"], {k: v for k, v in inherited.items() if k != "inheritedFrom"})),
        (404, lambda: adapter.update_flow_connection("flow-01", "no-such-connection")),
        (404, lambda: adapter.update_flow_connection("flow-99", SP_CONNECTION)),
        (404, lambda: adapter.run_flow("flow-99")),
    ]
    checksum = adapter.state_checksum()
    for status, call in cases:
        with pytest.raises(TenantError) as exc:
            call()
        assert exc.value.status == status
    assert adapter.state_checksum() == checksum


# ---------------------------------------------------------------- reset / checksum
def test_reset_restores_checksum(adapter, truth):
    seeded = adapter.state_checksum()
    assert seeded == adapter.state_checksum()
    seen = {seeded}
    x = _sole_direct(truth)
    grantee = adapter.list_item_permissions(x["file_id"])[0]["grantedToV2"]
    for write in (lambda: adapter.delete_item_permission(x["file_id"], x["permission_id"]),
                  lambda: adapter.add_item_grant(x["file_id"], {"roles": ["read"], "grantedToV2": grantee}),
                  lambda: adapter.update_flow_connection(x["flow_ids"][0], SP_CONNECTION)):
        write()
        checksum = adapter.state_checksum()
        assert checksum not in seen  # every write changes the state
        seen.add(checksum)
    adapter.reset()
    assert adapter.state_checksum() == seeded
    assert adapter.run_flow(x["flow_ids"][0])["status"] == "Succeeded"


def test_delete_then_re_add_same_grant_restores_checksum(adapter, truth):
    x = _sole_direct(truth)
    seeded = adapter.state_checksum()
    grant = next(p for p in adapter.list_item_permissions(x["file_id"]) if p["id"] == x["permission_id"])
    last = adapter.list_item_activity(x["file_id"])[x["permission_id"]]
    adapter.delete_item_permission(x["file_id"], x["permission_id"])
    adapter.add_item_grant(x["file_id"], grant, last_accessed_at=last)
    assert adapter.state_checksum() == seeded


def test_new_simulator_file_seeds_itself_with_the_same_state(adapter, tmp_path):
    fresh = SimulatorAdapter(tmp_path / "fresh.db")
    assert fresh.state_checksum() == adapter.state_checksum()
    assert len(fresh.list_users()) == 50 and len(fresh.list_files()) == 100 and len(fresh.list_flows()) == 25


# ---------------------------------------------------------------- scan parity and isolation
def test_scan_through_adapter_matches_classifications_before_the_split(adapter):
    """golden_classifications.json was captured from the session-based scanner before this change."""
    checksum = adapter.state_checksum()
    snap = load_snapshot(adapter)
    assessed, _ = classify(scan_permissions(snap, seed.NOW), snap)
    got = [{"permission_id": a.risk.permission.permission_id, "file_id": a.risk.file.id,
            "classification": a.classification, "risk_score": a.risk.score,
            "is_overshared": a.risk.is_overshared, "is_stale": a.risk.is_stale,
            "dependent_flow_ids": [d.flow_id for d in a.dependencies]} for a in assessed]
    assert got == json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert adapter.state_checksum() == checksum  # scanning is read-only


def test_api_scan_keeps_tenant_and_app_data_in_separate_files(client, scanned, adapter, db_path, tenant_db_path):
    assert inspect(make_engine(db_path)).get_table_names() == ["assessments", "remediation_plans", "remediation_steps"]
    assert sorted(inspect(make_engine(tenant_db_path)).get_table_names()) == \
        ["connections", "files", "flows", "permissions", "users"]
    assert client.get("/api/assessments").json()["total"] == 337


def test_rescan_after_a_write_reflects_the_new_tenant_state(client, scanned, adapter, truth):
    x = truth["stale_safe_to_revoke"][0]
    adapter.delete_item_permission(x["file_id"], x["permission_id"])
    second = client.post("/api/scan/run").json()
    assert second["permissions_scanned"] == 336
    assert second["by_classification"]["SAFE_TO_REVOKE"] == scanned["by_classification"]["SAFE_TO_REVOKE"] - 1


# ---------------------------------------------------------------- adapter contract
def test_live_adapter_has_the_same_method_list_and_is_a_stub():
    assert _public_methods(LiveGraphAdapter) == _public_methods(SimulatorAdapter)
    assert _public_methods(TenantAdapter) <= _public_methods(SimulatorAdapter)
    live = LiveGraphAdapter()
    for name in _public_methods(LiveGraphAdapter):
        with pytest.raises(NotImplementedError):
            getattr(live, name)()


def test_adapter_and_scanner_do_not_bypass_each_other():
    backend = Path(__file__).parents[1]
    assert not [line for line in (backend / "adapter.py").read_text(encoding="utf-8").splitlines()
                if line.lstrip().startswith(("import ", "from ")) and "flow_mapper" in line]
    scanner = (backend / "scanner.py").read_text(encoding="utf-8")
    assert "sqlalchemy" not in scanner and "backend.models" not in scanner
