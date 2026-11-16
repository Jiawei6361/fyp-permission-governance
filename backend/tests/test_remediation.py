"""Remediation plans: approval workflow, guarded execution, automatic and manual rollback."""
from __future__ import annotations

import pytest

from backend.adapter import TenantError
from backend.remediation import STEP_ORDER
from backend.seed import SP_APP, SP_CONNECTION

FAILED_RUN = {"status": "Failed", "error": {"status": 403, "code": "accessDenied", "action": "Process_file",
                                             "file_id": None, "message": "forced failure"}}


def _finding(client, classification, **match):
    items = client.get("/api/assessments", params={"classification": classification}).json()["items"]
    return next(i for i in items if all(i[k] == v for k, v in match.items()))


def _approved_plan(client, assessment, strategy="service_principal"):
    r = client.post("/api/remediations", json={"assessment_id": assessment["id"], "strategy": strategy,
                                               "created_by": "alice"})
    assert r.status_code == 201, r.text
    plan = r.json()
    assert plan["state"] == "DRAFT" and [s["status"] for s in plan["steps"]] == ["PENDING"] * 5
    assert client.post(f"/api/remediations/{plan['id']}/submit").json()["state"] == "PENDING_APPROVAL"
    plan = client.post(f"/api/remediations/{plan['id']}/approve", json={"actor": "bob"}).json()
    assert plan["state"] == "APPROVED" and plan["approved_by"] == "bob"
    return plan


def _execute(client, plan):
    r = client.post(f"/api/remediations/{plan['id']}/execute", json={"actor": "carol"})
    assert r.status_code == 200, r.text
    return r.json()


def _statuses(plan):
    return {s["action"]: s["status"] for s in plan["steps"]}


def _permission_ids(adapter, file_id):
    return {p["id"] for p in adapter.list_item_permissions(file_id)}


def _record_calls(adapter, monkeypatch):
    """Log every run_flow and delete_item_permission the executor makes, in order."""
    calls: list[tuple] = []
    run_flow, delete = adapter.run_flow, adapter.delete_item_permission
    monkeypatch.setattr(adapter, "run_flow", lambda fid: calls.append(("run_flow", fid)) or run_flow(fid))
    monkeypatch.setattr(adapter, "delete_item_permission",
                        lambda f, p: calls.append(("delete", f, p)) or delete(f, p))
    return calls


# ---------------------------------------------------------------- happy path
@pytest.mark.parametrize("strategy", ["service_principal", "scoped_identity_grant"])
@pytest.mark.parametrize("exposure", ["organization_link", "org_wide_group", None])  # None = stale direct grant
def test_breakage_critical_plan_completes_and_flow_still_runs(client, scanned, adapter, strategy, exposure):
    a = _finding(client, "BREAKAGE_CRITICAL", exposure=exposure)
    flow_ids = [d["flow_id"] for d in a["dependent_flows"]]
    plan = _execute(client, _approved_plan(client, a, strategy))

    assert plan["state"] == "COMPLETED" and plan["executed_by"] == "carol" and plan["created_by"] == "alice"
    assert [s["action"] for s in plan["steps"]] == list(STEP_ORDER) and [s["seq"] for s in plan["steps"]] == [1, 2, 3, 4, 5]
    assert all(s["status"] == "SUCCEEDED" and s["error"] is None for s in plan["steps"])
    assert plan["exposed_before"] is None and plan["exposed_after"] is None
    assert plan["steps"][4]["result"]["permission_removed"] is True

    assert a["permission_id"] not in _permission_ids(adapter, a["file_id"])
    assert flow_ids and all(adapter.run_flow(f)["status"] == "Succeeded" for f in flow_ids)
    grants = [p.get("grantedToV2") or {} for p in adapter.list_item_permissions(a["file_id"])]
    for d in a["dependent_flows"]:
        conn = adapter.get_flow(d["flow_id"])["properties"]["connectionReferences"]["shared_sharepointonline"]["connectionName"]
        if strategy == "service_principal":
            assert conn == SP_CONNECTION
            assert any(g.get("application", {}).get("id") == SP_APP["id"] for g in grants)
        else:
            assert conn == d["connection_name"]  # the flow keeps its own identity
            scoped = [p for p in adapter.list_item_permissions(a["file_id"])
                      if (p.get("grantedToV2") or {}).get("user", {}).get("id") == d["connection_identity"]]
            assert [p["roles"] for p in scoped] == [[d["required_role"]]]

    # a new scan no longer reports the flow as at risk from this file
    rescan = client.post("/api/scan/run").json()
    assert not set(flow_ids) & set(rescan["flows_at_risk"])
    assert rescan["by_classification"]["BREAKAGE_CRITICAL"] == 6


def test_safe_to_revoke_plan_completes_without_touching_flows(client, scanned, adapter):
    a = _finding(client, "SAFE_TO_REVOKE")
    flows_before = adapter.list_flows()
    plan = _execute(client, _approved_plan(client, a))
    assert plan["state"] == "COMPLETED" and plan["steps"][1]["before_state"] == {"flows": []}
    assert a["permission_id"] not in _permission_ids(adapter, a["file_id"])
    assert adapter.list_flows() == flows_before


# ---------------------------------------------------------------- the step 4 rule
def test_permission_is_removed_only_after_every_preflight_run(client, scanned, adapter, monkeypatch):
    a = _finding(client, "BREAKAGE_CRITICAL")
    flow_ids = [d["flow_id"] for d in a["dependent_flows"]]
    plan = _approved_plan(client, a)
    calls = _record_calls(adapter, monkeypatch)
    assert _execute(client, plan)["state"] == "COMPLETED"

    target = ("delete", a["file_id"], a["permission_id"])
    assert calls.count(target) == 1 and [c for c in calls if c[0] == "delete"] == [target]
    at = calls.index(target)
    assert calls[:at] == [("run_flow", f) for f in flow_ids]      # PREFLIGHT ran every flow first
    assert calls[at + 1:] == [("run_flow", f) for f in flow_ids]  # POSTFLIGHT ran them again


@pytest.mark.parametrize("strategy", ["service_principal", "scoped_identity_grant"])
def test_forced_preflight_failure_rolls_back_and_never_removes_access(client, scanned, adapter, monkeypatch, strategy):
    a = _finding(client, "BREAKAGE_CRITICAL")
    plan = _approved_plan(client, a, strategy)
    before = adapter.state_checksum()
    calls = _record_calls(adapter, monkeypatch)
    monkeypatch.setattr(adapter, "run_flow", lambda fid: {"flow_id": fid, **FAILED_RUN})

    plan = _execute(client, plan)
    assert plan["state"] == "ROLLED_BACK"
    assert _statuses(plan) == {"SNAPSHOT": "SUCCEEDED", "PROTECT_FLOW": "ROLLED_BACK", "PREFLIGHT": "FAILED",
                               "REMOVE_BROAD_GRANT": "SKIPPED", "POSTFLIGHT": "SKIPPED"}
    assert "forced failure" in plan["steps"][2]["error"]
    assert not [c for c in calls if c == ("delete", a["file_id"], a["permission_id"])]
    assert a["permission_id"] in _permission_ids(adapter, a["file_id"])
    assert adapter.state_checksum() == before


def test_postflight_failure_restores_the_permission(client, scanned, adapter, monkeypatch):
    a = _finding(client, "BREAKAGE_CRITICAL")
    plan = _approved_plan(client, a)
    before = adapter.state_checksum()
    run_flow, seen = adapter.run_flow, []

    def fail_second_time(fid):
        seen.append(fid)
        return run_flow(fid) if seen.count(fid) == 1 else {"flow_id": fid, **FAILED_RUN}

    monkeypatch.setattr(adapter, "run_flow", fail_second_time)
    plan = _execute(client, plan)
    assert plan["state"] == "ROLLED_BACK"
    assert _statuses(plan) == {"SNAPSHOT": "SUCCEEDED", "PROTECT_FLOW": "ROLLED_BACK", "PREFLIGHT": "SUCCEEDED",
                               "REMOVE_BROAD_GRANT": "ROLLED_BACK", "POSTFLIGHT": "FAILED"}
    assert adapter.state_checksum() == before


def test_failure_part_way_through_protect_flow_is_undone(client, scanned, adapter, monkeypatch):
    a = _finding(client, "BREAKAGE_CRITICAL")
    plan = _approved_plan(client, a)  # service_principal: rebind succeeds, then the grant fails
    before = adapter.state_checksum()

    def refuse(*_a, **_k):
        raise TenantError(503, "serviceNotAvailable", "simulated outage")

    monkeypatch.setattr(adapter, "add_item_grant", refuse)
    plan = _execute(client, plan)
    assert plan["state"] == "ROLLED_BACK" and _statuses(plan)["PROTECT_FLOW"] == "FAILED"
    assert "simulated outage" in plan["steps"][1]["error"]
    assert adapter.state_checksum() == before


# ---------------------------------------------------------------- manual rollback
@pytest.mark.parametrize("strategy", ["service_principal", "scoped_identity_grant"])
def test_manual_rollback_of_completed_plan_restores_checksum(client, scanned, adapter, strategy):
    a = _finding(client, "BREAKAGE_CRITICAL")
    before = adapter.state_checksum()
    plan = _execute(client, _approved_plan(client, a, strategy))
    assert plan["state"] == "COMPLETED" and adapter.state_checksum() != before

    plan = client.post(f"/api/remediations/{plan['id']}/rollback").json()
    assert plan["state"] == "ROLLED_BACK"
    assert _statuses(plan) == {"SNAPSHOT": "SUCCEEDED", "PROTECT_FLOW": "ROLLED_BACK", "PREFLIGHT": "SUCCEEDED",
                               "REMOVE_BROAD_GRANT": "ROLLED_BACK", "POSTFLIGHT": "SUCCEEDED"}
    assert adapter.state_checksum() == before
    assert all(adapter.run_flow(d["flow_id"])["status"] == "Succeeded" for d in a["dependent_flows"])
    assert client.post(f"/api/remediations/{plan['id']}/rollback").status_code == 409  # only once


def test_rollback_error_ends_rollback_failed_and_still_undoes_the_rest(client, scanned, adapter, monkeypatch):
    a = _finding(client, "BREAKAGE_CRITICAL")
    plan = _execute(client, _approved_plan(client, a))

    def refuse(*_a, **_k):
        raise TenantError(503, "serviceNotAvailable", "simulated outage")

    monkeypatch.setattr(adapter, "add_item_grant", refuse)
    plan = client.post(f"/api/remediations/{plan['id']}/rollback").json()
    assert plan["state"] == "ROLLBACK_FAILED"
    assert _statuses(plan)["REMOVE_BROAD_GRANT"] == "ROLLBACK_FAILED" and _statuses(plan)["PROTECT_FLOW"] == "ROLLED_BACK"
    assert "simulated outage" in plan["steps"][3]["error"]
    flow = adapter.get_flow(a["dependent_flows"][0]["flow_id"])
    assert flow["properties"]["connectionReferences"]["shared_sharepointonline"]["connectionName"] != SP_CONNECTION


# ---------------------------------------------------------------- workflow rules
def test_state_machine_refuses_out_of_order_transitions(client, scanned, adapter):
    a = _finding(client, "BREAKAGE_CRITICAL")
    before = adapter.state_checksum()
    plan = client.post("/api/remediations", json={"assessment_id": a["id"]}).json()
    url = f"/api/remediations/{plan['id']}"
    for action in ("approve", "reject", "execute", "rollback"):  # DRAFT must be submitted first
        assert client.post(f"{url}/{action}").status_code == 409
    assert client.post(f"{url}/submit").status_code == 200
    for action in ("submit", "execute", "rollback"):
        assert client.post(f"{url}/{action}").status_code == 409
    assert client.post(f"{url}/reject").json()["state"] == "REJECTED"
    for action in ("submit", "approve", "execute", "rollback"):
        r = client.post(f"{url}/{action}")
        assert r.status_code == 409 and "REJECTED" in r.json()["detail"]
    assert client.get(url).json()["state"] == "REJECTED"
    assert adapter.state_checksum() == before  # nothing but execute/rollback touches the tenant


def test_create_plan_validation(client, scanned):
    a = _finding(client, "BREAKAGE_CRITICAL")
    kept = _finding(client, "KEEP_REQUIRED")
    assert client.post("/api/remediations", json={"assessment_id": 999999}).status_code == 404
    assert client.post("/api/remediations", json={"assessment_id": kept["id"]}).status_code == 409
    assert client.post("/api/remediations", json={"assessment_id": a["id"], "strategy": "yolo"}).status_code == 422
    first = client.post("/api/remediations", json={"assessment_id": a["id"]})
    assert first.status_code == 201
    dup = client.post("/api/remediations", json={"assessment_id": a["id"]})
    assert dup.status_code == 409 and "already open" in dup.json()["detail"]
    for action in ("submit", "reject"):
        client.post(f"/api/remediations/{first.json()['id']}/{action}")
    assert client.post("/api/remediations", json={"assessment_id": a["id"]}).status_code == 201  # closed plans do not block
    assert client.get("/api/remediations/999999").status_code == 404
    assert client.post("/api/remediations/999999/execute").status_code == 404


def test_second_plan_for_an_already_removed_permission_fails_at_snapshot(client, scanned, adapter):
    a = _finding(client, "SAFE_TO_REVOKE")
    _execute(client, _approved_plan(client, a))
    before = adapter.state_checksum()
    plan = _execute(client, _approved_plan(client, a))
    assert plan["state"] == "ROLLED_BACK" and _statuses(plan)["SNAPSHOT"] == "FAILED"
    assert "run a new scan" in plan["steps"][0]["error"]
    assert adapter.state_checksum() == before


def test_list_remediations_newest_first_with_state_filter(client, scanned):
    a, b = (_finding(client, "BREAKAGE_CRITICAL"), _finding(client, "SAFE_TO_REVOKE"))
    assert client.get("/api/remediations").json() == {"total": 0, "items": []}
    first = client.post("/api/remediations", json={"assessment_id": a["id"]}).json()
    second = _approved_plan(client, b)
    body = client.get("/api/remediations").json()
    assert body["total"] == 2 and [p["id"] for p in body["items"]] == [second["id"], first["id"]]
    assert body["items"][1]["file_name"] == a["file_name"] and body["items"][1]["dependent_flows"] == a["dependent_flows"]
    drafts = client.get("/api/remediations", params={"state": "DRAFT"}).json()
    assert [p["id"] for p in drafts["items"]] == [first["id"]]
    assert client.get("/api/remediations", params={"state": "NOPE"}).status_code == 422
