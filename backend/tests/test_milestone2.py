"""Milestone 2: scanner, flow dependency detector, assessment API, dry-run safety, benchmark."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from backend import seed
from backend.evaluate_benchmark import evaluate
from backend.flow_mapper import MITIGATION, classify, parse_flow
from backend.models import Assessment, Permission, User, init_db, make_engine
from backend.scanner import (WEIGHTS, FileFacts, PermissionFacts, load_snapshot, scan_permissions,
                     score_permission)

NOW = seed.NOW
CRITICAL_FLOWS = [f"flow-{i:02d}" for i in range(1, 8)]


def _ids(items, classification=None):
    return {i["permission_id"] for i in items if classification is None or i["classification"] == classification}


def _file(label="Confidential", copilot=True):
    return FileFacts("f-x", "finance", "x.xlsx", "/sites/finance/x.xlsx", label, copilot)


def _perm(ptype="link", principal="p", roles=("read",), scope=None, inherited=None, days=10):
    last = None if days is None else NOW - timedelta(days=days)
    return PermissionFacts("perm-x", "f-x", principal, ptype, roles, scope, inherited, last)


# ---------------------------------------------------------------- scoring rules
class TestScoring:
    def test_anonymous_write_on_sensitive_copilot_stale_clamps_to_100(self):
        r = score_permission(_perm(scope="anonymous", roles=("write",), days=200), _file(), NOW)
        assert r.breakdown == {"anonymous_link": 45, "sensitive_label": 25, "copilot_indexed": 15,
                               "stale_access": 15, "write_on_broad": 10}
        assert r.score == 100 and r.is_overshared

    @pytest.mark.parametrize("ptype,principal,scope,key", [
        ("link", "p", "organization", "organization_link"),
        ("everyone_except_external", "everyone_except_external", None, "org_wide_group"),
        ("group", "g-all-staff", None, "org_wide_group"),
    ])
    def test_broad_exposure_weights(self, ptype, principal, scope, key):
        r = score_permission(_perm(ptype, principal, scope=scope), _file(), NOW)
        assert r.exposure == key and r.breakdown[key] == WEIGHTS[key]
        assert r.score == WEIGHTS[key] + 25 + 15 and r.is_overshared

    def test_benign_public_org_link_is_not_overshared(self):
        r = score_permission(_perm(scope="organization"), _file("Public", True), NOW)
        assert r.score == 35 and not r.is_overshared and not r.flagged

    def test_direct_user_grant_never_overshared_but_can_be_stale(self):
        r = score_permission(_perm("user", "u-001", days=None), _file(), NOW)
        assert r.score == 55 and not r.is_overshared and r.is_stale and r.days_since_access is None

    def test_stale_boundary_is_strictly_over_90_days(self):
        assert not score_permission(_perm("user", "u-001", days=90), _file(), NOW).is_stale
        assert score_permission(_perm("user", "u-001", days=91), _file(), NOW).is_stale

    def test_inherited_grants_are_not_stale_candidates(self):
        r = score_permission(_perm("group", "g-finance", inherited="/drives/d/root:", days=300), _file(), NOW)
        assert not r.is_stale and "stale_access" in r.breakdown

    def test_department_group_is_not_org_wide(self):
        assert score_permission(_perm("group", "g-finance"), _file(), NOW).exposure is None


# ---------------------------------------------------------------- engine vs ground truth
@pytest.fixture
def engine_output(adapter):
    snap = load_snapshot(adapter)
    results = scan_permissions(snap, NOW)
    assessed, profiles = classify(results, snap)
    return snap, results, assessed, profiles


def test_overshared_set_matches_ground_truth(engine_output, truth):
    _, results, _, _ = engine_output
    assert {r.permission.permission_id for r in results if r.is_overshared} == \
        {o["permission_id"] for o in truth["overshared_files"]}
    benign = {b["permission_id"] for b in truth["benign_broad_grants"]}
    assert not any(r.flagged for r in results if r.permission.permission_id in benign)


def test_classification_matches_ground_truth(engine_output, truth):
    _, _, assessed, _ = engine_output
    by_cls: dict[str, set[str]] = {}
    for a in assessed:
        by_cls.setdefault(a.classification, set()).add(a.risk.permission.permission_id)
    safe = ({o["permission_id"] for o in truth["overshared_files"] if o["expected_action"] == "remove"}
            | {x["permission_id"] for x in truth["stale_safe_to_revoke"]})
    assert by_cls["SAFE_TO_REVOKE"] == safe
    breaking_flagged = {x["permission_id"] for x in truth["workflow_breaking_permissions"]
                        if x["kind"] == "sole_broad_grant" or x["stale_by_access_log"]}
    assert by_cls["BREAKAGE_CRITICAL"] == breaking_flagged and len(breaking_flagged) == 7
    # the 5 active (non-stale) sole direct grants are kept and annotated with their flow
    kept = {a.risk.permission.permission_id: a for a in assessed if a.classification == "KEEP_REQUIRED"}
    for x in truth["workflow_breaking_permissions"]:
        if x["kind"] == "sole_direct_grant" and not x["stale_by_access_log"]:
            assert [d.flow_id for d in kept[x["permission_id"]].dependencies] == x["flow_ids"]


def test_breakage_dependencies_carry_flow_action_and_mitigation(engine_output, truth):
    _, _, assessed, _ = engine_output
    expected = {x["permission_id"]: x["flow_ids"] for x in truth["workflow_breaking_permissions"]}
    for a in assessed:
        if a.classification != "BREAKAGE_CRITICAL":
            continue
        assert [d.flow_id for d in a.dependencies] == expected[a.risk.permission.permission_id]
        for d in a.dependencies:
            assert d.action_name == "Process_file" and d.flow_name and d.mitigation == MITIGATION
            assert d.operation_id in ("UpdateFile", "GetFileContentByPath")
        assert a.mitigation == MITIGATION


def test_flow_parser_resolves_action_paths_and_identity(engine_output):
    snap, _, _, profiles = engine_output
    assert len(profiles) == 25
    for prof, fl in zip(profiles, snap.flows):
        assert [a.file_id for a in prof.actions] == [fl.target_file_id]
        assert prof.identity_user_id == (fl.owner_user_id if fl.connection_type == "user" else None)


def test_flow_parser_handles_nested_actions_and_dollar_connections(engine_output):
    snap, _, _, _ = engine_output
    fl = snap.flows[0]
    raw = fl.raw_definition_json
    props = dict(raw["properties"])
    action = props["definition"]["actions"]["Process_file"]
    props["connectionReferences"] = {}
    props["definition"] = {**props["definition"],
                           "parameters": {"$connections": {"value": {"shared_sharepointonline": {
                               "connectionName": "c1", "id": "/providers/Microsoft.PowerApps/apis/shared_sharepointonline"}}}},
                           "actions": {"Scope": {"type": "Scope", "actions": {"Nested_read": action}}}}
    fl.raw_definition_json = {**raw, "properties": props}
    prof = parse_flow(fl, {f.file_path: f.id for f in snap.files.values()})
    assert [(a.action_name, a.file_id) for a in prof.actions] == [("Nested_read", fl.target_file_id)]
    assert prof.connection_name == "c1"


def test_scanning_graph_payloads_equals_scanning_db_rows(engine_output, tenant_db_path):
    """Facts built from the adapter's Graph payloads equal the flattened rows of the simulator database."""
    snap, results, _, _ = engine_output
    with Session(make_engine(tenant_db_path)) as s:
        from_rows = [PermissionFacts(p.id, p.file_id, p.principal_id, p.principal_type, tuple(p.roles_json),
                                     p.link_scope, p.inherited_from, p.last_accessed_at)
                     for p in s.scalars(select(Permission).order_by(Permission.file_id, Permission.id))]
    assert from_rows == snap.permissions
    scores_rows = {p.permission_id: score_permission(p, snap.files[p.file_id], NOW).score for p in from_rows}
    assert scores_rows == {r.permission.permission_id: r.score for r in results}


# ---------------------------------------------------------------- schema migration safety
def test_init_db_creates_only_app_tables_and_leaves_tenant_untouched(tmp_path, tenant_db_path):
    app_db = tmp_path / "app.db"
    init_db(make_engine(app_db))
    assert inspect(make_engine(app_db)).get_table_names() == ["assessments", "remediation_plans", "remediation_steps"]
    assert "assessments" not in inspect(make_engine(tenant_db_path)).get_table_names()
    with Session(make_engine(tenant_db_path)) as s:
        assert s.scalar(select(func.count()).select_from(Permission)) == 337
        assert s.scalar(select(func.count()).select_from(User)) == 50


# ---------------------------------------------------------------- API
def test_scan_run_summary(scanned):
    assert scanned["files_scanned"] == 100
    assert scanned["permissions_scanned"] == 337
    assert scanned["flows_analysed"] == 25
    assert scanned["overshared_permissions"] == 12 and scanned["overshared_files"] == 12
    assert scanned["stale_permissions"] == 18
    assert scanned["flagged_for_revocation"] == 30
    assert scanned["by_classification"] == {"BREAKAGE_CRITICAL": 7, "SAFE_TO_REVOKE": 23, "KEEP_REQUIRED": 307}
    assert scanned["flows_at_risk"] == CRITICAL_FLOWS


def test_assessments_before_any_scan_is_404(client):
    assert client.get("/api/assessments").status_code == 404


def test_assessments_filter_by_classification(client, scanned, truth):
    r = client.get("/api/assessments", params={"classification": "BREAKAGE_CRITICAL"})
    assert r.status_code == 200
    body = r.json()
    assert body["scan_id"] == scanned["scan_id"] and body["total"] == 7
    assert all(i["classification"] == "BREAKAGE_CRITICAL" and i["dependent_flows"] for i in body["items"])
    dep = body["items"][0]["dependent_flows"][0]
    assert {"flow_id", "flow_name", "action_name", "mitigation"} <= dep.keys()

    safe = client.get("/api/assessments", params={"classification": "SAFE_TO_REVOKE"}).json()
    assert safe["total"] == 23
    assert all(i["is_overshared"] or i["is_stale"] for i in safe["items"])
    assert all(not i["dependent_flows"] for i in safe["items"])
    scores = [i["risk_score"] for i in safe["items"]]
    assert scores == sorted(scores, reverse=True)

    assert client.get("/api/assessments").json()["total"] == 337


def test_assessments_rejects_unknown_filters(client, scanned):
    assert client.get("/api/assessments", params={"classification": "NUKE"}).status_code == 422
    assert client.get("/api/assessments", params={"role": "owner"}).status_code == 422
    assert client.get("/api/assessments", params={"scan_id": "scan-missing"}).status_code == 404


def test_manager_view_returns_plain_language_cards(client, scanned):
    body = client.get("/api/assessments", params={"role": "manager", "classification": "BREAKAGE_CRITICAL"}).json()
    assert body["role"] == "manager" and body["total"] == 7
    for card in body["items"]:
        assert {"headline", "what_we_found", "why_it_matters", "recommended_action", "risk_level"} <= card.keys()
        assert "permission_id" not in card and "score_breakdown" not in card
        assert card["safe_to_fix_now"] is False
        assert "Do not remove this access yet" in card["recommended_action"]
    safe = client.get("/api/assessments", params={"role": "manager", "classification": "SAFE_TO_REVOKE"}).json()
    assert all(c["safe_to_fix_now"] and "nothing will break" in c["recommended_action"] for c in safe["items"])
    anon = [c for c in safe["items"] if "without signing in" in c["headline"]]
    assert len(anon) == 3 and all(c["risk_level"] == "High" for c in anon)


def test_get_single_assessment(client, scanned):
    first = client.get("/api/assessments").json()["items"][0]
    r = client.get(f"/api/assessments/{first['id']}")
    assert r.status_code == 200 and r.json() == first
    assert client.get("/api/assessments/999999").status_code == 404


def _permission_state(tenant_db_path):
    with Session(make_engine(tenant_db_path)) as s:
        return sorted((p.id, p.file_id, p.principal_id, tuple(p.roles_json), p.link_scope)
                      for p in s.scalars(select(Permission)))


def test_dry_run_safe_to_revoke_previews_graph_delete_without_executing(client, scanned, tenant_db_path):
    before = _permission_state(tenant_db_path)
    item = client.get("/api/assessments", params={"classification": "SAFE_TO_REVOKE"}).json()["items"][0]
    r = client.post(f"/api/assessments/{item['id']}/dry-run")
    assert r.status_code == 200
    p = r.json()
    assert p["dry_run"] is True and p["executed"] is False and p["blocked"] is False and p["warning"] is None
    path = f"/drives/{item['drive_id']}/items/{item['file_id']}/permissions/{item['permission_id']}"
    assert p["request"]["method"] == "DELETE" and p["request"]["path"] == path
    assert p["request"]["url"] == "https://graph.microsoft.com/v1.0" + path
    assert p["request"]["headers"]["Authorization"] == "Bearer <redacted>"
    assert _permission_state(tenant_db_path) == before


def test_dry_run_breakage_critical_is_blocked_with_warning(client, scanned, tenant_db_path):
    before = _permission_state(tenant_db_path)
    items = client.get("/api/assessments", params={"classification": "BREAKAGE_CRITICAL"}).json()["items"]
    for item in items:
        p = client.post(f"/api/assessments/{item['id']}/dry-run").json()
        assert p["blocked"] is True and p["executed"] is False
        assert p["warning"].startswith("BLOCKED")
        for d in item["dependent_flows"]:
            assert d["flow_id"] in p["warning"] and d["flow_name"] in p["warning"]
        assert p["breakage"] == item["dependent_flows"]
        assert p["preconditions"] and all(MITIGATION in pre for pre in p["preconditions"])
    assert _permission_state(tenant_db_path) == before


def test_dry_run_keep_required_is_blocked(client, scanned):
    item = client.get("/api/assessments", params={"classification": "KEEP_REQUIRED"}).json()["items"][0]
    p = client.post(f"/api/assessments/{item['id']}/dry-run").json()
    assert p["blocked"] is True and "not flagged" in p["warning"]
    assert client.post("/api/assessments/999999/dry-run").status_code == 404


def test_rescan_keeps_previous_snapshot(client, scanned, db_path):
    second = client.post("/api/scan/run").json()
    assert second["scan_id"] != scanned["scan_id"]
    assert client.get("/api/assessments").json()["scan_id"] == second["scan_id"]
    old = client.get("/api/assessments", params={"scan_id": scanned["scan_id"]}).json()
    assert old["total"] == 337
    with Session(make_engine(db_path)) as s:
        assert s.scalar(select(func.count()).select_from(Assessment)) == 2 * 337


def test_scoring_config_endpoint(client):
    body = client.get("/api/config/scoring").json()
    assert body["weights"] == WEIGHTS and body["overshare_threshold"] == 50 and body["stale_days"] == 90


# ---------------------------------------------------------------- benchmark
def test_benchmark_proposed_beats_baseline(tenant_db_path, tmp_path):
    truth_path = tmp_path / "gt.json"
    seed.seed_database(tenant_db_path, truth_path)
    res = evaluate(tenant_db_path, truth_path)
    base, ours = res["engines"]["baseline"], res["engines"]["proposed"]
    assert base["revocation_recommendation"] == {"tp": 23, "fp": 7, "fn": 0, "precision": 0.7667,
                                                 "recall": 1.0, "f1": 0.8679}
    assert ours["revocation_recommendation"] == {"tp": 23, "fp": 0, "fn": 0, "precision": 1.0,
                                                 "recall": 1.0, "f1": 1.0}
    assert ours["flow_dependency_detection"]["f1"] == 1.0 and base["flow_dependency_detection"]["recall"] == 0.0
    assert base["flows_broken_if_executed"] == CRITICAL_FLOWS and ours["flows_broken_if_executed"] == []
    assert res["workflow_breakage_prevention_rate_pct"] == 100.0
