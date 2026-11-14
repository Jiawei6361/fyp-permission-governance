"""Milestone 3: dashboard-facing API additions (CORS, benchmark endpoint, inheritedFrom facet)."""
from __future__ import annotations

import json

from backend.main import BENCHMARK_PATH

VITE = "http://localhost:5173"


def test_cors_preflight_allows_vite_dev_server(client):
    r = client.options("/api/scan/run", headers={"Origin": VITE, "Access-Control-Request-Method": "POST"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == VITE


def test_cors_rejects_unknown_origin(client):
    r = client.get("/api/config/scoring", headers={"Origin": "http://evil.example"})
    assert r.status_code == 200 and "access-control-allow-origin" not in r.headers


def test_benchmark_endpoint_serves_results_file(client):
    r = client.get("/api/benchmark")
    assert r.status_code == 200
    body = r.json()
    assert body == json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))
    assert set(body["engines"]) == {"baseline", "proposed"}
    assert body["workflow_breakage_prevention_rate_pct"] == 100.0


def test_benchmark_endpoint_404_when_file_missing(client, monkeypatch, tmp_path):
    monkeypatch.setattr("backend.main.BENCHMARK_PATH", tmp_path / "missing.json")
    assert client.get("/api/benchmark").status_code == 404


def test_admin_items_expose_inherited_from(client, scanned):
    items = client.get("/api/assessments").json()["items"]
    inherited = [i for i in items if i["inherited_from"]]
    assert inherited and all(i["inherited_from"].startswith("/") for i in inherited)
    assert any(i["inherited_from"] is None for i in items)
    one = client.get(f"/api/assessments/{inherited[0]['id']}").json()
    assert one["inherited_from"] == inherited[0]["inherited_from"]


def test_manager_cards_still_hide_technical_fields(client, scanned):
    card = client.get("/api/assessments", params={"role": "manager"}).json()["items"][0]
    assert not {"inherited_from", "permission_id", "drive_id", "principal_id"} & set(card)
