"""Shared fixtures. Tests never touch the committed databases: the simulator tenant is seeded
into a temp directory, and FYP_TENANT_DB_PATH / FYP_DB_PATH point there before `main` is imported."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from backend import seed

_TMP = Path(tempfile.mkdtemp(prefix="fyp-m2-"))
SEEDED_TENANT_DB = _TMP / "seeded_tenant.db"
SEEDED_TRUTH = _TMP / "ground_truth.json"
seed.seed_database(SEEDED_TENANT_DB, SEEDED_TRUTH)
os.environ["FYP_TENANT_DB_PATH"] = str(_TMP / "module_tenant.db")
shutil.copy(SEEDED_TENANT_DB, os.environ["FYP_TENANT_DB_PATH"])
os.environ["FYP_DB_PATH"] = str(_TMP / "module_app.db")


@pytest.fixture(scope="session")
def truth() -> dict:
    return json.loads(SEEDED_TRUTH.read_text(encoding="utf-8"))


@pytest.fixture
def tenant_db_path(tmp_path: Path) -> Path:
    """A private, freshly seeded copy of the simulator database."""
    path = tmp_path / "tenant_sim.db"
    shutil.copy(SEEDED_TENANT_DB, path)
    return path


@pytest.fixture
def adapter(tenant_db_path: Path):
    from backend.adapter import SimulatorAdapter

    return SimulatorAdapter(tenant_db_path)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """An empty app database path; `create_app` creates `assessments` in it."""
    return tmp_path / "fyp.db"


@pytest.fixture
def client(db_path: Path, adapter):
    from fastapi.testclient import TestClient

    from backend.main import create_app

    with TestClient(create_app(db_path, adapter)) as c:
        yield c


@pytest.fixture
def scanned(client):
    r = client.post("/api/scan/run")
    assert r.status_code == 200, r.text
    return r.json()
