"""Shared fixtures. Tests never touch the committed backend/fyp_governance.db: a seeded copy
is built in a temp directory and FYP_DB_PATH points there before `main` is imported."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from backend import seed

_TMP = Path(tempfile.mkdtemp(prefix="fyp-m2-"))
SEEDED_DB = _TMP / "seeded.db"
SEEDED_TRUTH = _TMP / "ground_truth.json"
seed.seed_database(SEEDED_DB, SEEDED_TRUTH)
os.environ["FYP_DB_PATH"] = str(_TMP / "module_app.db")
shutil.copy(SEEDED_DB, os.environ["FYP_DB_PATH"])


@pytest.fixture(scope="session")
def truth() -> dict:
    return json.loads(SEEDED_TRUTH.read_text(encoding="utf-8"))


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "fyp.db"
    shutil.copy(SEEDED_DB, path)
    return path


@pytest.fixture
def client(db_path: Path):
    from fastapi.testclient import TestClient

    from backend.main import create_app

    with TestClient(create_app(db_path)) as c:
        yield c


@pytest.fixture
def scanned(client):
    r = client.post("/api/scan/run")
    assert r.status_code == 200, r.text
    return r.json()
