from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import TOKENS, TRANSACTIONS, app as flask_app  # noqa: E402


@pytest.fixture()
def client():
    flask_app.config["TESTING"] = True
    TOKENS.clear()
    TRANSACTIONS.clear()
    with flask_app.test_client() as c:
        yield c


@pytest.fixture()
def alice_token(client):
    resp = client.post("/login", json={"username": "alice", "password": "alice-pw"})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


@pytest.fixture()
def bob_token(client):
    resp = client.post("/login", json={"username": "bob", "password": "bob-pw"})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]
