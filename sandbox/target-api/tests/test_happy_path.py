"""Regression tests for legitimate flows.

These tests are what the ValidatorAgent runs after the HealerAgent applies
a patch. They MUST continue to pass after any autonomous fix — if they fail,
the Validator rejects the patch. They do NOT test the vulnerabilities
themselves (the exploit replay does that).
"""
from __future__ import annotations


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_login_succeeds_with_valid_credentials(client):
    resp = client.post("/login", json={"username": "alice", "password": "alice-pw"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "token" in body and body["token"]
    assert body["user_id"] == 1


def test_login_rejects_wrong_password(client):
    resp = client.post("/login", json={"username": "alice", "password": "WRONG"})
    assert resp.status_code == 401


def test_login_rejects_unknown_user(client):
    resp = client.post("/login", json={"username": "nobody", "password": "x"})
    assert resp.status_code == 401


def test_pay_requires_auth(client):
    resp = client.post("/pay", json={"amount": 10.0})
    assert resp.status_code == 401


def test_pay_legitimate_charge(client, alice_token):
    resp = client.post(
        "/pay",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "order_id": "order-1001",
            "amount": 50.00,
            "pan": "4111111111111111",
            "cvv": "123",
            "idempotency_key": "key-happy-1",
        },
    )
    # We accept either the original (still-vulnerable) 200 or a hardened 200/201
    # so this test survives every reasonable patch shape.
    assert resp.status_code in (200, 201)
    body = resp.get_json()
    assert body.get("status") in ("approved", "accepted", "ok")
    assert "transaction_id" in body


def test_account_owner_can_read_own_account(client, alice_token):
    resp = client.get(
        "/account/1",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 1
    assert body["username"] == "alice"


def test_account_requires_auth(client):
    resp = client.get("/account/1")
    assert resp.status_code == 401
