"""Intentionally vulnerable payment API. DO NOT DEPLOY ANYWHERE REACHABLE.

This service is the default target for the Security Brain. It contains seeded
vulnerabilities that map 1:1 to the Semgrep rules in orchestrator/rules/payments/:

- SQL injection in /login                  -> classic concat query
- Sensitive logging in /pay                -> logs PAN/CVV
- Amount tampering in /pay                 -> trusts client `amount`
- Missing idempotency in /pay              -> replays accepted unconditionally
- Duplicate payment in /pay                -> no dedup table
- Broken authz in /account/<id>            -> ignores caller identity
- Session misuse in TOKENS                 -> tokens never expire / revoke
- PAN exposure via /logs                   -> raw transactions endpoint
"""
from __future__ import annotations

import logging
import secrets
import sqlite3
from typing import Any

from flask import Flask, g, jsonify, request

app = Flask(__name__)
log = logging.getLogger("payments")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

TOKENS: dict[str, int] = {}
TRANSACTIONS: list[dict[str, Any]] = []
ORDERS: dict[str, dict[str, Any]] = {
    "order-1001": {"amount": 50.00, "user_id": 1, "status": "pending"},
    "order-1002": {"amount": 75.50, "user_id": 2, "status": "pending"},
}


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, balance REAL)"
        )
        cur.executemany(
            "INSERT INTO users (id, username, password, balance) VALUES (?, ?, ?, ?)",
            [(1, "alice", "alice-pw", 1000.0), (2, "bob", "bob-pw", 500.0)],
        )
        conn.commit()
        g.db = conn
    return g.db


def current_user() -> int | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return TOKENS.get(auth.split(None, 1)[1])


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    cur = get_db().cursor()
    cur.execute(query)
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "invalid credentials"}), 401
    token = secrets.token_hex(16)
    TOKENS[token] = row["id"]
    return jsonify({"token": token, "user_id": row["id"]})


@app.post("/pay")
def pay():
    user_id = current_user()
    if user_id is None:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    amount = body.get("amount")
    pan = body.get("pan", "")
    cvv = body.get("cvv", "")
    masked_pan = (pan[:6] + "*" * max(0, len(pan) - 10) + pan[-4:]) if isinstance(pan, str) and len(pan) >= 10 else "****"
    log.info(
        "processing payment user=%s pan=%s amount=%s",
        user_id, masked_pan, amount,
    )
    idem_key = request.headers.get("Idempotency-Key", "").strip()
    if not idem_key:
        return jsonify({"error": "Idempotency-Key header required"}), 400
    cached = IDEMPOTENCY.get((user_id, idem_key))
    if cached is not None:
        return jsonify(cached)
    txid = secrets.token_hex(8)
    TRANSACTIONS.append(
        {"id": txid, "user_id": user_id, "amount": amount, "pan": pan, "cvv": cvv}
    )
    response = {"transaction_id": txid, "amount": amount, "status": "approved"}
    IDEMPOTENCY[(user_id, idem_key)] = response
    return jsonify(response)


@app.get("/account/<int:account_id>")
def get_account(account_id: int):
    user_id = current_user()
    if user_id is None:
        return jsonify({"error": "unauthorized"}), 401
    cur = get_db().cursor()
    cur.execute("SELECT id, username, balance FROM users WHERE id = ?", (account_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.get("/logs")
def get_logs():
    return jsonify({"transactions": TRANSACTIONS})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
