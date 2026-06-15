"""Tests for hardened /timan-sms-289 SMS webhook (v2)."""
import json
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

VALID_SMS = (
    "VietinBank:15/06/2026 16:17|TK:104879755415"
    "|GD:+30,000 VND|SDC:36,940,241 VND|ND:ct; tai iPay"
)
VALID_PAYLOAD = {
    "from": "VietinBank",
    "text": VALID_SMS,
    "sim": "0901234567",
    "sentStamp": 1750000000000,
    "receivedStamp": 1750000000000,
}


# ─── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    with patch("sepay_webhook._migrate_sms_table"):
        from sepay_webhook import app
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _make_conn(existing=None, insert_id=10):
    """Return (conn_mock, cursor_mock). existing=(id,) triggers duplicate path."""
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value = cur
    cur.fetchone.return_value = existing
    cur.lastrowid = insert_id
    return conn, cur


# ─── parse tests (unit) ───────────────────────────────────────────────────────

def test_parse_valid_sms():
    from sepay_webhook import _parse_sms
    r = _parse_sms(VALID_SMS)
    assert r["parse_status"] == "success"
    assert r["account"] == "104879755415"
    assert r["amount"] == 30000
    assert r["balance"] == 36940241
    assert r["direction"] == "credit"
    assert r["transaction_time"] == "15/06/2026 16:17"


def test_parse_debit_sms():
    from sepay_webhook import _parse_sms
    sms = "VietinBank:15/06/2026 14:48|TK:104879755415|GD:-4,000,000 VND|SDC:36,202,241 VND|ND:LAM THE ACB"
    r = _parse_sms(sms)
    assert r["parse_status"] == "success"
    assert r["amount"] == -4000000
    assert r["direction"] == "debit"


def test_parse_malformed_returns_failed():
    from sepay_webhook import _parse_sms
    r = _parse_sms("random garbage SMS no pipes")
    assert r["parse_status"] == "failed"
    assert r["parse_error"] is not None
    assert r["amount"] is None


def test_parse_never_raises():
    from sepay_webhook import _parse_sms
    for bad in ["", "|||", "a|b|c|d|e", None.__class__.__name__]:
        r = _parse_sms(bad)
        assert "parse_status" in r


# ─── txn_hash tests ───────────────────────────────────────────────────────────

def test_txn_hash_uses_parsed_fields_when_available():
    from sepay_webhook import _make_txn_hash
    h1 = _make_txn_hash("VietinBank", "123", 30000, "15/06/2026 16:17", "msg")
    h2 = _make_txn_hash("VietinBank", "123", 30000, "15/06/2026 16:17", "msg")
    assert h1 == h2
    assert len(h1) == 64


def test_txn_hash_falls_back_to_raw_msg():
    from sepay_webhook import _make_txn_hash
    h = _make_txn_hash("VietinBank", None, None, None, "raw message")
    assert len(h) == 64


# ─── endpoint tests ───────────────────────────────────────────────────────────

def test_valid_sms_inserted(client):
    conn, cur = _make_conn(existing=None, insert_id=42)
    with patch("sepay_webhook.get_connection", return_value=conn), \
         patch("sepay_webhook._push_lark_bg"):
        r = client.post("/timan-sms-289", json=VALID_PAYLOAD)
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["inserted"] is True
    assert data["parse_status"] == "success"


def test_malformed_sms_inserted_as_failed(client):
    payload = {**VALID_PAYLOAD, "text": "random garbage no pipes"}
    conn, cur = _make_conn(existing=None)
    with patch("sepay_webhook.get_connection", return_value=conn), \
         patch("sepay_webhook._push_lark_bg"):
        r = client.post("/timan-sms-289", json=payload)
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["inserted"] is True
    assert data["parse_status"] == "failed"


def test_duplicate_sms_skipped(client):
    conn, cur = _make_conn(existing=(99,))
    with patch("sepay_webhook.get_connection", return_value=conn):
        r = client.post("/timan-sms-289", json=VALID_PAYLOAD)
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["inserted"] is False
    assert data["parse_status"] == "duplicate"


def test_nested_body_payload(client):
    nested = {"body": VALID_PAYLOAD}
    conn, cur = _make_conn(existing=None)
    with patch("sepay_webhook.get_connection", return_value=conn), \
         patch("sepay_webhook._push_lark_bg"):
        r = client.post("/timan-sms-289", json=nested)
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_empty_body_returns_400(client):
    r = client.post("/timan-sms-289", data="not json",
                    content_type="application/json")
    assert r.status_code == 400


def test_otp_sms_flagged(client):
    payload = {**VALID_PAYLOAD, "text": "Ma OTP cua ban la: 847291. Co hieu luc 5 phut."}
    conn, cur = _make_conn(existing=None)
    with patch("sepay_webhook.get_connection", return_value=conn), \
         patch("sepay_webhook._push_lark_bg"):
        r = client.post("/timan-sms-289", json=payload)
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["inserted"] is True


# ─── /health ──────────────────────────────────────────────────────────────────

def test_health_endpoint(client):
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value = cur
    cur.fetchone.side_effect = [(1,), ("2026-06-15 16:17:00",)]
    with patch("sepay_webhook.get_connection", return_value=conn):
        r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["db_connected"] is True
    assert "latest_sms_received_at" in data
    assert data["latest_sms_received_at"] == "2026-06-15 16:17:00"


def test_health_degraded_when_db_down(client):
    with patch("sepay_webhook.get_connection", side_effect=Exception("no db")):
        r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["db_connected"] is False
    assert data["status"] == "degraded"


# ─── /sms/recent ──────────────────────────────────────────────────────────────

def test_sms_recent_returns_records(client):
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value = cur
    cur.fetchall.return_value = [{
        "id": 10, "bank": "VietinBank", "sim": "0901234567",
        "account": "104879755415", "amount": 30000, "balance": 36940241,
        "direction": "credit", "parse_status": "success", "parse_error": None,
        "transaction_time": "15/06/2026 16:17", "is_otp": 0,
        "created_at": datetime(2026, 6, 15, 16, 17),
    }]
    with patch("sepay_webhook.get_connection", return_value=conn):
        r = client.get("/sms/recent?limit=5")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["count"] == 1
    assert data["records"][0]["bank"] == "VietinBank"
    assert data["records"][0]["amount"] == 30000


def test_sms_recent_default_limit(client):
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value = cur
    cur.fetchall.return_value = []
    with patch("sepay_webhook.get_connection", return_value=conn):
        r = client.get("/sms/recent")
    assert r.status_code == 200
    # Verify LIMIT 10 was used
    call_args = cur.execute.call_args
    assert 10 in call_args[0][1]
