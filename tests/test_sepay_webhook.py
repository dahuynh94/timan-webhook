"""SePay webhook tests — Go Live validation.

Coverage:
  TestWebhookEndpoint      (10 tests) — HTTP / routing
  TestApiKeyAuth           (6 tests)  — API key validation
  TestHmacSignature        (5 tests)  — HMAC-SHA256
  TestPayloadParsing       (8 tests)  — normalize_sepay
  TestDeduplication        (5 tests)  — duplicate handling
  TestVerifyCSV            (7 tests)  — sepay_verify CSV parsing
  TestAccountRegistry      (6 tests)  — bank_account_registry
  TestHealthCheck          (3 tests)  — /health endpoint

Total: 50 tests
"""
import hashlib
import hmac
import json
import sys
import pytest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from uat_db import make_uat_db


# ─── Flask test client ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """Flask test client with SEPAY_WEBHOOK_API_KEY set."""
    import os
    os.environ["SEPAY_WEBHOOK_API_KEY"]  = "test-api-key-123"
    os.environ["SEPAY_WEBHOOK_SECRET"]   = ""   # HMAC off by default
    os.environ["SEPAY_IP_WHITELIST"]     = ""   # IP filter off

    # Patch db so we use SQLite in-memory instead of MySQL
    import importlib, sepay_webhook as wh

    wh.app.config["TESTING"] = True
    return wh.app.test_client()


def _api_headers(key: str = "test-api-key-123") -> dict:
    return {"Authorization": f"Apikey {key}", "Content-Type": "application/json"}


def _payload(sepay_id=1, amount=150_000, txn_type="in",
             account="1234567890", content="Chuyen khoan TIMAN") -> dict:
    return {
        "id":              sepay_id,
        "gateway":         "VCB",
        "transactionDate": "2026-06-14 10:30:00",
        "accountNumber":   account,
        "transferAmount":  amount,
        "transferType":    txn_type,
        "content":         content,
        "referenceCode":   f"FT{sepay_id:08d}",
        "transactionCode": f"TXN{sepay_id}",
    }


# ─── TestHealthCheck ─────────────────────────────────────────────────────────

class TestHealthCheck:
    def test_root_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_root_body(self, client):
        r = client.get("/")
        data = r.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "timan-sepay-webhook"
        assert data["uptime"] == "running"

    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_has_service_field(self, client):
        r = client.get("/health")
        data = r.get_json()
        assert data["service"] == "timan-sepay-webhook"
        assert "db_connected" in data

    def test_health_db_connected_is_bool(self, client):
        r = client.get("/health")
        data = r.get_json()
        assert isinstance(data["db_connected"], bool)

    def test_webhook_route_still_works(self, client, monkeypatch):
        _patch_loader(monkeypatch, duplicate=False, txn_id=999)
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload(sepay_id=601)),
                        content_type="application/json",
                        headers=_api_headers())
        assert r.status_code == 200
        assert r.get_json()["success"] is True


# ─── TestWebhookEndpoint ─────────────────────────────────────────────────────

class TestWebhookEndpoint:

    def test_get_probe_returns_200(self, client):
        r = client.get("/sepay/webhook")
        assert r.status_code == 200

    def test_get_probe_body(self, client):
        r = client.get("/sepay/webhook")
        data = r.get_json()
        assert data.get("success") is True

    def test_post_without_auth_returns_401(self, client):
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload()),
                        content_type="application/json")
        assert r.status_code == 401

    def test_post_wrong_key_returns_401(self, client):
        headers = _api_headers(key="wrong-key")
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload()),
                        content_type="application/json",
                        headers=headers)
        assert r.status_code == 401

    def test_post_empty_body_returns_200(self, client):
        """Even empty body must return 200 to prevent SePay retry."""
        r = client.post("/sepay/webhook",
                        data="",
                        content_type="application/json",
                        headers=_api_headers())
        assert r.status_code == 200

    def test_post_valid_payload_returns_200(self, client, monkeypatch):
        _patch_loader(monkeypatch, duplicate=False, txn_id=99)
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload(sepay_id=101)),
                        content_type="application/json",
                        headers=_api_headers())
        assert r.status_code == 200

    def test_post_returns_success_true(self, client, monkeypatch):
        _patch_loader(monkeypatch, duplicate=False, txn_id=100)
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload(sepay_id=102)),
                        content_type="application/json",
                        headers=_api_headers())
        data = r.get_json()
        assert data.get("success") is True

    def test_duplicate_returns_200_with_flag(self, client, monkeypatch):
        _patch_loader(monkeypatch, duplicate=True, txn_id=55)
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload(sepay_id=103)),
                        content_type="application/json",
                        headers=_api_headers())
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("duplicate") is True

    def test_db_error_still_returns_200(self, client, monkeypatch):
        """DB crash must not cause 5xx — SePay must not retry."""
        _patch_loader_error(monkeypatch)
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload(sepay_id=104)),
                        content_type="application/json",
                        headers=_api_headers())
        assert r.status_code == 200

    def test_unknown_route_returns_404(self, client):
        r = client.get("/unknown")
        assert r.status_code == 404


# ─── TestApiKeyAuth ──────────────────────────────────────────────────────────

class TestApiKeyAuth:

    def test_correct_key_accepted(self, client, monkeypatch):
        _patch_loader(monkeypatch, duplicate=False, txn_id=200)
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload(sepay_id=201)),
                        content_type="application/json",
                        headers={"Authorization": "Apikey test-api-key-123",
                                 "Content-Type": "application/json"})
        assert r.status_code == 200

    def test_wrong_key_rejected(self, client):
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload()),
                        content_type="application/json",
                        headers={"Authorization": "Apikey WRONG",
                                 "Content-Type": "application/json"})
        assert r.status_code == 401

    def test_missing_auth_header_rejected(self, client):
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload()),
                        content_type="application/json")
        assert r.status_code == 401

    def test_bearer_format_rejected(self, client):
        """SePay dùng 'Apikey', không phải 'Bearer'."""
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload()),
                        content_type="application/json",
                        headers={"Authorization": "Bearer test-api-key-123"})
        assert r.status_code == 401

    def test_empty_api_key_env_allows_all(self, monkeypatch):
        """Khi không config SEPAY_WEBHOOK_API_KEY, chấp nhận mọi request (dev mode)."""
        import sepay_webhook as wh
        monkeypatch.setattr(wh, "_WEBHOOK_API_KEY", "")
        _patch_loader(monkeypatch, duplicate=False, txn_id=300)
        r = wh.app.test_client().post(
            "/sepay/webhook",
            data=json.dumps(_payload(sepay_id=301)),
            content_type="application/json",
        )
        assert r.status_code == 200

    def test_verify_api_key_function_correct(self):
        import sepay_webhook as wh
        monkeypatch_wh_key = "abc123"
        import unittest.mock as mock
        with mock.patch.object(wh, "_WEBHOOK_API_KEY", monkeypatch_wh_key):
            class FakeReq:
                headers = {"Authorization": "Apikey abc123"}
            assert wh._verify_api_key(FakeReq()) is True


# ─── TestHmacSignature ───────────────────────────────────────────────────────

class TestHmacSignature:

    def _make_sig(self, secret: str, body: bytes) -> str:
        return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    def test_valid_hmac_accepted(self, client, monkeypatch):
        import sepay_webhook as wh
        monkeypatch.setattr(wh, "_WEBHOOK_SECRET", "my-secret")
        _patch_loader(monkeypatch, duplicate=False, txn_id=400)
        body = json.dumps(_payload(sepay_id=401)).encode()
        sig  = self._make_sig("my-secret", body)
        r = client.post("/sepay/webhook",
                        data=body,
                        content_type="application/json",
                        headers={"Authorization": "Apikey test-api-key-123",
                                 "X-Sepay-Signature": sig})
        assert r.status_code == 200

    def test_invalid_hmac_rejected(self, client, monkeypatch):
        import sepay_webhook as wh
        monkeypatch.setattr(wh, "_WEBHOOK_SECRET", "my-secret")
        body = json.dumps(_payload(sepay_id=402)).encode()
        r = client.post("/sepay/webhook",
                        data=body,
                        content_type="application/json",
                        headers={"Authorization": "Apikey test-api-key-123",
                                 "X-Sepay-Signature": "badhash"})
        assert r.status_code == 401

    def test_missing_hmac_rejected_when_secret_set(self, client, monkeypatch):
        import sepay_webhook as wh
        monkeypatch.setattr(wh, "_WEBHOOK_SECRET", "my-secret")
        body = json.dumps(_payload(sepay_id=403)).encode()
        r = client.post("/sepay/webhook",
                        data=body,
                        content_type="application/json",
                        headers={"Authorization": "Apikey test-api-key-123"})
        assert r.status_code == 401

    def test_hmac_skipped_when_secret_not_set(self, client, monkeypatch):
        import sepay_webhook as wh
        monkeypatch.setattr(wh, "_WEBHOOK_SECRET", "")
        _patch_loader(monkeypatch, duplicate=False, txn_id=500)
        r = client.post("/sepay/webhook",
                        data=json.dumps(_payload(sepay_id=501)),
                        content_type="application/json",
                        headers=_api_headers())
        assert r.status_code == 200

    def test_verify_hmac_pure_function(self):
        import sepay_webhook as wh
        secret = "testsecret"
        body   = b'{"id":1}'
        sig    = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        import unittest.mock as mock
        with mock.patch.object(wh, "_WEBHOOK_SECRET", secret):
            class FakeReq:
                headers = {"X-Sepay-Signature": sig}
                def get_data(self): return body
            assert wh._verify_hmac(FakeReq()) is True


# ─── TestPayloadParsing ───────────────────────────────────────────────────────

class TestPayloadParsing:

    def test_normalize_credit(self):
        from sepay_loader import normalize_sepay
        rec = normalize_sepay(_payload(txn_type="in", amount=200_000))
        assert rec["direction"] == "credit"
        assert rec["amount"]    == 200_000.0

    def test_normalize_debit(self):
        from sepay_loader import normalize_sepay
        rec = normalize_sepay(_payload(txn_type="out", amount=100_000))
        assert rec["direction"] == "debit"
        assert rec["amount"]    == 100_000.0

    def test_normalize_amount_absolute(self):
        """Amount phải luôn dương dù SePay gửi âm."""
        from sepay_loader import normalize_sepay
        p = _payload(); p["transferAmount"] = -50_000
        rec = normalize_sepay(p)
        assert rec["amount"] > 0

    def test_normalize_account_number(self):
        from sepay_loader import normalize_sepay
        rec = normalize_sepay(_payload(account="9876543210"))
        assert rec["bank_account"] == "9876543210"

    def test_normalize_datetime_format(self):
        from sepay_loader import normalize_sepay
        rec = normalize_sepay(_payload())
        assert rec["posted_at"] == "2026-06-14 10:30:00"

    def test_normalize_gateway_as_bank_code(self):
        from sepay_loader import normalize_sepay
        rec = normalize_sepay(_payload())
        assert rec["bank_code"] == "VCB"

    def test_normalize_source_is_sepay(self):
        from sepay_loader import normalize_sepay
        rec = normalize_sepay(_payload())
        assert rec["source"] == "sepay"

    def test_normalize_meta_json_contains_original(self):
        from sepay_loader import normalize_sepay
        import json
        p = _payload(sepay_id=777)
        rec = normalize_sepay(p)
        meta = json.loads(rec["meta_json"])
        assert meta["id"] == 777


# ─── TestDeduplication ───────────────────────────────────────────────────────

class TestDeduplication:

    def test_same_payload_twice_is_duplicate(self):
        from sepay_loader import normalize_sepay, compute_txn_hash
        p    = _payload(sepay_id=1000)
        rec1 = normalize_sepay(p)
        rec2 = normalize_sepay(p)
        assert rec1["txn_hash"] == rec2["txn_hash"]

    def test_different_amount_different_hash(self):
        from sepay_loader import normalize_sepay
        r1 = normalize_sepay(_payload(amount=100_000))
        r2 = normalize_sepay(_payload(amount=200_000))
        assert r1["txn_hash"] != r2["txn_hash"]

    def test_different_account_different_hash(self):
        from sepay_loader import normalize_sepay
        r1 = normalize_sepay(_payload(account="111"))
        r2 = normalize_sepay(_payload(account="222"))
        assert r1["txn_hash"] != r2["txn_hash"]

    def test_load_from_webhook_uat(self):
        from sepay_loader import load_from_webhook
        db = make_uat_db(":memory:")
        result = load_from_webhook(_payload(sepay_id=2000), conn=db)
        assert result["is_duplicate"] is False
        assert result["id"] is not None

    def test_load_duplicate_webhook_uat(self):
        from sepay_loader import load_from_webhook
        db = make_uat_db(":memory:")
        p = _payload(sepay_id=2001)
        load_from_webhook(p, conn=db)
        result2 = load_from_webhook(p, conn=db)
        assert result2["is_duplicate"] is True


# ─── TestVerifyCSV ───────────────────────────────────────────────────────────

class TestVerifyCSV:

    def _write_csv(self, tmp_path, rows: list[dict]) -> str:
        import csv
        path = str(tmp_path / "bank.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Date","Description","Credit","Debit"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        return path

    def test_parse_vcb_csv(self, tmp_path):
        from sepay_verify import parse_bank_csv
        path = self._write_csv(tmp_path, [
            {"Date": "2026-06-14", "Description": "TT Shopee", "Credit": "150000", "Debit": "0"},
            {"Date": "2026-06-14", "Description": "Phi dich vu", "Credit": "0", "Debit": "5000"},
        ])
        records = parse_bank_csv(path)
        assert len(records) == 2

    def test_credit_sum_correct(self, tmp_path):
        from sepay_verify import parse_bank_csv, _aggregate_csv
        path = self._write_csv(tmp_path, [
            {"Date": "2026-06-14", "Description": "A", "Credit": "100000", "Debit": "0"},
            {"Date": "2026-06-14", "Description": "B", "Credit": "200000", "Debit": "0"},
        ])
        records = parse_bank_csv(path)
        agg = _aggregate_csv(records, "2026-06-14", "2026-06-14")
        assert agg["credit"] == pytest.approx(300_000)

    def test_debit_sum_correct(self, tmp_path):
        from sepay_verify import parse_bank_csv, _aggregate_csv
        path = self._write_csv(tmp_path, [
            {"Date": "2026-06-14", "Description": "A", "Credit": "0", "Debit": "50000"},
        ])
        records = parse_bank_csv(path)
        agg = _aggregate_csv(records, "2026-06-14", "2026-06-14")
        assert agg["debit"] == pytest.approx(50_000)

    def test_date_filter_excludes_out_of_range(self, tmp_path):
        from sepay_verify import parse_bank_csv, _aggregate_csv
        path = self._write_csv(tmp_path, [
            {"Date": "2026-06-01", "Description": "old", "Credit": "999999", "Debit": "0"},
            {"Date": "2026-06-14", "Description": "new", "Credit": "111000", "Debit": "0"},
        ])
        records = parse_bank_csv(path)
        agg = _aggregate_csv(records, "2026-06-14", "2026-06-14")
        assert agg["credit"] == pytest.approx(111_000)

    def test_compare_zero_diff_is_match(self):
        from sepay_verify import compare
        data = {"credit": 1_000_000, "debit": 200_000, "net": 800_000, "count": 5,
                "by_date": {}}
        diff = compare(data, data)
        assert diff["match"] is True
        assert diff["credit_diff"] == 0

    def test_compare_large_diff_is_fail(self):
        from sepay_verify import compare
        sepay = {"credit": 1_000_000, "debit": 0, "net": 1_000_000, "count": 1, "by_date": {}}
        bank  = {"credit":   900_000, "debit": 0, "net":   900_000, "count": 1, "by_date": {}}
        diff  = compare(sepay, bank)
        assert diff["match"] is False
        assert diff["credit_diff"] == 100_000

    def test_compare_within_tolerance_is_match(self):
        from sepay_verify import compare
        sepay = {"credit": 1_000_000, "debit": 0, "net": 1_000_000, "count": 1, "by_date": {}}
        bank  = {"credit":   999_000, "debit": 0, "net":   999_000, "count": 1, "by_date": {}}
        diff  = compare(sepay, bank)
        # diff=1000 VND, tolerance=2000 → match
        assert diff["match"] is True


# ─── TestAccountRegistry ─────────────────────────────────────────────────────

class TestAccountRegistry:

    def test_get_all_accounts_returns_list(self):
        from bank_account_registry import get_all_accounts
        accs = get_all_accounts()
        assert isinstance(accs, list) and len(accs) > 0

    def test_active_only_filter(self):
        from bank_account_registry import get_all_accounts
        active = get_all_accounts(active_only=True)
        assert all(a.get("active") for a in active)

    def test_is_registered_false_for_unknown(self):
        from bank_account_registry import is_registered
        assert is_registered("0000000000UNKNOWN") is False

    def test_get_channel_none_for_unknown(self):
        from bank_account_registry import get_channel_for_account
        assert get_channel_for_account("99999") is None

    def test_active_count_is_int(self):
        from bank_account_registry import get_active_count
        assert isinstance(get_active_count(), int)

    def test_all_accounts_have_required_fields(self):
        from bank_account_registry import get_all_accounts
        required = {"bank_code", "bank_name", "purpose", "owner", "active"}
        for acc in get_all_accounts():
            assert required <= set(acc.keys()), f"Missing fields in {acc}"


# ─── patch helpers (avoid MySQL in tests) ─────────────────────────────────────

class _FakeConn:
    def close(self): pass


def _patch_loader(monkeypatch, duplicate: bool, txn_id: int):
    """Patch module-level load_from_webhook and get_connection in sepay_webhook."""
    import sepay_webhook as wh

    monkeypatch.setattr(wh, "load_from_webhook",
                        lambda payload, conn=None: {
                            "id": txn_id,
                            "txn_hash": "abc123fake",
                            "is_duplicate": duplicate,
                        })
    monkeypatch.setattr(wh, "get_connection", lambda: _FakeConn())


def _patch_loader_error(monkeypatch):
    """Patch to simulate DB crash — still must return 200."""
    import sepay_webhook as wh

    def _crash(payload, conn=None):
        raise RuntimeError("Simulated DB crash")

    monkeypatch.setattr(wh, "load_from_webhook", _crash)
    monkeypatch.setattr(wh, "get_connection", lambda: _FakeConn())
