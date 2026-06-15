#!/usr/bin/env python3
"""SePay Webhook Server — Go Live entry point cho TIMAN Finance OS.

Nhận POST từ SePay khi có giao dịch ngân hàng mới.
Đẩy thẳng vào finance_transactions và trả về {"success": true}.

Authentication:
  Header: Authorization: Apikey <SEPAY_WEBHOOK_API_KEY>
  Optional HMAC: X-Sepay-Signature: <HMAC-SHA256 of raw body>

SePay retry policy: 7 lần, Fibonacci interval, tổng ~5 giờ.
→ Endpoint PHẢI trả 200 trong vòng 30 giây.
→ Mọi lỗi internal vẫn return 200 (để SePay không retry) và log lỗi.

Deployment:
  python sepay_webhook.py                  # dev: port 5055
  gunicorn sepay_webhook:app -b 0.0.0.0:5055 --workers 2  # prod

Env vars:
  SEPAY_WEBHOOK_API_KEY   — API key dùng để verify header Authorization
  SEPAY_WEBHOOK_SECRET    — (optional) HMAC-SHA256 secret
  SEPAY_WEBHOOK_PORT      — port mặc định 5055
  SEPAY_IP_WHITELIST      — comma-separated IPs, để trống = không lọc IP
  FINANCE_WEBHOOK_LOG     — path file log (default: logs/sepay_webhook.log)
"""
import hashlib
import hmac
import io
import json
import logging
import os
import re
import sys
import threading
import urllib.request
from datetime import datetime
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from dotenv import load_dotenv
load_dotenv(HERE / ".env")

# ─── logging setup (file + stdout) ───────────────────────────────────────────

_LOG_PATH = Path(os.getenv("FINANCE_WEBHOOK_LOG", str(HERE / "logs" / "sepay_webhook.log")))
_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(_LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("sepay_webhook")

# ─── Flask app ────────────────────────────────────────────────────────────────

from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

# ─── lazy imports (kept at module level so monkeypatching works in tests) ─────

try:
    from sepay_loader import load_from_webhook
    from db_config import get_connection
except ImportError:  # test environments without MySQL deps
    load_from_webhook = None  # type: ignore[assignment]
    get_connection    = None  # type: ignore[assignment]

# ─── config ───────────────────────────────────────────────────────────────────

_WEBHOOK_API_KEY    = os.getenv("SEPAY_WEBHOOK_API_KEY", "")
_WEBHOOK_SECRET     = os.getenv("SEPAY_WEBHOOK_SECRET", "")
_IP_WHITELIST_RAW   = os.getenv("SEPAY_IP_WHITELIST", "")
_IP_WHITELIST: set  = {ip.strip() for ip in _IP_WHITELIST_RAW.split(",") if ip.strip()}

# ─── Lark Base (SMS log) ─────────────────────────────────────────────────────
_LARK_APP_ID    = os.getenv("LARK_APP_ID", "")
_LARK_APP_SECRET = os.getenv("LARK_APP_SECRET", "")
_LARK_SMS_BASE_ID  = os.getenv("LARK_SMS_BASE_ID", "")
_LARK_SMS_TABLE_ID = os.getenv("LARK_SMS_TABLE_ID", "")

# SePay official IPs (as documented at docs.sepay.vn/tich-hop-webhooks.html)
# Add to SEPAY_IP_WHITELIST in .env to enforce strict IP filtering
SEPAY_OFFICIAL_IPS = {
    "103.88.44.10",
    "103.88.44.11",
    "103.88.44.12",
    "103.88.44.13",
    "103.88.44.14",
    "103.88.44.15",
}


# ─── helpers ──────────────────────────────────────────────────────────────────

def _success(txn_id=None, duplicate=False) -> tuple:
    body = {"success": True}
    if txn_id:
        body["id"] = txn_id
    if duplicate:
        body["duplicate"] = True
    return jsonify(body), 200


def _error_still_200(message: str) -> tuple:
    """Return 200 even on error so SePay doesn't retry an unrecoverable payload."""
    log.error("Webhook error (returning 200 to prevent retry): %s", message)
    return jsonify({"success": False, "error": message}), 200


def _verify_api_key(req) -> bool:
    """Check Authorization: Apikey <key> header."""
    if not _WEBHOOK_API_KEY:
        return True  # not configured → open (dev mode)
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Apikey "):
        return auth[len("Apikey "):].strip() == _WEBHOOK_API_KEY
    return False


def _verify_hmac(req) -> bool:
    """Validate X-Sepay-Signature: HMAC-SHA256(raw_body, secret).

    If SEPAY_WEBHOOK_SECRET is not set, skip verification.
    """
    if not _WEBHOOK_SECRET:
        return True
    sig = req.headers.get("X-Sepay-Signature", "")
    if not sig:
        return False
    raw_body = req.get_data()  # bytes, before json parsing
    expected = hmac.new(
        _WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig.lower())


def _get_client_ip(req) -> str:
    """Get real client IP (handles proxies)."""
    forwarded = req.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return req.remote_addr or ""


# ─── endpoints ────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def root():
    """Root endpoint — Render health probe + browser check."""
    return jsonify({
        "status":  "ok",
        "service": "timan-sepay-webhook",
        "uptime":  "running",
    }), 200


@app.route("/health", methods=["GET"])
def health():
    """Deep health check — verifies DB connectivity + latest SMS timestamp."""
    db_connected = False
    latest_sms = None
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.execute("SELECT created_at FROM sms_bank_log ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if row:
            latest_sms = str(row[0])
        cur.close()
        conn.close()
        db_connected = True
    except Exception:
        pass
    return jsonify({
        "status":                 "healthy" if db_connected else "degraded",
        "service":                "timan-sepay-webhook",
        "db_connected":           db_connected,
        "latest_sms_received_at": latest_sms,
    }), 200


@app.route("/sepay/webhook", methods=["POST"])
def sepay_webhook():
    """Main SePay webhook endpoint.

    SePay POST JSON payload khi có giao dịch mới.
    Phải trả {"success": true} trong vòng 30 giây.
    """
    client_ip = _get_client_ip(request)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── IP whitelist ──────────────────────────────────────────────────────────
    if _IP_WHITELIST and client_ip not in _IP_WHITELIST:
        log.warning("Rejected IP: %s at %s", client_ip, ts)
        return jsonify({"success": False, "error": "IP not allowed"}), 403

    # ── API key ───────────────────────────────────────────────────────────────
    if not _verify_api_key(request):
        log.warning("Invalid API key from %s at %s", client_ip, ts)
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    # ── HMAC signature ────────────────────────────────────────────────────────
    if not _verify_hmac(request):
        log.warning("HMAC mismatch from %s at %s", client_ip, ts)
        return jsonify({"success": False, "error": "Signature invalid"}), 401

    # ── parse JSON ────────────────────────────────────────────────────────────
    payload = request.get_json(silent=True)
    if not payload:
        return _error_still_200("Payload rỗng hoặc không phải JSON")

    sepay_id     = payload.get("id", "?")
    amount       = payload.get("transferAmount") or payload.get("amount") or 0
    transfer_type = payload.get("transferType", "?")
    account      = payload.get("accountNumber", "?")
    content      = (payload.get("content") or "")[:80]

    log.info(
        "Nhận webhook | SePay ID=%s | %s %s VND | acc=%s | nội dung='%s' | IP=%s",
        sepay_id, transfer_type.upper(), amount, account, content, client_ip,
    )

    # ── persist ───────────────────────────────────────────────────────────────
    try:
        conn = get_connection()
        try:
            result = load_from_webhook(payload, conn=conn)
        finally:
            conn.close()

        if result["is_duplicate"]:
            log.info("Duplicate txn_hash=%s (SePay ID=%s) — bỏ qua", result["txn_hash"][:12], sepay_id)
            return _success(txn_id=result["id"], duplicate=True)

        log.info("Đã lưu txn id=%s hash=%s", result["id"], result["txn_hash"][:12])
        return _success(txn_id=result["id"])

    except Exception as exc:
        log.exception("Lỗi persist SePay ID=%s: %s", sepay_id, exc)
        return _error_still_200(f"Internal error: {exc}")


@app.route("/sepay/webhook", methods=["GET"])
def sepay_webhook_probe():
    """SePay gọi GET để kiểm tra endpoint tồn tại."""
    return jsonify({"success": True, "message": "SePay webhook endpoint sẵn sàng"}), 200


# ─── SMS Bank Log ─────────────────────────────────────────────────────────────

def _migrate_sms_table() -> None:
    """Add new columns to sms_bank_log if missing. Safe to run multiple times."""
    try:
        conn = get_connection()
        cur = conn.cursor()
        for sql in [
            "ALTER TABLE sms_bank_log ADD COLUMN sim VARCHAR(50) DEFAULT NULL AFTER bank",
            "ALTER TABLE sms_bank_log ADD COLUMN direction ENUM('credit','debit') DEFAULT NULL AFTER balance",
            "ALTER TABLE sms_bank_log ADD COLUMN description TEXT DEFAULT NULL AFTER direction",
            "ALTER TABLE sms_bank_log ADD COLUMN raw_payload_json MEDIUMTEXT DEFAULT NULL",
            "ALTER TABLE sms_bank_log ADD COLUMN parse_status VARCHAR(20) NOT NULL DEFAULT 'success'",
            "ALTER TABLE sms_bank_log ADD COLUMN parse_error TEXT DEFAULT NULL",
            "ALTER TABLE sms_bank_log ADD COLUMN txn_hash CHAR(64) DEFAULT NULL",
        ]:
            try:
                cur.execute(sql)
                conn.commit()
            except Exception as e:
                if "1060" not in str(e):
                    log.warning("Migration: %s", e)
        try:
            cur.execute("ALTER TABLE sms_bank_log ADD UNIQUE KEY uq_txn_hash (txn_hash)")
            conn.commit()
        except Exception:
            pass
        cur.close()
        conn.close()
        log.info("sms_bank_log schema OK")
    except Exception as exc:
        log.warning("Migration skipped (DB not ready?): %s", exc)


def _parse_sms(text: str) -> dict:
    """Parse bank SMS. Always returns dict — never raises, never returns None."""
    out = {
        "parse_status": "failed", "parse_error": None,
        "transaction_time": None, "account": None,
        "amount": None, "balance": None, "direction": None, "description": None,
    }
    try:
        parts = text.split("|")
        if len(parts) < 4:
            out["parse_error"] = f"Need ≥4 pipe-parts, got {len(parts)}"
            return out
        time_str   = parts[0].split(":", 1)[1].strip() if ":" in parts[0] else ""
        account    = parts[1].split(":", 1)[1].strip() if ":" in parts[1] else ""
        amt_raw    = parts[2].split(":", 1)[1].strip() if ":" in parts[2] else ""
        bal_raw    = parts[3].split(":", 1)[1].strip() if ":" in parts[3] else ""
        desc       = parts[4].split(":", 1)[1].strip() if len(parts) > 4 and ":" in parts[4] else ""
        amt_digits = re.sub(r"\D", "", amt_raw)
        bal_digits = re.sub(r"\D", "", bal_raw)
        if not amt_digits:
            out["parse_error"] = f"Cannot parse amount: {amt_raw!r}"
            return out
        is_credit = not amt_raw.strip().startswith("-")
        out.update({
            "parse_status":    "success",
            "transaction_time": time_str,
            "account":         account,
            "amount":          int(amt_digits) * (1 if is_credit else -1),
            "balance":         int(bal_digits) if bal_digits else None,
            "direction":       "credit" if is_credit else "debit",
            "description":     desc,
        })
    except Exception as exc:
        out["parse_error"] = str(exc)
    return out


def _make_txn_hash(bank: str, account: str, amount, txn_time: str, original_msg: str) -> str:
    """SHA-256 dedup key. Uses parsed fields when full, else hashes raw message."""
    if account and amount is not None and txn_time:
        raw = f"{bank}|{account}|{amount}|{txn_time}|{original_msg}"
    else:
        raw = original_msg
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _lark_token() -> str | None:
    if not _LARK_APP_ID or not _LARK_APP_SECRET:
        return None
    try:
        body = json.dumps({"app_id": _LARK_APP_ID, "app_secret": _LARK_APP_SECRET}).encode()
        req = urllib.request.Request(
            "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal/",
            data=body, headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("tenant_access_token")
    except Exception as exc:
        log.error("Lark token error: %s", exc)
        return None


def _push_lark_bg(records: list) -> None:
    if not _LARK_SMS_BASE_ID or not _LARK_SMS_TABLE_ID:
        return
    token = _lark_token()
    if not token:
        return
    try:
        url = (f"https://open.larksuite.com/open-apis/bitable/v1/apps/"
               f"{_LARK_SMS_BASE_ID}/tables/{_LARK_SMS_TABLE_ID}/records/batch_create")
        body = json.dumps({"records": records}).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            log.info("Lark push: code=%s", json.loads(r.read()).get("code"))
    except Exception as exc:
        log.error("Lark push error: %s", exc)


def _insert_sms_log(conn, row: dict) -> int:
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO sms_bank_log
            (sms_uid, bank, sim, account, amount, balance, direction,
             description, transaction_msg, original_msg, transaction_time,
             received_at_ms, raw_payload_json, parse_status, parse_error, txn_hash, is_otp)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        row.get("sms_uid", ""), row.get("bank"), row.get("sim"),
        row.get("account"), row.get("amount"), row.get("balance"), row.get("direction"),
        row.get("description"), row.get("description"),
        row.get("original_msg"), row.get("transaction_time"), row.get("received_at_ms"),
        json.dumps(row.get("raw_payload"), ensure_ascii=False) if row.get("raw_payload") else None,
        row.get("parse_status", "failed"), row.get("parse_error"),
        row.get("txn_hash"), 1 if row.get("is_otp") else 0,
    ))
    conn.commit()
    new_id = cur.lastrowid
    cur.close()
    return new_id


@app.route("/timan-sms-289", methods=["POST"])
def sms_webhook():
    """Nhận SMS từ điện thoại → parse → dedup → MySQL + Lark Base.

    Supports flat {text, from, sim, receivedStamp}
    and nested {body: {text, from, sim, receivedStamp}}.
    Always returns 200. Always saves raw payload first.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"ok": False, "error": "No JSON body"}), 400

    raw         = payload.get("body") if isinstance(payload.get("body"), dict) else payload
    text        = str(raw.get("text", ""))
    bank        = str(raw.get("from", ""))
    sim         = str(raw.get("sim", ""))
    received_ms = int(raw.get("receivedStamp") or raw.get("sentStamp") or 0)

    is_otp = "OTP" in text.upper()
    parsed = (
        {"parse_status": "success", "parse_error": None, "transaction_time": None,
         "account": None, "amount": None, "balance": None, "direction": None, "description": text}
        if is_otp else _parse_sms(text)
    )

    txn_hash = _make_txn_hash(
        bank, parsed.get("account"), parsed.get("amount"),
        parsed.get("transaction_time"), text,
    )

    row = {
        "sms_uid": f"{sim}-{received_ms}", "bank": bank, "sim": sim,
        "original_msg": text, "received_at_ms": received_ms,
        "is_otp": is_otp, "raw_payload": raw, "txn_hash": txn_hash,
        **parsed,
    }

    new_id = None
    inserted = False

    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM sms_bank_log WHERE txn_hash = %s", (txn_hash,))
            if cur.fetchone():
                cur.close()
                log.info("SMS duplicate hash=%s", txn_hash[:12])
                return jsonify({"ok": True, "inserted": False, "parse_status": "duplicate"}), 200
            cur.close()
            new_id = _insert_sms_log(conn, row)
            inserted = True
            log.info("SMS id=%s bank=%s account=%s amount=%s parse=%s is_otp=%s",
                     new_id, bank, parsed.get("account"), parsed.get("amount"),
                     parsed.get("parse_status"), is_otp)
        finally:
            conn.close()
    except Exception as exc:
        log.exception("SMS MySQL error: %s", exc)

    if inserted:
        lark_fields = (
            {"ID": bank, "Bank": bank, "Transaction Type": "OTP",
             "Transaction Message": text, "Original Message": text, "Time received": received_ms}
            if is_otp else
            {"ID": f"{sim}-{parsed.get('account', '')}", "Bank": bank,
             "Account": parsed.get("account"), "Amount": parsed.get("amount"),
             "Balance": parsed.get("balance"), "Transaction Message": parsed.get("description"),
             "Original Message": text, "Transaction Time": parsed.get("transaction_time"),
             "Time received": received_ms}
        )
        threading.Thread(target=_push_lark_bg, args=([{"fields": lark_fields}],), daemon=True).start()

    return jsonify({
        "ok":           True,
        "inserted":     inserted,
        "parse_status": parsed.get("parse_status", "failed"),
    }), 200


@app.route("/sms/recent", methods=["GET"])
def sms_recent():
    """Debug: xem SMS gần nhất. ?limit=N (max 100)."""
    limit = min(int(request.args.get("limit", 10)), 100)
    try:
        conn = get_connection()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, bank, sim, account, amount, balance, direction,
                   parse_status, parse_error, transaction_time, is_otp, created_at
            FROM sms_bank_log ORDER BY id DESC LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({
            "ok": True, "count": len(rows),
            "records": [{**r, "created_at": str(r["created_at"])} for r in rows],
        }), 200
    except Exception as exc:
        log.exception("sms/recent error: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500


# ─── audit log endpoint (xem webhook history) ────────────────────────────────

@app.route("/sepay/logs", methods=["GET"])
def sepay_logs():
    """Xem 50 dòng log cuối — chỉ dùng nội bộ."""
    if not _verify_api_key(request):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        lines = _LOG_PATH.read_text(encoding="utf-8").splitlines()[-50:]
        return jsonify({"lines": lines, "total": len(lines)}), 200
    except FileNotFoundError:
        return jsonify({"lines": [], "total": 0}), 200


# ─── main ────────────────────────────────────────────────────────────────────

_migrate_sms_table()

if __name__ == "__main__":
    port = int(os.getenv("SEPAY_WEBHOOK_PORT", "5055"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"

    log.info("SePay webhook server khởi động — port %d | API key: %s",
             port, "✓ có" if _WEBHOOK_API_KEY else "⚠ CHƯA CẤU HÌNH")
    if _IP_WHITELIST:
        log.info("IP whitelist: %s", _IP_WHITELIST)
    else:
        log.info("IP whitelist: tắt (chấp nhận mọi IP)")

    app.run(host="0.0.0.0", port=port, debug=debug)
