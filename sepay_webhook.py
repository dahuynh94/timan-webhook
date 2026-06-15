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
import sys
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

@app.route("/health", methods=["GET"])
def health():
    """Health check — dùng để monitor uptime."""
    return jsonify({"status": "ok", "service": "sepay-webhook", "ts": datetime.now().isoformat()}), 200


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
