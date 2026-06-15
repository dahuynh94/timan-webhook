#!/usr/bin/env python3
"""SePay → finance_transactions loader.

Loads bank transactions from SePay webhook payloads or batch API responses
into the MySQL single source of truth.

Usage:
    from sepay_loader import load_from_webhook, load_from_api, load_batch_json

    # Single webhook
    result = load_from_webhook(payload)         # {id, txn_hash, is_duplicate}

    # Batch from SePay /transactions API
    result = load_from_api(api_response_list)   # {loaded, duplicates, errors}

    # From JSON file
    result = load_batch_json("raw_data/sepay_20260613.json")
"""
import hashlib
import io
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

from db_config import get_connection, MISMATCH_TOLERANCE_VND


# ─── hash ─────────────────────────────────────────────────────────────────────

def compute_txn_hash(
    source: str,
    bank_account: str,
    posted_at: str,          # ISO 8601 string
    amount: float,
    direction: str,
    raw_content: str,
) -> str:
    """SHA-256 fingerprint used to deduplicate transactions across reloads."""
    key = f"{source}|{bank_account}|{posted_at}|{amount:.2f}|{direction}|{(raw_content or '')[:200]}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ─── normalise ────────────────────────────────────────────────────────────────

_REF_PATTERNS = [
    re.compile(r"\b([A-Z0-9]{8,20})\b"),    # generic alphanumeric ref
    re.compile(r"DH\d{6,}"),                 # Shopee order prefix DH
    re.compile(r"SP\d{6,}"),                 # Shopee settlement SP
]


def _extract_ref(content: str) -> Optional[str]:
    if not content:
        return None
    for pat in _REF_PATTERNS:
        m = pat.search(content)
        if m:
            return m.group(0)
    return None


def _parse_sepay_datetime(value: str) -> str:
    """Normalise SePay date strings to MySQL DATETIME (YYYY-MM-DD HH:MM:SS)."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    raise ValueError(f"SePay: không parse được ngày: {value!r}")


def normalize_sepay(payload: dict) -> dict:
    """Map SePay webhook / API payload → chuẩn DB record."""
    raw_content = payload.get("content") or payload.get("description") or ""
    amount_raw = payload.get("transferAmount") or payload.get("amount") or 0
    transfer_type = (payload.get("transferType") or "in").lower()
    direction = "credit" if transfer_type in ("in", "credit", "+") else "debit"
    bank_account = (
        payload.get("accountNumber")
        or payload.get("account_number")
        or payload.get("subAccount")
        or ""
    )
    date_str = payload.get("transactionDate") or payload.get("when") or datetime.now().isoformat()
    posted_at = _parse_sepay_datetime(date_str)

    amount = abs(float(amount_raw))
    txn_hash = compute_txn_hash("sepay", bank_account, posted_at, amount, direction, raw_content)

    return {
        "txn_hash":     txn_hash,
        "source":       "sepay",
        "direction":    direction,
        "amount":       amount,
        "currency":     "VND",
        "bank_account": bank_account,
        "bank_code":    payload.get("gateway") or payload.get("bankCode"),
        "raw_content":  raw_content,
        "normalized_ref": (
            payload.get("referenceCode")
            or payload.get("code")
            or _extract_ref(raw_content)
        ),
        "channel":      None,    # sẽ được classify_transaction gán sau
        "branch":       None,
        "posted_at":    posted_at,
        "meta_json":    json.dumps(payload, ensure_ascii=False),
    }


# ─── classification ───────────────────────────────────────────────────────────

def apply_classification_rules(record: dict, conn) -> dict:
    """Apply finance_classification_rules to set channel/branch on a record."""
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT content_pattern, direction, channel, branch "
        "FROM finance_classification_rules "
        "WHERE is_active = 1 "
        "  AND (source_filter IS NULL OR source_filter = %s) "
        "  AND (direction = 'both' OR direction = %s) "
        "ORDER BY priority ASC",
        (record["source"], record["direction"]),
    )
    rules = cur.fetchall()
    cur.close()

    content = record.get("raw_content") or ""
    for rule in rules:
        if re.search(rule["content_pattern"], content, re.IGNORECASE):
            record["channel"] = rule["channel"]
            record["branch"] = rule["branch"]
            break
    return record


# ─── insert ───────────────────────────────────────────────────────────────────

_INSERT_SQL = """
INSERT IGNORE INTO finance_transactions
    (txn_hash, source, direction, amount, currency, bank_account, bank_code,
     raw_content, normalized_ref, channel, branch, posted_at, meta_json)
VALUES
    (%(txn_hash)s, %(source)s, %(direction)s, %(amount)s, %(currency)s,
     %(bank_account)s, %(bank_code)s, %(raw_content)s, %(normalized_ref)s,
     %(channel)s, %(branch)s, %(posted_at)s, %(meta_json)s)
"""


def _insert_transaction(record: dict, conn) -> dict:
    """Insert one normalised record. Returns {id, txn_hash, is_duplicate}."""
    cur = conn.cursor()
    cur.execute(_INSERT_SQL, record)
    conn.commit()

    if cur.rowcount == 0:
        cur2 = conn.cursor(dictionary=True)
        cur2.execute(
            "SELECT id FROM finance_transactions WHERE txn_hash = %s",
            (record["txn_hash"],),
        )
        row = cur2.fetchone()
        cur2.close()
        return {"id": row["id"] if row else None, "txn_hash": record["txn_hash"], "is_duplicate": True}

    inserted_id = cur.lastrowid
    cur.close()
    return {"id": inserted_id, "txn_hash": record["txn_hash"], "is_duplicate": False}


# ─── public API ───────────────────────────────────────────────────────────────

def load_from_webhook(payload: dict, conn=None) -> dict:
    """Load a single SePay webhook payload. Returns {id, txn_hash, is_duplicate}."""
    _own_conn = conn is None
    if _own_conn:
        conn = get_connection()
    try:
        record = normalize_sepay(payload)
        record = apply_classification_rules(record, conn)
        return _insert_transaction(record, conn)
    finally:
        if _own_conn:
            conn.close()


def load_from_api(transactions: list, conn=None) -> dict:
    """Load a list of SePay API transaction dicts. Returns summary dict."""
    _own_conn = conn is None
    if _own_conn:
        conn = get_connection()
    loaded = duplicates = errors = 0
    error_list = []
    try:
        for raw in transactions:
            try:
                record = normalize_sepay(raw)
                record = apply_classification_rules(record, conn)
                result = _insert_transaction(record, conn)
                if result["is_duplicate"]:
                    duplicates += 1
                else:
                    loaded += 1
            except Exception as exc:
                errors += 1
                error_list.append({"raw": raw, "error": str(exc)})
    finally:
        if _own_conn:
            conn.close()

    summary = {
        "loaded": loaded,
        "duplicates": duplicates,
        "errors": errors,
        "error_list": error_list,
    }
    print(
        f"SePay loader: {loaded} mới | {duplicates} trùng | {errors} lỗi"
    )
    return summary


def load_batch_json(path: str, conn=None) -> dict:
    """Load from a JSON file containing a list of SePay transaction objects."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "transactions" in data:
        data = data["transactions"]
    return load_from_api(data, conn=conn)


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SePay → finance_transactions loader")
    parser.add_argument("--json", metavar="FILE", help="JSON file từ SePay API")
    parser.add_argument("--webhook", metavar="JSON_STRING", help="Payload webhook (JSON string)")
    args = parser.parse_args()

    if args.json:
        result = load_batch_json(args.json)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.webhook:
        result = load_from_webhook(json.loads(args.webhook))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        parser.print_help()
