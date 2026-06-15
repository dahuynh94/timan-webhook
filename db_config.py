#!/usr/bin/env python3
"""MySQL connection config — TIMAN Finance Reconciliation OS."""
import io
import os
import sys
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

MISMATCH_TOLERANCE_VND = int(os.getenv("FINANCE_MISMATCH_TOLERANCE", "2000"))
STORE_VARIANCE_THRESHOLD_VND = int(os.getenv("FINANCE_STORE_VARIANCE_THRESHOLD", "50000"))
ADS_UNASSIGNED_MIN_VND = int(os.getenv("FINANCE_ADS_UNASSIGNED_MIN", "10000"))


def get_connection():
    """Return a mysql-connector connection to timan_finance."""
    import mysql.connector  # lazy import so tests can mock before this runs

    return mysql.connector.connect(
        host=os.getenv("FINANCE_DB_HOST", "127.0.0.1"),
        port=int(os.getenv("FINANCE_DB_PORT", "3306")),
        database=os.getenv("FINANCE_DB_NAME", "timan_finance"),
        user=os.getenv("FINANCE_DB_USER", "root"),
        password=os.getenv("FINANCE_DB_PASSWORD", ""),
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        autocommit=False,
        connection_timeout=10,
    )
