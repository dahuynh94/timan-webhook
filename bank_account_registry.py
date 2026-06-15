#!/usr/bin/env python3
"""Bank Account Registry — danh sách tài khoản ngân hàng của TIMAN.

Mỗi tài khoản được đăng ký kết nối SePay sẽ có entry ở đây.
Dùng để:
  - Xác nhận SePay đang theo dõi đúng tài khoản
  - Gắn metadata (ngân hàng, mục đích, team phụ trách) cho transactions
  - Phát hiện giao dịch từ tài khoản chưa đăng ký

Thêm tài khoản mới:
  1. Đăng nhập SePay → Tài khoản ngân hàng → Thêm tài khoản
  2. Thêm dict vào REGISTERED_ACCOUNTS bên dưới
  3. Chạy: python bank_account_registry.py --check

Usage:
    from bank_account_registry import (
        get_account_info, is_registered, get_all_accounts,
        get_channel_for_account, validate_sepay_coverage
    )
"""
import io
import sys
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from dotenv import load_dotenv
load_dotenv(HERE / ".env")


# ─── Tài khoản đã đăng ký SePay ─────────────────────────────────────────────
#
# Thêm/sửa tài khoản ở đây sau khi đăng ký trong SePay dashboard.
#
# Trường bắt buộc:
#   account_number  — số tài khoản chính xác như trong SePay
#   bank_code       — VCB / TCB / MB / ACB / ...
#   bank_name       — tên đầy đủ
#   purpose         — mục đích: operating / ads / store_hn / store_hcm / ...
#   channel         — kênh mặc định (có thể bị ghi đè bởi classification rules)
#   owner           — team chịu trách nhiệm
#   active          — đang kết nối SePay hay không
#
# Trường tuỳ chọn:
#   alias           — tên gọi nội bộ ngắn
#   note            — ghi chú thêm

REGISTERED_ACCOUNTS: list[dict] = [
    # ── TÀI KHOẢN CHÍNH (vận hành) ───────────────────────────────────────────
    {
        "account_number": "",          # TODO: điền số TK VCB công ty
        "bank_code":      "VCB",
        "bank_name":      "Vietcombank",
        "purpose":        "operating",
        "channel":        None,        # nhận tiền từ nhiều kênh
        "owner":          "Finance",
        "alias":          "VCB công ty",
        "active":         False,       # chưa đăng ký SePay → đổi True sau khi kết nối
        "note":           "Tài khoản thu chính: Shopee, TikTok, COD",
    },
    {
        "account_number": "",          # TODO: điền số TK Techcombank
        "bank_code":      "TCB",
        "bank_name":      "Techcombank",
        "purpose":        "operating",
        "channel":        None,
        "owner":          "Finance",
        "alias":          "Techcombank",
        "active":         False,
        "note":           "Tài khoản thu phụ",
    },
    {
        "account_number": "",          # TODO: điền số TK MB
        "bank_code":      "MB",
        "bank_name":      "MB Bank",
        "purpose":        "operating",
        "channel":        None,
        "owner":          "Finance",
        "alias":          "MB Bank",
        "active":         False,
        "note":           "",
    },
    # ── TÀI KHOẢN ADS ────────────────────────────────────────────────────────
    {
        "account_number": "",          # TODO: điền số TK nạp tiền quảng cáo
        "bank_code":      "VCB",
        "bank_name":      "Vietcombank",
        "purpose":        "ads",
        "channel":        "ads",
        "owner":          "Marketing",
        "alias":          "VCB Ads",
        "active":         False,
        "note":           "Nạp Meta Ads, TikTok Ads, Shopee Ads",
    },
    # ── TÀI KHOẢN SHOWROOM / CỬA HÀNG ───────────────────────────────────────
    {
        "account_number": "",          # TODO: điền nếu có TK riêng cho store
        "bank_code":      "VCB",
        "bank_name":      "Vietcombank",
        "purpose":        "store",
        "channel":        "store",
        "owner":          "Store",
        "alias":          "VCB Showroom",
        "active":         False,
        "note":           "Thu tiền mặt cửa hàng, nếu có chuyển khoản",
    },
]


# ─── public API ───────────────────────────────────────────────────────────────

def get_all_accounts(active_only: bool = False) -> list[dict]:
    """Trả về tất cả tài khoản đã đăng ký."""
    if active_only:
        return [a for a in REGISTERED_ACCOUNTS if a.get("active")]
    return list(REGISTERED_ACCOUNTS)


def get_account_info(account_number: str) -> dict | None:
    """Tìm metadata của một số tài khoản. None nếu không tìm thấy."""
    for acc in REGISTERED_ACCOUNTS:
        if acc.get("account_number") == account_number:
            return acc
    return None


def is_registered(account_number: str) -> bool:
    """True nếu tài khoản đã đăng ký trong registry."""
    return get_account_info(account_number) is not None


def get_channel_for_account(account_number: str) -> str | None:
    """Channel mặc định của tài khoản (có thể None nếu tài khoản đa kênh)."""
    info = get_account_info(account_number)
    return info.get("channel") if info else None


def get_active_count() -> int:
    """Số tài khoản đang kết nối SePay."""
    return sum(1 for a in REGISTERED_ACCOUNTS if a.get("active"))


# ─── validation ───────────────────────────────────────────────────────────────

def validate_sepay_coverage(conn=None) -> dict:
    """So sánh registry vs giao dịch thực tế trong DB.

    Phát hiện:
      - Tài khoản đã đăng ký nhưng chưa có giao dịch (chưa kết nối)
      - Tài khoản trong DB nhưng không có trong registry (chưa được khai báo)

    Args:
        conn: MySQL connection (optional; nếu None sẽ tự lấy)

    Returns:
        {
          "registered":    [list account_number],
          "in_db":         [list distinct account_number from finance_transactions],
          "missing_in_db": [đăng ký nhưng chưa có txn],
          "unknown_in_db": [có txn nhưng chưa đăng ký],
          "active_count":  int,
        }
    """
    _own = conn is None
    if _own:
        from db_config import get_connection
        conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT DISTINCT bank_account
            FROM finance_transactions
            WHERE source = 'sepay' AND bank_account IS NOT NULL
        """)
        in_db = {row["bank_account"] for row in cur.fetchall()}
        cur.close()
    finally:
        if _own:
            conn.close()

    active_accs = {a["account_number"] for a in REGISTERED_ACCOUNTS
                   if a.get("active") and a.get("account_number")}
    all_registered = {a["account_number"] for a in REGISTERED_ACCOUNTS
                      if a.get("account_number")}

    return {
        "registered":    sorted(all_registered),
        "active":        sorted(active_accs),
        "in_db":         sorted(in_db),
        "missing_in_db": sorted(active_accs - in_db),
        "unknown_in_db": sorted(in_db - all_registered),
        "active_count":  get_active_count(),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json as _json

    parser = argparse.ArgumentParser(description="Kiểm tra bank account registry")
    parser.add_argument("--check",  action="store_true", help="So sánh registry vs DB")
    parser.add_argument("--list",   action="store_true", help="Liệt kê tài khoản đã đăng ký")
    args = parser.parse_args()

    if args.list:
        for a in REGISTERED_ACCOUNTS:
            status = "✅" if a.get("active") else "❌"
            print(f"{status} [{a['bank_code']}] {a.get('alias','')} "
                  f"| {a.get('account_number','(chưa điền)')} "
                  f"| {a.get('purpose','')} "
                  f"| {a.get('note','')}")

    elif args.check:
        result = validate_sepay_coverage()
        print(_json.dumps(result, ensure_ascii=False, indent=2))
        if result["missing_in_db"]:
            print("\n⚠️  Tài khoản đăng ký nhưng chưa có giao dịch:")
            for acc in result["missing_in_db"]:
                info = get_account_info(acc)
                print(f"  - {acc} ({info['bank_code'] if info else '?'}) — kiểm tra kết nối SePay")
        if result["unknown_in_db"]:
            print("\n⚠️  Tài khoản có giao dịch nhưng chưa đăng ký:")
            for acc in result["unknown_in_db"]:
                print(f"  - {acc} — thêm vào REGISTERED_ACCOUNTS")
        if not result["missing_in_db"] and not result["unknown_in_db"]:
            print("\n✅ Tất cả tài khoản đều khớp.")

    else:
        parser.print_help()
