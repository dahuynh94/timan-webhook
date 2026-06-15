-- =============================================================================
-- TIMAN Finance Reconciliation OS — MySQL Schema
-- Sprint 1 — 2026-06-13
-- Single source of truth: timan_finance database
-- =============================================================================

CREATE DATABASE IF NOT EXISTS timan_finance
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE timan_finance;

-- -----------------------------------------------------------------------------
-- 1. finance_transactions
--    All actual money movements from any source (bank, cash, etc.)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_transactions (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    txn_hash        CHAR(64)        NOT NULL,        -- SHA-256 dedup key
    source          VARCHAR(50)     NOT NULL,         -- sepay | cash_sheet | manual
    direction       ENUM('credit','debit') NOT NULL,
    amount          DECIMAL(18,2)   NOT NULL,         -- always positive, VND
    currency        CHAR(3)         NOT NULL DEFAULT 'VND',
    bank_account    VARCHAR(50)     DEFAULT NULL,     -- tài khoản ngân hàng
    bank_code       VARCHAR(20)     DEFAULT NULL,     -- VCB | MB | ACB | TPB…
    raw_content     TEXT            DEFAULT NULL,     -- nội dung gốc từ ngân hàng
    normalized_ref  VARCHAR(255)    DEFAULT NULL,     -- mã đơn / mã đối soát trích xuất
    channel         VARCHAR(50)     DEFAULT NULL,     -- shopee|tiktok|cod|ads|store|other
    branch          VARCHAR(100)    DEFAULT NULL,     -- chi nhánh / cửa hàng
    posted_at       DATETIME        NOT NULL,
    loaded_at       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status          ENUM('unmatched','matched','reviewed','ignored') NOT NULL DEFAULT 'unmatched',
    meta_json       JSON            DEFAULT NULL,

    PRIMARY KEY (id),
    UNIQUE  KEY uq_txn_hash     (txn_hash),
    INDEX   idx_status          (status),
    INDEX   idx_posted_at       (posted_at),
    INDEX   idx_channel         (channel),
    INDEX   idx_branch          (branch),
    INDEX   idx_source          (source),
    INDEX   idx_normalized_ref  (normalized_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 2. sms_bank_log
--    Raw SMS từ điện thoại — forwarded qua /timan-sms-289 webhook
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sms_bank_log (
    id               INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    sms_uid          VARCHAR(120)    NOT NULL,          -- sim-receivedMs (display/debug)
    bank             VARCHAR(100)    DEFAULT NULL,      -- tên ngân hàng (raw.from)
    account          VARCHAR(50)     DEFAULT NULL,      -- số tài khoản
    amount           BIGINT          DEFAULT NULL,      -- signed VND (+credit/-debit)
    balance          BIGINT          DEFAULT NULL,      -- số dư sau GD
    transaction_msg  TEXT            DEFAULT NULL,      -- nội dung giao dịch (ND:...)
    original_msg     TEXT            DEFAULT NULL,      -- toàn bộ SMS gốc
    transaction_time VARCHAR(30)     DEFAULT NULL,      -- "DD/MM/YYYY HH:MM" từ SMS
    received_at_ms   BIGINT          DEFAULT NULL,      -- Unix ms từ app điện thoại
    is_otp           TINYINT(1)      NOT NULL DEFAULT 0,
    created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_bank        (bank),
    INDEX idx_account     (account),
    INDEX idx_received    (received_at_ms),
    INDEX idx_is_otp      (is_otp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 3. finance_expected_receivables
--    What we expect to receive: settlement, COD, store cash
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_expected_receivables (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source          VARCHAR(50)     NOT NULL,         -- shopee_settlement | tiktok_settlement | cod_statement | store_cash
    reference_code  VARCHAR(255)    NOT NULL,         -- settlement ID / batch / statement ref
    channel         VARCHAR(50)     DEFAULT NULL,
    branch          VARCHAR(100)    DEFAULT NULL,
    amount_expected DECIMAL(18,2)   NOT NULL,
    currency        CHAR(3)         NOT NULL DEFAULT 'VND',
    due_date        DATE            DEFAULT NULL,
    period_start    DATE            DEFAULT NULL,
    period_end      DATE            DEFAULT NULL,
    status          ENUM('pending','matched','mismatch','unpaid','duplicate','needs_review') NOT NULL DEFAULT 'pending',
    matched_txn_id  BIGINT UNSIGNED DEFAULT NULL,
    amount_actual   DECIMAL(18,2)   DEFAULT NULL,     -- điền khi matched
    variance        DECIMAL(18,2)   DEFAULT NULL,     -- amount_actual - amount_expected
    meta_json       JSON            DEFAULT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE  KEY uq_source_ref   (source, reference_code),
    INDEX   idx_status          (status),
    INDEX   idx_channel         (channel),
    INDEX   idx_due_date        (due_date),
    INDEX   idx_matched_txn     (matched_txn_id),
    CONSTRAINT fk_er_txn FOREIGN KEY (matched_txn_id)
        REFERENCES finance_transactions(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 3. finance_expected_payables
--    What we expect to pay: ads top-up, supplier, COD payout
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_expected_payables (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source          VARCHAR(50)     NOT NULL,         -- ads_topup | supplier | cod_payout
    reference_code  VARCHAR(255)    NOT NULL,
    channel         VARCHAR(50)     DEFAULT NULL,     -- meta_ads | tiktok_ads | shopee_ads
    branch          VARCHAR(100)    DEFAULT NULL,
    amount_expected DECIMAL(18,2)   NOT NULL,
    currency        CHAR(3)         NOT NULL DEFAULT 'VND',
    due_date        DATE            DEFAULT NULL,
    status          ENUM('pending','matched','mismatch','unpaid','duplicate','needs_review') NOT NULL DEFAULT 'pending',
    matched_txn_id  BIGINT UNSIGNED DEFAULT NULL,
    amount_actual   DECIMAL(18,2)   DEFAULT NULL,
    variance        DECIMAL(18,2)   DEFAULT NULL,
    meta_json       JSON            DEFAULT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE  KEY uq_source_ref   (source, reference_code),
    INDEX   idx_status          (status),
    INDEX   idx_channel         (channel),
    INDEX   idx_due_date        (due_date),
    INDEX   idx_matched_txn     (matched_txn_id),
    CONSTRAINT fk_ep_txn FOREIGN KEY (matched_txn_id)
        REFERENCES finance_transactions(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 4. finance_reconciliation_matches
--    Audit trail for every matching attempt (auto or manual)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_reconciliation_matches (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    expected_type   ENUM('receivable','payable') NOT NULL,
    expected_id     BIGINT UNSIGNED NOT NULL,
    actual_txn_id   BIGINT UNSIGNED DEFAULT NULL,
    match_status    ENUM('matched','mismatch','needs_review','duplicate','unpaid') NOT NULL,
    amount_expected DECIMAL(18,2)   NOT NULL,
    amount_actual   DECIMAL(18,2)   DEFAULT NULL,
    variance        DECIMAL(18,2)   DEFAULT NULL,     -- amount_actual - amount_expected
    matched_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    matched_by      ENUM('auto','manual') NOT NULL DEFAULT 'auto',
    notes           TEXT            DEFAULT NULL,

    PRIMARY KEY (id),
    INDEX   idx_expected        (expected_type, expected_id),
    INDEX   idx_actual_txn      (actual_txn_id),
    INDEX   idx_match_status    (match_status),
    INDEX   idx_matched_at      (matched_at),
    CONSTRAINT fk_rm_txn FOREIGN KEY (actual_txn_id)
        REFERENCES finance_transactions(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 5. finance_alerts
--    Cảnh báo tự động: lệch số, chưa đối soát, vượt ngân sách
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_alerts (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_type      VARCHAR(100)    NOT NULL,         -- mismatch|unpaid|over_budget|unassigned|variance|duplicate
    severity        ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    entity_type     VARCHAR(50)     DEFAULT NULL,     -- receivable|payable|transaction|branch|account
    entity_id       BIGINT UNSIGNED DEFAULT NULL,
    message         TEXT            NOT NULL,
    amount          DECIMAL(18,2)   DEFAULT NULL,
    resolved_at     DATETIME        DEFAULT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX   idx_alert_type  (alert_type),
    INDEX   idx_severity    (severity),
    INDEX   idx_resolved    (resolved_at),
    INDEX   idx_created     (created_at),
    INDEX   idx_entity      (entity_type, entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 6. finance_review_queue
--    Hàng chờ kiểm tra thủ công: dữ liệu không hợp lệ hoặc không khớp
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_review_queue (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source          VARCHAR(50)     NOT NULL,
    raw_data_json   JSON            NOT NULL,
    issue_type      VARCHAR(100)    DEFAULT NULL,     -- missing_field|invalid_amount|duplicate|parse_error
    issue_description TEXT          DEFAULT NULL,
    status          ENUM('pending','reviewed','resolved','rejected') NOT NULL DEFAULT 'pending',
    reviewer_notes  TEXT            DEFAULT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at     DATETIME        DEFAULT NULL,

    PRIMARY KEY (id),
    INDEX   idx_status      (status),
    INDEX   idx_source      (source),
    INDEX   idx_issue_type  (issue_type),
    INDEX   idx_created     (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 7. finance_classification_rules
--    Regex rules để auto-tag channel và branch từ nội dung giao dịch
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_classification_rules (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_name       VARCHAR(255)    NOT NULL,
    source_filter   VARCHAR(50)     DEFAULT NULL,     -- NULL = áp dụng mọi source
    content_pattern VARCHAR(500)    NOT NULL,          -- regex khớp với raw_content
    direction       ENUM('credit','debit','both') NOT NULL DEFAULT 'both',
    channel         VARCHAR(50)     DEFAULT NULL,
    branch          VARCHAR(100)    DEFAULT NULL,
    priority        SMALLINT UNSIGNED NOT NULL DEFAULT 100,  -- thứ tự ưu tiên, nhỏ = cao hơn
    is_active       TINYINT(1)      NOT NULL DEFAULT 1,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE  KEY uq_rule_name (rule_name),
    INDEX   idx_priority    (priority),
    INDEX   idx_active      (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- 8. finance_sources
--    Registry của các nguồn dữ liệu đầu vào
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance_sources (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_key      VARCHAR(50)     NOT NULL,
    source_name     VARCHAR(255)    NOT NULL,
    description     TEXT            DEFAULT NULL,
    last_synced_at  DATETIME        DEFAULT NULL,
    sync_status     ENUM('ok','error','never') NOT NULL DEFAULT 'never',
    sync_error_msg  TEXT            DEFAULT NULL,
    config_json     JSON            DEFAULT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_source_key (source_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- -----------------------------------------------------------------------------
-- SEED: nguồn dữ liệu mặc định
-- -----------------------------------------------------------------------------
INSERT IGNORE INTO finance_sources (source_key, source_name, description) VALUES
    ('sepay',           'SePay Banking',            'Webhook / API từ SePay — giao dịch ngân hàng thực tế'),
    ('cash_sheet',      'Google Sheet Tiền mặt',    'Báo cáo tiền mặt thủ công từ cửa hàng'),
    ('shopee',          'Shopee Mall Settlement',   'Đối soát thanh toán Shopee Mall (depnamtiman / giaytiman)'),
    ('tiktok',          'TikTok Shop Settlement',   'Đối soát thanh toán TikTok Shop'),
    ('carrier_cod',     'Carrier COD Statement',    'Bảng kê COD từ GHTK / Ninja Van / J&T Express'),
    ('store_cash',      'Store Cash Report',        'POS + tiền mặt nộp theo ca / theo ngày'),
    ('ads',             'Ads Wallet',               'Nạp tiền quảng cáo Meta Ads / TikTok Ads / Shopee Ads');


-- -----------------------------------------------------------------------------
-- SEED: classification rules mặc định cho Timan
-- -----------------------------------------------------------------------------
INSERT IGNORE INTO finance_classification_rules
    (rule_name, content_pattern, direction, channel, priority) VALUES
    ('shopee_settlement',   '(?i)shopee|SPAY|SHPE',         'credit', 'shopee',   10),
    ('tiktok_settlement',   '(?i)tiktok|TKTK|tik tok',      'credit', 'tiktok',   10),
    ('ghtk_cod',            '(?i)GHTK|giao hang tiet kiem', 'credit', 'cod',      20),
    ('ninja_cod',           '(?i)ninja|NVS',                 'credit', 'cod',      20),
    ('jnt_cod',             '(?i)J&T|JNT|jandt',            'credit', 'cod',      20),
    ('meta_ads_topup',      '(?i)meta|facebook|FB ADS',      'debit',  'ads',      30),
    ('tiktok_ads_topup',    '(?i)tiktok ads|TTADS',          'debit',  'ads',      30),
    ('shopee_ads_topup',    '(?i)shopee ads|SHOPADS',        'debit',  'ads',      30);
