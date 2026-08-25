-- VaporDrop 持久層 schema（SQLite）
--
-- 設計原則：只有「身份憑證」需要持久化，內容一律不入庫。
-- 這裡刻意不存 email、不存 IP、不存任何存取記錄。
--
-- 檔案位置：/data/vapor.db（docker volume）
-- 內容資料完全不在此處，見 docs/DATA_MODEL.md 的 Redis / tmpfs 部分。

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------
-- 用戶：只有一個不可反推的 uid 與一個顯示用 handle
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    uid         TEXT PRIMARY KEY,              -- 32 hex，CSPRNG 產生
    handle      TEXT NOT NULL UNIQUE,          -- 登入顯示名，非 email
    created_at  INTEGER NOT NULL,              -- unix epoch 秒
    disabled    INTEGER NOT NULL DEFAULT 0     -- 1 = 停用，保留憑證但拒絕登入
);

-- ---------------------------------------------------------------
-- Passkey 憑證：每個裝置一筆
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credentials (
    credential_id TEXT PRIMARY KEY,            -- base64url(raw credential id)
    uid           TEXT NOT NULL,
    public_key    BLOB NOT NULL,               -- COSE 公鑰
    sign_count    INTEGER NOT NULL DEFAULT 0,  -- 必須單調遞增，用於偵測複製
    transports    TEXT NOT NULL DEFAULT '',    -- 逗號分隔：internal,hybrid,usb
    label         TEXT NOT NULL DEFAULT '',    -- 用戶自訂名稱，例如 MacBook Pro
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,                     -- 只記「最近一次」，不保留歷史
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_credentials_uid ON credentials(uid);

-- ---------------------------------------------------------------
-- 邀請碼：註冊唯一入口，一次性，有效期短
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS invites (
    code        TEXT PRIMARY KEY,              -- base64url 隨機碼
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,                       -- 非 NULL 即已用，不可重用
    used_by     TEXT,                          -- uid
    note        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_invites_expires ON invites(expires_at);

-- ---------------------------------------------------------------
-- 緊急登入碼（break-glass）：Google 服務中斷或 OAuth client 被停用時的逃生門
-- 只存 SHA-256 雜湊；原文只在 CLI 產生的那一瞬間印在終端
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rescue_codes (
    code_hash   TEXT PRIMARY KEY,              -- sha256(原文碼)
    uid         TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,              -- 預設 600 秒
    used_at     INTEGER,                       -- 非 NULL 即已用，不可重用
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rescue_expires ON rescue_codes(expires_at);

-- ---------------------------------------------------------------
-- Google 登入如何對應到 users（重要）
-- ---------------------------------------------------------------
--   uid = HMAC-SHA256(UID_PEPPER, 小寫 email) 的前 32 個 hex 字
--   → 同一 email 永遠對到同一列，但資料庫裡沒有 email 原文
--   → handle 預設為 g-<uid 前 10 位>，完全不可辨識；
--     若 STORE_EMAIL_HANDLE=true 則改用 email 的 @ 前半部（好認，但留下部分個資）
--   → Google 登入的用戶在 credentials 表裡沒有任何列，除非他另外加註 Passkey

-- ---------------------------------------------------------------
-- 刻意不建立的表（設計決定，不是遺漏）
-- ---------------------------------------------------------------
--   sessions      -> 只存在 Redis，帶 TTL，重啟即失
--   content       -> 只存在 Redis（metadata）+ tmpfs（密文），10 分鐘蒸發
--   access_log    -> 不存在。無日誌是硬需求
--   audit_trail   -> 不存在。若日後合規需要，只可記「無內容」的計數
--   emails        -> 不存在。Google 登入只存 HMAC 後的 uid，不存 email
--   oauth_tokens  -> 不存在。access / refresh token 驗證完即丟，一律不保留
