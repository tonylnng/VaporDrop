"""SQLite 持久層：只存 Passkey 憑證與邀請碼，絕不存內容或存取記錄。

所有函式都是同步的（SQLite 本身如此），呼叫端以 asyncio.to_thread 包裹。
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from typing import Any

from . import config

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    uid         TEXT PRIMARY KEY,
    handle      TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id TEXT PRIMARY KEY,
    uid           TEXT NOT NULL,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT NOT NULL DEFAULT '',
    label         TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_credentials_uid ON credentials(uid);

CREATE TABLE IF NOT EXISTS invites (
    code        TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    used_by     TEXT,
    note        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_invites_expires ON invites(expires_at);
"""


def _connect() -> sqlite3.Connection:
    directory = os.path.dirname(config.DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


# --- 用戶 -------------------------------------------------------------
def user_count() -> int:
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])


def create_user(handle: str) -> str:
    uid = secrets.token_hex(16)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO users (uid, handle, created_at) VALUES (?, ?, ?)",
            (uid, handle, int(time.time())),
        )
    return uid


def get_user_by_handle(handle: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE handle = ?", (handle,)).fetchone()
    return dict(row) if row else None


def get_user(uid: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
    return dict(row) if row else None


# --- 憑證 -------------------------------------------------------------
def add_credential(
    credential_id: str,
    uid: str,
    public_key: bytes,
    sign_count: int,
    transports: str = "",
    label: str = "",
) -> None:
    with _connect() as conn:
        conn.execute(
            """INSERT INTO credentials
               (credential_id, uid, public_key, sign_count, transports, label, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (credential_id, uid, public_key, sign_count, transports, label, int(time.time())),
        )


def get_credential(credential_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()
    return dict(row) if row else None


def credentials_for_handle(handle: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """SELECT c.* FROM credentials c
               JOIN users u ON u.uid = c.uid
               WHERE u.handle = ?""",
            (handle,),
        ).fetchall()
    return [dict(r) for r in rows]


def credentials_for_uid(uid: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM credentials WHERE uid = ?", (uid,)).fetchall()
    return [dict(r) for r in rows]


def touch_credential(credential_id: str, sign_count: int) -> None:
    """更新 sign_count 與最近使用時間。只保留最新值，不累積歷史。"""
    with _connect() as conn:
        conn.execute(
            "UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?",
            (sign_count, int(time.time()), credential_id),
        )


def delete_credential(credential_id: str, uid: str) -> bool:
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM credentials WHERE credential_id = ? AND uid = ?",
            (credential_id, uid),
        )
        return cur.rowcount > 0


# --- 邀請碼 -----------------------------------------------------------
def create_invite(note: str = "", ttl: int | None = None) -> tuple[str, int]:
    code = secrets.token_urlsafe(18)
    now = int(time.time())
    expires = now + (ttl if ttl is not None else config.INVITE_TTL)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO invites (code, created_at, expires_at, note) VALUES (?, ?, ?, ?)",
            (code, now, expires, note),
        )
    return code, expires


def consume_invite(code: str) -> bool:
    """原子性地消耗邀請碼。已用或過期回 False。"""
    now = int(time.time())
    with _connect() as conn:
        cur = conn.execute(
            """UPDATE invites SET used_at = ?
               WHERE code = ? AND used_at IS NULL AND expires_at > ?""",
            (now, code, now),
        )
        return cur.rowcount == 1


def bind_invite(code: str, uid: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE invites SET used_by = ? WHERE code = ?", (uid, code))


def release_invite(code: str) -> None:
    """註冊失敗時歸還邀請碼。"""
    with _connect() as conn:
        conn.execute("UPDATE invites SET used_at = NULL WHERE code = ? AND used_by IS NULL", (code,))


def purge_expired_invites() -> int:
    now = int(time.time())
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM invites WHERE (expires_at < ? AND used_at IS NULL) OR used_at < ?",
            (now, now - 86400),
        )
        return cur.rowcount
