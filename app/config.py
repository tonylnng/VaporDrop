"""集中設定。全部來自環境變數，無預設密鑰、無硬編碼秘密。"""
from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, "true" if default else "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# --- 基礎設施 ---------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
BLOB_DIR = os.getenv("BLOB_DIR", "/vapor")
DB_PATH = os.getenv("DB_PATH", "/data/vapor.db")
STATIC_DIR = os.getenv("STATIC_DIR", os.path.join(os.path.dirname(__file__), "static"))

# --- 時間邊界（秒）----------------------------------------------------
CONTENT_TTL = _int("CONTENT_TTL_SECONDS", 600)          # content session 硬上限，永不續期
IDLE_TIMEOUT = _int("IDLE_TIMEOUT_SECONDS", 1800)       # 登入 session 滑動逾時
INVITE_TTL = _int("INVITE_TTL_SECONDS", 900)
FLOW_TTL = _int("FLOW_TTL_SECONDS", 300)                # WebAuthn challenge 存活期
SWEEP_INTERVAL = _int("SWEEP_INTERVAL_SECONDS", 30)

# --- 配額 -------------------------------------------------------------
MAX_ITEM_BYTES = _int("MAX_ITEM_BYTES", 32 * 1024 * 1024)
MAX_SESSION_BYTES = _int("MAX_SESSION_BYTES", 128 * 1024 * 1024)
MAX_ITEMS_PER_SESSION = _int("MAX_ITEMS_PER_SESSION", 50)
MAX_ACTIVE_SESSIONS_PER_USER = _int("MAX_ACTIVE_SESSIONS_PER_USER", 5)
MAX_TOKEN_USES = _int("MAX_TOKEN_USES", 20)

# --- WebAuthn ---------------------------------------------------------
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "VaporDrop")
# 逗號分隔，必須含 scheme，例如 https://vapor.example.com
ORIGINS = [o.strip() for o in os.getenv("ORIGINS", "http://localhost:8080").split(",") if o.strip()]

# --- Google 登入（OIDC）----------------------------------------------
# 空白 = 停用 Google 登入，只保留 Passkey。
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
# 未設定時由 ORIGINS[0] 推導出 <origin>/auth/google/callback
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
GOOGLE_AUTH_ENDPOINT = os.getenv(
    "GOOGLE_AUTH_ENDPOINT", "https://accounts.google.com/o/oauth2/v2/auth"
)
GOOGLE_TOKEN_ENDPOINT = os.getenv("GOOGLE_TOKEN_ENDPOINT", "https://oauth2.googleapis.com/token")

# 白名單：逗號分隔的 email（全小寫比對）。與 ALLOWED_DOMAIN 任一命中即放行。
ALLOWED_EMAILS = [
    e.strip().lower() for e in os.getenv("ALLOWED_EMAILS", "").split(",") if e.strip()
]
# 整個 Google Workspace 網域放行；同時作為 hd 參數送給 Google。
ALLOWED_DOMAIN = os.getenv("ALLOWED_DOMAIN", "").strip().lower()

# uid = HMAC(UID_PEPPER, email)。資料庫因此只存不可逆的識別碼，不存 email 原文。
# 一旦部署後更換此值，所有既有帳號會變成新帳號。
UID_PEPPER = os.getenv("UID_PEPPER", "").strip()

# true = handle 用 email 的 @ 前半部（好認，但等於在 DB 留下部分個資）
# false = handle 用 g-<uid 前綴>（完全不可辨識，管理員可用 cli whois 反查）
STORE_EMAIL_HANDLE = _bool("STORE_EMAIL_HANDLE", False)

# 緊急登入連結（break-glass）有效秒數
RESCUE_TTL = _int("RESCUE_TTL_SECONDS", 600)


def google_enabled() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and UID_PEPPER)


def google_redirect_uri() -> str:
    if GOOGLE_REDIRECT_URI:
        return GOOGLE_REDIRECT_URI
    base = ORIGINS[0].rstrip("/") if ORIGINS else "http://localhost:8080"
    return f"{base}/auth/google/callback"


# --- Cookie -----------------------------------------------------------
COOKIE_NAME = os.getenv("COOKIE_NAME", "vsid")
COOKIE_SECURE = _bool("COOKIE_SECURE", True)

# --- 行為開關 ---------------------------------------------------------
# 啟用後，session 可標記 plain=true：伺服器直接存明文，接收方一條 curl 即可取用。
# 代價是喪失零知識性質。預設關閉。
ALLOW_SERVER_SIDE_PLAIN = _bool("ALLOW_SERVER_SIDE_PLAIN", False)

# 是否允許在無邀請碼時註冊第一個用戶（首次部署 bootstrap 用，建立後自動失效）
ALLOW_FIRST_USER_BOOTSTRAP = _bool("ALLOW_FIRST_USER_BOOTSTRAP", True)

# --- 速率限制 ---------------------------------------------------------
RL_AUTH_PER_MIN = _int("RL_AUTH_PER_MIN", 10)
RL_API_PER_MIN = _int("RL_API_PER_MIN", 120)
RL_RAW_PER_MIN = _int("RL_RAW_PER_MIN", 60)
