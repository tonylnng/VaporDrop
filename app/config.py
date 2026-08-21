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
