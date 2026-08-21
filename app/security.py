"""安全中介層：回應標頭、Origin 檢查、無身份速率限制、認證依賴。"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from . import config, store

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    # 明示本服務不希望被索引或存檔
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        # 移除可能洩漏版本的標頭
        if "server" in response.headers:
            del response.headers["server"]
        return response


# --- 速率限制 ---------------------------------------------------------
# 完全在記憶體內。IP 只以每日輪換的 salt 做 HMAC 後當作桶的 key，
# 原文 IP 不進入任何資料結構，程序重啟即無痕。
_buckets: dict[str, deque[float]] = defaultdict(deque)
_salt = secrets.token_bytes(32)
_salt_day = int(time.time()) // 86400


def _client_bucket(request: Request) -> str:
    global _salt, _salt_day
    day = int(time.time()) // 86400
    if day != _salt_day:
        _salt = secrets.token_bytes(32)
        _salt_day = day
        _buckets.clear()
    host = request.client.host if request.client else "unknown"
    return hmac.new(_salt, host.encode(), hashlib.sha256).hexdigest()[:16]


def rate_limit(request: Request, scope: str, per_min: int) -> None:
    key = f"{scope}:{_client_bucket(request)}"
    now = time.monotonic()
    bucket = _buckets[key]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= per_min:
        raise HTTPException(status_code=429, detail="請求過於頻繁，請稍後再試")
    bucket.append(now)
    if len(_buckets) > 10000:  # 防止記憶體膨脹
        for k in list(_buckets)[:5000]:
            if not _buckets[k]:
                _buckets.pop(k, None)


# --- Origin / CSRF ----------------------------------------------------
def require_same_origin(request: Request) -> None:
    """狀態變更請求必須帶合法 Origin。搭配 SameSite=Strict 形成雙重防護。"""
    origin = request.headers.get("origin")
    if origin is None:
        # 非瀏覽器客戶端（curl / Agent）不帶 Origin，但它們只能用 Bearer token
        # 存取唯讀端點；此處只在 cookie 認證路徑上要求 Origin。
        if request.cookies.get(config.COOKIE_NAME):
            raise HTTPException(status_code=403, detail="缺少 Origin")
        return
    if origin not in config.ORIGINS:
        raise HTTPException(status_code=403, detail="Origin 不被允許")


# --- 認證依賴 ---------------------------------------------------------
async def current_uid(request: Request) -> str:
    sid = request.cookies.get(config.COOKIE_NAME)
    if not sid:
        raise HTTPException(status_code=401, detail="未登入")
    uid = await store.session_touch(sid)
    if uid is None:
        raise HTTPException(status_code=401, detail="session 已逾時，請重新登入")
    request.state.sid = sid
    request.state.uid = uid
    return uid


def set_session_cookie(response, sid: str) -> None:
    response.set_cookie(
        key=config.COOKIE_NAME,
        value=sid,
        max_age=config.IDLE_TIMEOUT,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(key=config.COOKIE_NAME, path="/", samesite="strict")


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
