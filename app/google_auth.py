"""Google 登入（OpenID Connect）與緊急登入（break-glass）。

設計取捨，逐條說明：

1. 用「伺服器端 Authorization Code + PKCE」，不用 Google 的 JS SDK。
   One Tap / GIS 按鈕需要從 accounts.google.com 載入腳本，會迫使我們放寬
   CSP 的 script-src。改成純轉址後，前端只是一個 <a>，CSP 一個字都不用動。

2. state / nonce / code_verifier 全部存在 Redis（flow_put，取出即刪、300 秒過期），
   不用 cookie。原因：callback 是從 Google 過來的跨站導覽，SameSite=Strict
   cookie 不會被送出。把狀態放伺服器端反而更乾淨，也天然防 login CSRF。

3. id_token 不做簽章驗證，只驗 claims。依據 Google 官方 OIDC 文件：token 是我們
   自己用 client_secret 在後端直連 HTTPS token endpoint 換回來的，通道本身已可信，
   因此可略過簽章驗證。若哪天改成從前端接收 id_token，就必須加上 JWKS 驗簽。
   https://developers.google.com/identity/openid-connect/openid-connect

4. 資料庫不存 email。uid = HMAC-SHA256(UID_PEPPER, 小寫 email) 的前 32 個 hex 字。
   同一個 email 永遠對到同一個 uid，但拿到資料庫也反推不出是誰（除非同時拿到
   .env 裡的 UID_PEPPER 並逐一猜測 email）。

5. 失敗一律導回 /?e=<短碼>，不回傳細節，也不寫任何日誌。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from . import config, db, security, store

router = APIRouter(prefix="/auth", tags=["auth"])

_ALLOWED_ISS = {"https://accounts.google.com", "accounts.google.com"}
_CLOCK_SKEW = 120  # 秒，容忍 VM 與 Google 之間的時鐘偏差
_HANDLE_OK = set("abcdefghijklmnopqrstuvwxyz0123456789._-")


# --- 小工具 -----------------------------------------------------------
def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def uid_for_email(email: str) -> str:
    """email → 不可逆 uid。同一 email 恆定，換 pepper 則全部失效。"""
    mac = hmac.new(config.UID_PEPPER.encode(), email.strip().lower().encode(), hashlib.sha256)
    return mac.hexdigest()[:32]


def handle_for(email: str, uid: str) -> str:
    """顯示名。預設完全不可辨識；開啟 STORE_EMAIL_HANDLE 才用 email 前半部。"""
    if not config.STORE_EMAIL_HANDLE:
        return f"g-{uid[:10]}"
    local = email.split("@", 1)[0].lower()
    cleaned = "".join(ch for ch in local if ch in _HANDLE_OK)[:32]
    return cleaned if len(cleaned) >= 3 else f"g-{uid[:10]}"


def email_allowed(email: str, hosted_domain: str) -> bool:
    email = email.strip().lower()
    if config.ALLOWED_EMAILS and email in config.ALLOWED_EMAILS:
        return True
    if config.ALLOWED_DOMAIN:
        domain = email.rsplit("@", 1)[-1]
        if domain == config.ALLOWED_DOMAIN and (
            not hosted_domain or hosted_domain.lower() == config.ALLOWED_DOMAIN
        ):
            return True
    return False


def _fail(code: str) -> RedirectResponse:
    """一律導回首頁，只帶一個無資訊量的短碼。"""
    return RedirectResponse(url=f"/?e={code}", status_code=303)


# --- 啟動登入 ---------------------------------------------------------
@router.get("/google/start")
async def google_start(request: Request):
    if not config.google_enabled():
        raise HTTPException(status_code=404, detail="not found")
    security.rate_limit(request, "auth", config.RL_AUTH_PER_MIN)

    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url_encode(hashlib.sha256(verifier.encode()).digest())
    # flow id 直接當 state：不可猜、一次性、300 秒過期
    state = await store.flow_put("goog", {"nonce": nonce, "verifier": verifier})

    params = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": config.google_redirect_uri(),
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        # online：我們只要一次身份確認，不需要 refresh token
        "access_type": "online",
        "prompt": "select_account",
        # 不要求任何額外授權，登入後即與 Google 斷開關係
        "include_granted_scopes": "false",
    }
    if config.ALLOWED_DOMAIN:
        params["hd"] = config.ALLOWED_DOMAIN

    return RedirectResponse(
        url=f"{config.GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}",
        status_code=303,
        headers={"Cache-Control": "no-store"},
    )


# --- 回呼 -------------------------------------------------------------
@router.get("/google/callback")
async def google_callback(request: Request):
    if not config.google_enabled():
        raise HTTPException(status_code=404, detail="not found")
    security.rate_limit(request, "auth", config.RL_AUTH_PER_MIN)

    params = request.query_params
    state = params.get("state", "")
    code = params.get("code", "")
    if params.get("error") or not code or not state:
        return _fail("denied")

    ctx = await store.flow_take("goog", state)
    if ctx is None:
        return _fail("state")

    try:
        claims = await _exchange_and_verify(code, ctx["verifier"], ctx["nonce"])
    except Exception:
        return _fail("token")
    if claims is None:
        return _fail("token")

    email = str(claims.get("email", ""))
    if not email or claims.get("email_verified") not in (True, "true"):
        return _fail("email")
    if not email_allowed(email, str(claims.get("hd", ""))):
        return _fail("nolist")

    uid = uid_for_email(email)
    user = await asyncio.to_thread(db.ensure_user, uid, handle_for(email, uid))
    if user["disabled"]:
        return _fail("nolist")

    sid = await store.session_create(uid)
    response = RedirectResponse(url="/", status_code=303)
    security.set_session_cookie(response, sid)
    response.headers["Cache-Control"] = "no-store"
    return response


async def _exchange_and_verify(code: str, verifier: str, nonce: str) -> dict | None:
    """後端直連 Google 換 id_token，然後驗 claims。任何不符即回 None。"""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            config.GOOGLE_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "redirect_uri": config.google_redirect_uri(),
                "grant_type": "authorization_code",
                "code_verifier": verifier,
            },
            headers={"Accept": "application/json"},
        )
    if resp.status_code != 200:
        return None
    id_token = resp.json().get("id_token")
    if not isinstance(id_token, str) or id_token.count(".") != 2:
        return None
    claims = json.loads(_b64url_decode(id_token.split(".")[1]))
    return await _verify_claims(claims, nonce)


async def _verify_claims(claims: dict, nonce: str) -> dict | None:
    """驗 iss / aud / exp / iat / nonce。任一不符即回 None，不區分原因。"""
    now = int(time.time())
    if claims.get("iss") not in _ALLOWED_ISS:
        return None
    aud = claims.get("aud")
    if aud != config.GOOGLE_CLIENT_ID:
        return None
    if not isinstance(claims.get("exp"), int) or claims["exp"] + _CLOCK_SKEW < now:
        return None
    if isinstance(claims.get("iat"), int) and claims["iat"] - _CLOCK_SKEW > now:
        return None
    if not security.constant_time_eq(str(claims.get("nonce", "")), nonce):
        return None
    return claims


# --- 緊急登入（break-glass）------------------------------------------
@router.get("/rescue")
async def rescue(request: Request):
    """一次性緊急登入。用於 Google 服務中斷或 OAuth client 被停用時。

    碼由 CLI 產生（python -m app.cli rescue --handle …），資料庫只存雜湊，
    有效期預設 10 分鐘，用過即失效。
    """
    security.rate_limit(request, "auth", config.RL_AUTH_PER_MIN)
    code = request.query_params.get("c", "")
    if not code:
        return _fail("rescue")

    uid = await asyncio.to_thread(db.consume_rescue_code, code)
    if uid is None:
        return _fail("rescue")
    user = await asyncio.to_thread(db.get_user, uid)
    if user is None or user["disabled"]:
        return _fail("rescue")

    sid = await store.session_create(uid)
    response = RedirectResponse(url="/", status_code=303)
    security.set_session_cookie(response, sid)
    response.headers["Cache-Control"] = "no-store"
    return response
