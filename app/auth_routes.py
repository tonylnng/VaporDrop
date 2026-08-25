"""Passkey / WebAuthn 認證端點。

流程要點：
  * 註冊必須帶一次性邀請碼（首次部署可 bootstrap 第一個用戶）。
  * challenge 存在 Redis，取出即刪，無法重放。
  * 使用 discoverable credential（resident key），登入時不需輸入任何帳號。
  * sign_count 必須單調遞增，否則拒絕（偵測憑證複製）。
"""
from __future__ import annotations

import asyncio
import json
import re

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from . import config, db, security, store

router = APIRouter(prefix="/auth", tags=["auth"])

HANDLE_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class RegisterBegin(BaseModel):
    handle: str = Field(min_length=3, max_length=32)
    invite: str = ""
    label: str = Field(default="", max_length=60)


class RegisterFinish(BaseModel):
    flow: str
    credential: dict


class LoginFinish(BaseModel):
    flow: str
    credential: dict


@router.get("/state")
async def auth_state(request: Request):
    """前端啟動時用：是否已登入、是否需要 bootstrap 註冊。"""
    users = await asyncio.to_thread(db.user_count)
    sid = request.cookies.get(config.COOKIE_NAME)
    uid = await store.session_touch(sid) if sid else None
    handle = ""
    if uid:
        user = await asyncio.to_thread(db.get_user, uid)
        handle = user["handle"] if user else ""
    return {
        "authenticated": uid is not None,
        "handle": handle,
        "bootstrap": users == 0 and config.ALLOW_FIRST_USER_BOOTSTRAP,
        "google": config.google_enabled(),
        "idle_timeout": config.IDLE_TIMEOUT,
        "content_ttl": config.CONTENT_TTL,
        "allow_plain": config.ALLOW_SERVER_SIDE_PLAIN,
        "max_item_bytes": config.MAX_ITEM_BYTES,
        "max_session_bytes": config.MAX_SESSION_BYTES,
    }


@router.post("/register/begin")
async def register_begin(request: Request, body: RegisterBegin):
    security.rate_limit(request, "auth", config.RL_AUTH_PER_MIN)
    security.require_same_origin(request)

    if not HANDLE_RE.match(body.handle):
        raise HTTPException(status_code=400, detail="handle 只允許 3-32 個字母、數字、. _ -")

    users = await asyncio.to_thread(db.user_count)
    bootstrap = users == 0 and config.ALLOW_FIRST_USER_BOOTSTRAP

    existing = await asyncio.to_thread(db.get_user_by_handle, body.handle)
    if existing and not bootstrap:
        # 已存在的 handle 要加新裝置，必須先登入後走 /auth/credentials/add
        raise HTTPException(status_code=409, detail="此 handle 已存在，請登入後在設定中新增裝置")

    invite_code = ""
    if not bootstrap:
        if not body.invite:
            raise HTTPException(status_code=403, detail="需要邀請碼")
        if not await asyncio.to_thread(db.consume_invite, body.invite.strip()):
            raise HTTPException(status_code=403, detail="邀請碼無效或已使用")
        invite_code = body.invite.strip()

    uid = await asyncio.to_thread(db.create_user, body.handle)
    if invite_code:
        await asyncio.to_thread(db.bind_invite, invite_code, uid)

    options = generate_registration_options(
        rp_id=config.RP_ID,
        rp_name=config.RP_NAME,
        user_id=uid.encode(),
        user_name=body.handle,
        user_display_name=body.handle,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        timeout=120_000,
    )
    flow = await store.flow_put(
        "reg",
        {
            "uid": uid,
            "challenge": bytes_to_base64url(options.challenge),
            "label": body.label,
        },
    )
    return {"flow": flow, "options": json.loads(options_to_json(options))}


@router.post("/register/finish")
async def register_finish(request: Request, body: RegisterFinish, response: Response):
    security.rate_limit(request, "auth", config.RL_AUTH_PER_MIN)
    security.require_same_origin(request)

    ctx = await store.flow_take("reg", body.flow)
    if ctx is None:
        raise HTTPException(status_code=400, detail="註冊流程已逾時，請重新開始")

    try:
        verified = verify_registration_response(
            credential=json.dumps(body.credential),
            expected_challenge=base64url_to_bytes(ctx["challenge"]),
            expected_origin=config.ORIGINS,
            expected_rp_id=config.RP_ID,
            require_user_verification=True,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="憑證驗證失敗")

    transports = ",".join(
        t for t in (body.credential.get("response", {}).get("transports") or []) if isinstance(t, str)
    )
    await asyncio.to_thread(
        db.add_credential,
        bytes_to_base64url(verified.credential_id),
        ctx["uid"],
        verified.credential_public_key,
        verified.sign_count,
        transports,
        ctx.get("label", ""),
    )

    sid = await store.session_create(ctx["uid"])
    security.set_session_cookie(response, sid)
    return {"ok": True}


@router.post("/login/begin")
async def login_begin(request: Request):
    security.rate_limit(request, "auth", config.RL_AUTH_PER_MIN)
    security.require_same_origin(request)

    options = generate_authentication_options(
        rp_id=config.RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=120_000,
    )
    flow = await store.flow_put("auth", {"challenge": bytes_to_base64url(options.challenge)})
    return {"flow": flow, "options": json.loads(options_to_json(options))}


@router.post("/login/finish")
async def login_finish(request: Request, body: LoginFinish, response: Response):
    security.rate_limit(request, "auth", config.RL_AUTH_PER_MIN)
    security.require_same_origin(request)

    ctx = await store.flow_take("auth", body.flow)
    if ctx is None:
        raise HTTPException(status_code=400, detail="登入流程已逾時，請重試")

    cred_id = body.credential.get("id") or body.credential.get("rawId")
    if not cred_id:
        raise HTTPException(status_code=400, detail="憑證格式錯誤")

    record = await asyncio.to_thread(db.get_credential, cred_id)
    if record is None:
        raise HTTPException(status_code=401, detail="認證失敗")

    user = await asyncio.to_thread(db.get_user, record["uid"])
    if user is None or user["disabled"]:
        raise HTTPException(status_code=401, detail="認證失敗")

    try:
        verified = verify_authentication_response(
            credential=json.dumps(body.credential),
            expected_challenge=base64url_to_bytes(ctx["challenge"]),
            expected_origin=config.ORIGINS,
            expected_rp_id=config.RP_ID,
            credential_public_key=record["public_key"],
            credential_current_sign_count=record["sign_count"],
            require_user_verification=True,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="認證失敗")

    await asyncio.to_thread(db.touch_credential, cred_id, verified.new_sign_count)
    sid = await store.session_create(record["uid"])
    security.set_session_cookie(response, sid)
    return {"ok": True, "handle": user["handle"]}


@router.post("/credentials/add/begin")
async def add_credential_begin(request: Request):
    """已登入用戶為新裝置註冊多一把 Passkey。"""
    uid = await security.current_uid(request)
    security.require_same_origin(request)
    user = await asyncio.to_thread(db.get_user, uid)
    existing = await asyncio.to_thread(db.credentials_for_uid, uid)

    from webauthn.helpers.structs import PublicKeyCredentialDescriptor

    options = generate_registration_options(
        rp_id=config.RP_ID,
        rp_name=config.RP_NAME,
        user_id=uid.encode(),
        user_name=user["handle"],
        user_display_name=user["handle"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"]))
            for c in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        timeout=120_000,
    )
    flow = await store.flow_put(
        "reg", {"uid": uid, "challenge": bytes_to_base64url(options.challenge), "label": ""}
    )
    return {"flow": flow, "options": json.loads(options_to_json(options))}


@router.get("/credentials")
async def list_credentials(request: Request):
    uid = await security.current_uid(request)
    creds = await asyncio.to_thread(db.credentials_for_uid, uid)
    return {
        "credentials": [
            {
                "credential_id": c["credential_id"],
                "label": c["label"],
                "transports": c["transports"],
                "created_at": c["created_at"],
                "last_used_at": c["last_used_at"],
            }
            for c in creds
        ]
    }


@router.delete("/credentials/{credential_id}")
async def delete_credential(request: Request, credential_id: str):
    uid = await security.current_uid(request)
    security.require_same_origin(request)
    creds = await asyncio.to_thread(db.credentials_for_uid, uid)
    if len(creds) <= 1:
        raise HTTPException(status_code=400, detail="至少需保留一把 Passkey")
    if not await asyncio.to_thread(db.delete_credential, credential_id, uid):
        raise HTTPException(status_code=404, detail="找不到憑證")
    return {"ok": True}


@router.post("/logout")
async def logout(request: Request, response: Response):
    """登出：撤銷 session，並連帶銷毀該用戶所有未過期內容。"""
    sid = request.cookies.get(config.COOKIE_NAME)
    destroyed = 0
    if sid:
        uid = await store.session_touch(sid)
        if uid:
            destroyed = await store.content_destroy_all_for_user(uid)
        await store.session_destroy(sid)
    security.clear_session_cookie(response)
    return {"ok": True, "sessions_destroyed": destroyed}
