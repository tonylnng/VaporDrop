"""Content session 端點：開 session、上傳密文、產生一次性 token、供 Agent 讀取。

伺服器對內容的認知僅限：位元組長度、kind 標記、以及一個它無法解密的名稱欄位。
"""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config, security, store

router = APIRouter(tags=["sessions"])


class CreateSession(BaseModel):
    label: str = Field(default="", max_length=120)
    burn_after_read: bool = False
    plain: bool = False


class CreateToken(BaseModel):
    uses: int = Field(default=1, ge=1, le=100)


# --- 擁有者操作（cookie 認證）------------------------------------------
@router.post("/api/sessions")
async def create_session(request: Request, body: CreateSession):
    uid = await security.current_uid(request)
    security.require_same_origin(request)
    security.rate_limit(request, "api", config.RL_API_PER_MIN)

    if body.plain and not config.ALLOW_SERVER_SIDE_PLAIN:
        raise HTTPException(status_code=400, detail="伺服器端明文模式已停用")

    try:
        meta = await store.content_create(uid, body.burn_after_read, body.plain, body.label)
    except store.QuotaError as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    return {
        "cid": meta["cid"],
        "expires_at": int(meta["expires_at"]),
        "ttl": config.CONTENT_TTL,
        "burn": body.burn_after_read,
        "plain": body.plain,
    }


@router.get("/api/sessions")
async def list_sessions(request: Request):
    uid = await security.current_uid(request)
    security.rate_limit(request, "api", config.RL_API_PER_MIN)
    return {"sessions": await store.content_list(uid)}


@router.put("/api/sessions/{cid}/items")
async def put_item(
    request: Request,
    cid: str,
    x_vapor_name: str = Header(default=""),
    x_vapor_kind: str = Header(default="file"),
):
    """上傳一個 item。body 為原始位元組（零知識模式下是 iv||ciphertext）。

    名稱本身也已在瀏覽器加密，透過 X-Vapor-Name 以 base64url 傳遞。
    """
    uid = await security.current_uid(request)
    security.require_same_origin(request)
    security.rate_limit(request, "api", config.RL_API_PER_MIN)

    declared = request.headers.get("content-length")
    if declared and int(declared) > config.MAX_ITEM_BYTES:
        raise HTTPException(status_code=413, detail="單項超過上限")
    if x_vapor_kind not in {"text", "file"}:
        raise HTTPException(status_code=400, detail="kind 必須是 text 或 file")
    if len(x_vapor_name) > 4096:
        raise HTTPException(status_code=400, detail="名稱欄位過長")

    data = await request.body()
    if not data:
        raise HTTPException(status_code=400, detail="內容為空")

    try:
        item = await store.content_add_item(cid, uid, x_vapor_kind, x_vapor_name, data)
    except store.QuotaError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except store.NotFoundError:
        raise HTTPException(status_code=404, detail="session 不存在或已過期")
    return item


@router.delete("/api/sessions/{cid}")
async def destroy_session(request: Request, cid: str):
    uid = await security.current_uid(request)
    security.require_same_origin(request)
    meta = await store.content_meta(cid)
    if not meta or meta.get("owner") != uid:
        raise HTTPException(status_code=404, detail="session 不存在或已過期")
    await store.content_destroy(cid, uid)
    return {"ok": True}


@router.post("/api/sessions/{cid}/tokens")
async def create_token(request: Request, cid: str, body: CreateToken):
    uid = await security.current_uid(request)
    security.require_same_origin(request)
    security.rate_limit(request, "api", config.RL_API_PER_MIN)

    meta = await store.content_meta(cid)
    if not meta or meta.get("owner") != uid:
        raise HTTPException(status_code=404, detail="session 不存在或已過期")
    try:
        token, ttl = await store.token_create(cid, body.uses)
    except store.NotFoundError:
        raise HTTPException(status_code=404, detail="session 不存在或已過期")
    return {"token": token, "uses": min(body.uses, config.MAX_TOKEN_USES), "ttl": ttl}


# --- 接收方操作（Bearer token 或 cookie）-------------------------------
async def _authorize_read(request: Request, cid: str, spend: bool) -> dict[str, str]:
    """回傳 meta。Bearer token 綁定單一 cid；擁有者亦可用 cookie 讀取。"""
    meta = await store.content_meta(cid)
    auth = request.headers.get("authorization", "")

    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if spend:
            token_cid = await store.token_spend(token)
        else:
            token_cid = await store.token_peek(token)
        if not token_cid or not meta or not security.constant_time_eq(token_cid, cid):
            raise HTTPException(status_code=404, detail="not found")
        return meta

    sid = request.cookies.get(config.COOKIE_NAME)
    if sid:
        uid = await store.session_touch(sid)
        if uid and meta and meta.get("owner") == uid:
            return meta

    raise HTTPException(status_code=404, detail="not found")


@router.get("/api/receive/{cid}")
async def receive_meta(request: Request, cid: str):
    """接收方列出 session 內的項目。不消耗 token 次數（讀 metadata 不算取用）。"""
    security.rate_limit(request, "raw", config.RL_RAW_PER_MIN)
    meta = await _authorize_read(request, cid, spend=False)
    r = store.redis_client()
    ttl = await r.ttl(store.k_meta(cid))
    items_raw = await r.hgetall(store.k_items(cid))
    import json as _json

    return {
        "cid": cid,
        "label": meta.get("label", ""),
        "plain": meta.get("plain") == "1",
        "burn": meta.get("burn") == "1",
        "ttl": max(ttl, 0),
        "items": [store._item_public(i, _json.loads(v)) for i, v in items_raw.items()],
    }


@router.get("/s/{cid}/raw")
async def raw(request: Request, cid: str, item: str | None = None):
    """給 VM / AI Agent 的取用端點。

    零知識模式回 iv||ciphertext，需以帶外遞送的金鑰在本地解密。
    plain 模式（需在部署時啟用）直接回明文，適合 tailnet 內一條 curl 取用。
    """
    security.rate_limit(request, "raw", config.RL_RAW_PER_MIN)
    meta = await _authorize_read(request, cid, spend=True)

    r = store.redis_client()
    items = await r.hkeys(store.k_items(cid))
    if not items:
        raise HTTPException(status_code=404, detail="not found")
    iid = item or items[0]
    if iid not in items:
        raise HTTPException(status_code=404, detail="not found")

    result = await store.content_read_item(cid, iid)
    if result is None:
        raise HTTPException(status_code=404, detail="not found")
    data, rec = result

    plain = meta.get("plain") == "1"
    media = "text/plain; charset=utf-8" if (plain and rec.get("kind") == "text") else "application/octet-stream"
    headers = {
        "X-Vapor-Kind": rec.get("kind", "file"),
        "X-Vapor-Plain": "1" if plain else "0",
        "X-Vapor-Items": str(len(items)),
        # 永不 inline 渲染，避免上傳內容變成 XSS
        "Content-Disposition": f'attachment; filename="{iid}.bin"',
    }
    if rec.get("name"):
        headers["X-Vapor-Name"] = rec["name"]

    if meta.get("burn") == "1":
        await store.content_burn_item(cid, iid)

    return Response(content=data, media_type=media, headers=headers)


@router.get("/s/{cid}/manifest")
async def manifest(request: Request, cid: str):
    """給腳本用的項目清單（不消耗 token）。"""
    security.rate_limit(request, "raw", config.RL_RAW_PER_MIN)
    await _authorize_read(request, cid, spend=False)
    r = store.redis_client()
    items_raw = await r.hgetall(store.k_items(cid))
    ttl = await r.ttl(store.k_meta(cid))
    import json as _json

    return JSONResponse(
        {
            "cid": cid,
            "ttl": max(ttl, 0),
            "items": [store._item_public(i, _json.loads(v)) for i, v in items_raw.items()],
        }
    )
