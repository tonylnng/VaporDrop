"""易失儲存層：Redis 存 metadata 與 session，tmpfs 存密文位元組。

不變式：
  1. 所有 Redis key 必須帶 TTL。無 TTL 的 key 視為 bug。
  2. content session 的 TTL 一經設定即不再延長（10 分鐘為硬上限）。
  3. 刪除檔案前先以隨機資料覆寫，再 unlink。
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import time
from typing import Any

import redis.asyncio as aioredis

from . import config

_redis: aioredis.Redis | None = None


def redis_client() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(config.REDIS_URL, decode_responses=True)
    return _redis


async def close() -> None:
    global _redis
    if _redis is not None:
        await _redis.close()
        _redis = None


# --- key 命名 ---------------------------------------------------------
def k_auth(sid: str) -> str:
    return f"auth:{sid}"


def k_flow(kind: str, flow: str) -> str:
    return f"chal:{kind}:{flow}"


def k_meta(cid: str) -> str:
    return f"blob:{cid}:meta"


def k_items(cid: str) -> str:
    return f"blob:{cid}:items"


def k_token(token: str) -> str:
    return f"tok:{token}"


def k_user_blobs(uid: str) -> str:
    return f"user:{uid}:blobs"


def new_id(nbytes: int = 16) -> str:
    """128-bit CSPRNG 識別碼。"""
    return secrets.token_urlsafe(nbytes)


# --- 登入 session -----------------------------------------------------
async def session_create(uid: str) -> str:
    sid = new_id(32)
    await redis_client().set(k_auth(sid), uid, ex=config.IDLE_TIMEOUT)
    return sid


async def session_touch(sid: str) -> str | None:
    """讀取並滑動續期。回 uid 或 None。"""
    r = redis_client()
    uid = await r.get(k_auth(sid))
    if uid is None:
        return None
    await r.expire(k_auth(sid), config.IDLE_TIMEOUT)
    return uid


async def session_destroy(sid: str) -> None:
    await redis_client().delete(k_auth(sid))


# --- WebAuthn flow 暫存 ------------------------------------------------
async def flow_put(kind: str, payload: dict[str, Any]) -> str:
    flow = new_id()
    await redis_client().set(k_flow(kind, flow), json.dumps(payload), ex=config.FLOW_TTL)
    return flow


async def flow_take(kind: str, flow: str) -> dict[str, Any] | None:
    """一次性取出：取出即刪，防止 challenge 重放。"""
    r = redis_client()
    key = k_flow(kind, flow)
    async with r.pipeline(transaction=True) as pipe:
        pipe.get(key)
        pipe.delete(key)
        raw, _ = await pipe.execute()
    return json.loads(raw) if raw else None


# --- content session ---------------------------------------------------
async def content_create(uid: str, burn: bool, plain: bool, label: str) -> dict[str, Any]:
    r = redis_client()
    active = await r.scard(k_user_blobs(uid))
    if active >= config.MAX_ACTIVE_SESSIONS_PER_USER:
        raise QuotaError(
            f"同時最多 {config.MAX_ACTIVE_SESSIONS_PER_USER} 個 session，請先銷毀或等待過期"
        )

    cid = new_id()
    now = int(time.time())
    meta = {
        "owner": uid,
        "created_at": str(now),
        "expires_at": str(now + config.CONTENT_TTL),
        "burn": "1" if burn else "0",
        "plain": "1" if plain else "0",
        "label": label[:120],
        "bytes": "0",
    }
    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(k_meta(cid), mapping=meta)
        pipe.expire(k_meta(cid), config.CONTENT_TTL)
        pipe.sadd(k_user_blobs(uid), cid)
        pipe.expire(k_user_blobs(uid), config.IDLE_TIMEOUT + config.CONTENT_TTL)
        await pipe.execute()

    os.makedirs(os.path.join(config.BLOB_DIR, cid), mode=0o700, exist_ok=True)
    return {"cid": cid, **meta}


async def content_meta(cid: str) -> dict[str, str] | None:
    meta = await redis_client().hgetall(k_meta(cid))
    return meta or None


async def content_list(uid: str) -> list[dict[str, Any]]:
    r = redis_client()
    cids = await r.smembers(k_user_blobs(uid))
    out: list[dict[str, Any]] = []
    stale: list[str] = []
    for cid in cids:
        meta = await r.hgetall(k_meta(cid))
        if not meta:
            stale.append(cid)
            continue
        ttl = await r.ttl(k_meta(cid))
        items = await r.hgetall(k_items(cid))
        out.append(
            {
                "cid": cid,
                "label": meta.get("label", ""),
                "burn": meta.get("burn") == "1",
                "plain": meta.get("plain") == "1",
                "bytes": int(meta.get("bytes", "0")),
                "ttl": max(ttl, 0),
                "items": [_item_public(i, json.loads(v)) for i, v in items.items()],
            }
        )
    if stale:
        await r.srem(k_user_blobs(uid), *stale)
    out.sort(key=lambda x: x["ttl"], reverse=True)
    return out


def item_public(iid: str, rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "item_id": iid,
        "kind": rec.get("kind", "file"),
        "name": rec.get("name", ""),          # 密文（base64url），伺服器不知其明文
        "size": rec.get("size", 0),
        "iv_len": rec.get("iv_len", 12),
    }


_item_public = item_public  # 舊名保留


async def content_add_item(
    cid: str, uid: str, kind: str, enc_name: str, data: bytes
) -> dict[str, Any]:
    r = redis_client()
    meta = await r.hgetall(k_meta(cid))
    if not meta:
        raise NotFoundError("session 不存在或已過期")
    if meta.get("owner") != uid:
        raise NotFoundError("session 不存在或已過期")  # 不洩漏存在性

    if len(data) > config.MAX_ITEM_BYTES:
        raise QuotaError(f"單項超過上限 {config.MAX_ITEM_BYTES} bytes")
    if int(meta.get("bytes", "0")) + len(data) > config.MAX_SESSION_BYTES:
        raise QuotaError(f"session 總量超過上限 {config.MAX_SESSION_BYTES} bytes")
    if await r.hlen(k_items(cid)) >= config.MAX_ITEMS_PER_SESSION:
        raise QuotaError(f"項目數超過上限 {config.MAX_ITEMS_PER_SESSION}")

    iid = new_id(12)
    path = _item_path(cid, iid)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    # 直寫 tmpfs（RAM），不經任何暫存磁碟路徑
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        _shred_file(path)
        raise

    rec = {"kind": kind, "name": enc_name, "size": len(data), "iv_len": 12}
    ttl = await r.ttl(k_meta(cid))
    ttl = ttl if ttl and ttl > 0 else config.CONTENT_TTL
    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(k_items(cid), iid, json.dumps(rec))
        pipe.expire(k_items(cid), ttl)          # 對齊 meta 剩餘 TTL，不延長
        pipe.hincrby(k_meta(cid), "bytes", len(data))
        await pipe.execute()
    return _item_public(iid, rec)


async def content_read_item(cid: str, iid: str) -> tuple[bytes, dict[str, Any]] | None:
    r = redis_client()
    raw = await r.hget(k_items(cid), iid)
    if not raw:
        return None
    rec = json.loads(raw)
    path = _item_path(cid, iid)
    if not os.path.exists(path):
        await r.hdel(k_items(cid), iid)
        return None
    with open(path, "rb") as fh:
        return fh.read(), rec


async def content_burn_item(cid: str, iid: str) -> None:
    r = redis_client()
    await r.hdel(k_items(cid), iid)
    _shred_file(_item_path(cid, iid))
    if await r.hlen(k_items(cid)) == 0:
        meta = await r.hgetall(k_meta(cid))
        await content_destroy(cid, meta.get("owner"))


async def content_destroy(cid: str, uid: str | None = None) -> None:
    r = redis_client()
    if uid is None:
        uid = await r.hget(k_meta(cid), "owner")
    async with r.pipeline(transaction=True) as pipe:
        pipe.delete(k_meta(cid))
        pipe.delete(k_items(cid))
        if uid:
            pipe.srem(k_user_blobs(uid), cid)
        await pipe.execute()
    # 撤銷所有指向此 session 的 token
    async for key in r.scan_iter(match="tok:*", count=200):
        if await r.hget(key, "cid") == cid:
            await r.delete(key)
    _shred_dir(os.path.join(config.BLOB_DIR, cid))


async def content_destroy_all_for_user(uid: str) -> int:
    r = redis_client()
    cids = await r.smembers(k_user_blobs(uid))
    for cid in cids:
        await content_destroy(cid, uid)
    await r.delete(k_user_blobs(uid))
    return len(cids)


# --- 一次性 token ------------------------------------------------------
async def token_create(cid: str, uses: int) -> tuple[str, int]:
    r = redis_client()
    ttl = await r.ttl(k_meta(cid))
    if not ttl or ttl <= 0:
        raise NotFoundError("session 不存在或已過期")
    uses = max(1, min(uses, config.MAX_TOKEN_USES))
    token = new_id(32)
    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(k_token(token), mapping={"cid": cid, "uses": str(uses)})
        pipe.expire(k_token(token), ttl)     # token 絕不長於內容本身
        await pipe.execute()
    return token, ttl


async def token_peek(token: str) -> str | None:
    """只驗證 token 有效性，不扣減次數（用於列 metadata）。"""
    return await redis_client().hget(k_token(token), "cid")


async def token_spend(token: str) -> str | None:
    """驗證並扣減使用次數。回 cid 或 None。"""
    r = redis_client()
    key = k_token(token)
    if not await r.exists(key):
        return None
    remaining = await r.hincrby(key, "uses", -1)
    cid = await r.hget(key, "cid")
    if remaining <= 0:
        await r.delete(key)
    return cid


# --- tmpfs 工具 --------------------------------------------------------
def _item_path(cid: str, iid: str) -> str:
    # cid / iid 皆為 token_urlsafe 產生，字元集受限；仍做一次防護性檢查
    for part in (cid, iid):
        if "/" in part or ".." in part or not part:
            raise ValueError("illegal id")
    return os.path.join(config.BLOB_DIR, cid, f"{iid}.bin")


def _shred_file(path: str) -> None:
    """先覆寫再刪除。tmpfs 在 RAM，覆寫可降低殘留頁被讀出的機會。"""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as fh:
            fh.write(secrets.token_bytes(size))
            fh.flush()
            os.fsync(fh.fileno())
    except (FileNotFoundError, OSError):
        pass
    try:
        os.remove(path)
    except (FileNotFoundError, OSError):
        pass


def _shred_dir(path: str) -> None:
    if not os.path.isdir(path):
        return
    for root, _dirs, files in os.walk(path):
        for name in files:
            _shred_file(os.path.join(root, name))
    shutil.rmtree(path, ignore_errors=True)


async def sweep_once() -> dict[str, int]:
    """對照 Redis 與 tmpfs，清掉沒有對應 metadata 的孤兒目錄與檔案。"""
    r = redis_client()
    removed_dirs = 0
    removed_files = 0
    if not os.path.isdir(config.BLOB_DIR):
        return {"dirs": 0, "files": 0}
    for entry in os.listdir(config.BLOB_DIR):
        cid_path = os.path.join(config.BLOB_DIR, entry)
        if not os.path.isdir(cid_path):
            continue
        if not await r.exists(k_meta(entry)):
            _shred_dir(cid_path)
            removed_dirs += 1
            continue
        known = set(await r.hkeys(k_items(entry)))
        for fname in os.listdir(cid_path):
            if not fname.endswith(".bin"):
                continue
            if fname[:-4] not in known:
                _shred_file(os.path.join(cid_path, fname))
                removed_files += 1
    return {"dirs": removed_dirs, "files": removed_files}


async def stats() -> dict[str, Any]:
    """無身份計數，供 /metrics 使用。不含任何用戶或內容資訊。"""
    r = redis_client()
    sessions = 0
    async for _ in r.scan_iter(match="blob:*:meta", count=200):
        sessions += 1
    total = 0
    if os.path.isdir(config.BLOB_DIR):
        for root, _d, files in os.walk(config.BLOB_DIR):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    return {"active_sessions": sessions, "bytes_in_ram": total}


class QuotaError(Exception):
    pass


class NotFoundError(Exception):
    pass
