"""核心不變式測試：TTL 不續期、覆寫刪除、token 一次性、越權不可見、安全標頭。

以 fakeredis 取代 Redis，以 tmp 目錄取代 tmpfs，因此可在無 Docker 環境執行：
    pip install -r requirements-dev.txt && pytest -q
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BLOB_DIR", str(tmp_path / "vapor"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vapor.db"))
    monkeypatch.setenv("CONTENT_TTL_SECONDS", "600")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    for mod in [m for m in list(sys.modules) if m.startswith("app")]:
        sys.modules.pop(mod)

    import fakeredis.aioredis

    from app import config, db, store

    os.makedirs(config.BLOB_DIR, exist_ok=True)
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(store, "redis_client", lambda: fake)
    db.init()
    return store, config, db


def run(coro):
    return asyncio.run(coro)


def test_content_ttl_never_extends(env):
    store, config, _ = env

    async def scenario():
        meta = await store.content_create("u1", burn=False, plain=False, label="t")
        cid = meta["cid"]
        r = store.redis_client()
        # 人為把 TTL 壓到 5 秒，模擬「已經快到期」
        await r.expire(store.k_meta(cid), 5)
        await store.content_add_item(cid, "u1", "text", "bmFtZQ", b"x" * 32)
        ttl = await r.ttl(store.k_meta(cid))
        assert ttl <= 5, "上傳新內容不得延長 session 壽命"
        items_ttl = await r.ttl(store.k_items(cid))
        assert items_ttl <= 5, "items key 的 TTL 必須對齊 meta，不可更長"

    run(scenario())


def test_all_keys_have_ttl(env):
    store, _, _ = env

    async def scenario():
        meta = await store.content_create("u1", False, False, "")
        cid = meta["cid"]
        await store.content_add_item(cid, "u1", "file", "bmFtZQ", b"data")
        await store.token_create(cid, 1)
        r = store.redis_client()
        async for key in r.scan_iter(match="*"):
            assert await r.ttl(key) > 0, f"{key} 沒有 TTL"

    run(scenario())


def test_token_is_single_use(env):
    store, _, _ = env

    async def scenario():
        meta = await store.content_create("u1", False, False, "")
        cid = meta["cid"]
        await store.content_add_item(cid, "u1", "text", "bmFtZQ", b"payload")
        token, _ = await store.token_create(cid, 1)
        assert await store.token_spend(token) == cid
        assert await store.token_spend(token) is None, "一次性 token 不得重用"

    run(scenario())


def test_token_ttl_not_longer_than_content(env):
    store, _, _ = env

    async def scenario():
        meta = await store.content_create("u1", False, False, "")
        cid = meta["cid"]
        r = store.redis_client()
        await r.expire(store.k_meta(cid), 30)
        token, ttl = await store.token_create(cid, 5)
        assert ttl <= 30
        assert await r.ttl(store.k_token(token)) <= 30

    run(scenario())


def test_cross_user_write_is_invisible(env):
    store, _, _ = env

    async def scenario():
        meta = await store.content_create("owner", False, False, "")
        with pytest.raises(store.NotFoundError):
            await store.content_add_item(meta["cid"], "attacker", "text", "x", b"y")

    run(scenario())


def test_destroy_shreds_files(env):
    store, config, _ = env

    async def scenario():
        meta = await store.content_create("u1", False, False, "")
        cid = meta["cid"]
        item = await store.content_add_item(cid, "u1", "file", "bmFtZQ", b"secret-bytes")
        path = os.path.join(config.BLOB_DIR, cid, f"{item['item_id']}.bin")
        assert os.path.exists(path)
        await store.content_destroy(cid, "u1")
        assert not os.path.exists(path)
        assert not os.path.exists(os.path.join(config.BLOB_DIR, cid))
        assert await store.content_meta(cid) is None

    run(scenario())


def test_burn_after_read_removes_item(env):
    store, _, _ = env

    async def scenario():
        meta = await store.content_create("u1", burn=True, plain=False, label="")
        cid = meta["cid"]
        item = await store.content_add_item(cid, "u1", "text", "bmFtZQ", b"one-shot")
        assert (await store.content_read_item(cid, item["item_id"]))[0] == b"one-shot"
        await store.content_burn_item(cid, item["item_id"])
        assert await store.content_read_item(cid, item["item_id"]) is None
        # 最後一項被燒掉後整個 session 應消失
        assert await store.content_meta(cid) is None

    run(scenario())


def test_sweeper_removes_orphan_dirs(env):
    store, config, _ = env

    async def scenario():
        orphan = os.path.join(config.BLOB_DIR, "orphan-cid")
        os.makedirs(orphan, exist_ok=True)
        with open(os.path.join(orphan, "x.bin"), "wb") as fh:
            fh.write(b"leftover")
        result = await store.sweep_once()
        assert result["dirs"] >= 1
        assert not os.path.exists(orphan)

    run(scenario())


def test_logout_destroys_all_user_content(env):
    store, _, _ = env

    async def scenario():
        a = await store.content_create("u1", False, False, "")
        b = await store.content_create("u1", False, False, "")
        assert await store.content_destroy_all_for_user("u1") == 2
        assert await store.content_meta(a["cid"]) is None
        assert await store.content_meta(b["cid"]) is None

    run(scenario())


def test_quota_blocks_oversized_item(env):
    store, config, monkeypatch = env[0], env[1], None

    async def scenario():
        meta = await store.content_create("u1", False, False, "")
        big = b"x" * (config.MAX_ITEM_BYTES + 1)
        with pytest.raises(store.QuotaError):
            await store.content_add_item(meta["cid"], "u1", "file", "n", big)

    run(scenario())


def test_path_traversal_rejected(env):
    store, _, _ = env
    with pytest.raises(ValueError):
        store._item_path("../../etc", "passwd")


def test_security_headers_and_no_docs(env):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        res = client.get("/healthz")
        assert res.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in res.headers["Content-Security-Policy"]
        assert res.headers["Referrer-Policy"] == "no-referrer"
        assert "no-store" in res.headers["Cache-Control"]
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/docs").status_code == 404
        assert "Disallow: /" in client.get("/robots.txt").text


def test_unauthenticated_api_is_401(env):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        assert client.get("/api/sessions").status_code == 401
        assert client.post("/api/sessions", json={}).status_code == 401
        # 不存在的 session 對匿名者一律 404，不洩漏存在性
        assert client.get("/s/does-not-exist/raw").status_code == 404
