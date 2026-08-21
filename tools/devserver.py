#!/usr/bin/env python3
"""本機開發啟動器（僅供開發，切勿用於部署）。

以 fakeredis 取代真實 Redis，讓你在沒有 Docker 的機器上跑起完整 UI 與 API：

    pip install -r requirements-dev.txt
    python tools/devserver.py
    # 開 http://localhost:8080 （RP_ID=localhost，Passkey 在 http://localhost 可用）

正式部署請用 docker compose，見 docs/DEPLOY.md。
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

DEV_DIR = os.getenv("DEV_DIR", "/tmp/vapor-dev")
os.makedirs(DEV_DIR, exist_ok=True)

os.environ.setdefault("BLOB_DIR", os.path.join(DEV_DIR, "blobs"))
os.environ.setdefault("DB_PATH", os.path.join(DEV_DIR, "vapor.db"))
os.environ.setdefault("RP_ID", "localhost")
os.environ.setdefault("ORIGINS", "http://localhost:8080")
os.environ.setdefault("COOKIE_SECURE", "false")   # 本機以 http 測試
os.environ.setdefault("ALLOW_FIRST_USER_BOOTSTRAP", "true")

import fakeredis.aioredis  # noqa: E402

from app import store  # noqa: E402

_fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
store.redis_client = lambda: _fake  # 記憶體版 Redis，程序結束即消失

from app.main import app  # noqa: E402

if __name__ == "__main__":
    import uvicorn

    print(f"dev 資料夾：{DEV_DIR}（可直接刪除以重置帳號）")
    uvicorn.run(app, host="127.0.0.1", port=8080, access_log=False, server_header=False)
