"""VaporDrop 應用入口。

刻意沒有做的事：
  * 沒有 access log。uvicorn 以 --no-access-log 啟動。
  * 例外處理只回泛用訊息，不把路徑、參數或內容寫進 stderr。
  * 沒有 /docs 與 /openapi.json（減少攻擊面與資訊洩漏）。
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import auth_routes, config, db, security, session_routes, store

# 把可能寫出請求細節的 logger 全部關掉
for name in ("uvicorn.access", "uvicorn.error", "fastapi", "asyncio"):
    logging.getLogger(name).handlers = [logging.NullHandler()]
    logging.getLogger(name).propagate = False
logging.getLogger().setLevel(logging.WARNING)


async def _sweeper() -> None:
    """週期性清理：孤兒密文檔 + 過期邀請碼。"""
    while True:
        try:
            await store.sweep_once()
            await asyncio.to_thread(db.purge_expired_invites)
        except Exception:
            pass  # 絕不記錄細節
        await asyncio.sleep(config.SWEEP_INTERVAL)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(config.BLOB_DIR, mode=0o700, exist_ok=True)
    await asyncio.to_thread(db.init)
    # 冷啟動先清一次：上一次程序留下的任何殘檔都不該存在
    await store.sweep_once()
    task = asyncio.create_task(_sweeper())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await store.close()


app = FastAPI(
    title="VaporDrop",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(security.SecurityHeadersMiddleware)
app.include_router(auth_routes.router)
app.include_router(session_routes.router)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    """任何未預期錯誤都回同一句話，不洩漏內部狀態。"""
    return JSONResponse(status_code=500, content={"detail": "internal error"})


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# --- 靜態頁面 ---------------------------------------------------------
app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")


def _page(name: str) -> FileResponse:
    return FileResponse(
        os.path.join(config.STATIC_DIR, name),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/", include_in_schema=False)
async def index():
    return _page("index.html")


@app.get("/s/{cid}", include_in_schema=False)
async def receive_page(cid: str):
    # 頁面本身不需認證：解密金鑰在 URL fragment，內容仍需 token 或 cookie 才能取得
    return _page("receive.html")


@app.get("/robots.txt", include_in_schema=False)
async def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@app.get("/healthz", include_in_schema=False)
async def healthz():
    try:
        await store.redis_client().ping()
    except Exception:
        raise HTTPException(status_code=503, detail="degraded")
    return {"ok": True}


@app.get("/metrics", include_in_schema=False)
async def metrics():
    """無身份計數。刻意不含用戶、IP、session id 或任何內容資訊。"""
    s = await store.stats()
    lines = [
        "# HELP vapor_active_sessions 目前未過期的 content session 數",
        "# TYPE vapor_active_sessions gauge",
        f"vapor_active_sessions {s['active_sessions']}",
        "# HELP vapor_bytes_in_ram tmpfs 上密文佔用位元組",
        "# TYPE vapor_bytes_in_ram gauge",
        f"vapor_bytes_in_ram {s['bytes_in_ram']}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")
