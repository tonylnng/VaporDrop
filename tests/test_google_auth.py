"""Google 登入（OIDC）與緊急登入的不變式測試。

不連外網：token endpoint 以 monkeypatch 攔下，id_token 在測試內自行組出。
重點驗證：state 一次性、nonce 必須相符、白名單、aud/iss/exp 檢查、
資料庫不得出現 email 原文、緊急登入碼一次性。
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CLIENT_ID = "test-client-id.apps.googleusercontent.com"
PEPPER = "0123456789abcdef0123456789abcdef"
GOOD_EMAIL = "tony@example.com"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_id_token(**overrides) -> str:
    claims = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "email": GOOD_EMAIL,
        "email_verified": True,
    }
    claims.update(overrides)
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    return f"{header}.{payload}.signature-not-verified-by-design"


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BLOB_DIR", str(tmp_path / "vapor"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vapor.db"))
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("ORIGINS", "http://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("UID_PEPPER", PEPPER)
    monkeypatch.setenv("ALLOWED_EMAILS", GOOD_EMAIL)
    for mod in [m for m in list(sys.modules) if m.startswith("app")]:
        sys.modules.pop(mod)

    import fakeredis.aioredis

    from app import config, db, google_auth, store

    os.makedirs(config.BLOB_DIR, exist_ok=True)
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(store, "redis_client", lambda: fake)
    db.init()

    from app.main import app

    # 攔下對 Google token endpoint 的呼叫，回傳測試自製的 id_token
    state: dict = {"id_token": make_id_token(), "status": 200, "calls": []}

    async def fake_exchange(code, verifier, nonce):
        state["calls"].append({"code": code, "verifier": verifier, "nonce": nonce})
        if state["status"] != 200:
            return None
        token = state["id_token"]
        claims = json.loads(google_auth._b64url_decode(token.split(".")[1]))
        claims.setdefault("nonce", nonce)  # 預設模擬 Google 正確回填 nonce
        if state.get("force_nonce") is not None:
            claims["nonce"] = state["force_nonce"]
        return await google_auth._verify_claims(claims, nonce)

    monkeypatch.setattr(google_auth, "_exchange_and_verify", fake_exchange)

    with TestClient(app, follow_redirects=False) as client:
        yield client, state, config, db, google_auth


def start_login(client) -> str:
    """按下登入按鈕，回傳 Google 會帶回來的 state。"""
    resp = client.get("/auth/google/start")
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "code_challenge_method=S256" in location
    assert f"client_id={CLIENT_ID}" in location
    assert "scope=openid+email" in location
    from urllib.parse import parse_qs, urlparse

    return parse_qs(urlparse(location).query)["state"][0]


def test_start_redirects_with_pkce_and_state(app_env):
    client, *_ = app_env
    state = start_login(client)
    assert len(state) >= 16


def test_full_login_creates_user_without_storing_email(app_env):
    client, _, config, db, google_auth = app_env
    state = start_login(client)
    resp = client.get(f"/auth/google/callback?code=abc&state={state}")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert config.COOKIE_NAME in resp.cookies

    # 帳號以 HMAC(email) 為 uid 建立
    uid = google_auth.uid_for_email(GOOD_EMAIL)
    user = db.get_user(uid)
    assert user is not None
    assert user["handle"] == f"g-{uid[:10]}", "預設 handle 必須不可辨識"

    # 資料庫檔案裡不得出現 email 原文或其網域
    raw = open(config.DB_PATH, "rb").read()
    assert GOOD_EMAIL.encode() not in raw
    assert b"example.com" not in raw

    # 已登入狀態可用
    state_resp = client.get("/auth/state")
    assert state_resp.json()["authenticated"] is True
    assert state_resp.json()["google"] is True


def test_second_login_reuses_same_account(app_env):
    client, _, _, db, google_auth = app_env
    for _ in range(2):
        state = start_login(client)
        assert client.get(f"/auth/google/callback?code=abc&state={state}").status_code == 303
    conn = db._connect()
    assert conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 1


def test_state_is_single_use(app_env):
    client, *_ = app_env
    state = start_login(client)
    assert client.get(f"/auth/google/callback?code=abc&state={state}").status_code == 303
    second = client.get(f"/auth/google/callback?code=abc&state={state}")
    assert second.headers["location"] == "/?e=state", "state 重放必須失敗"


def test_unknown_state_rejected(app_env):
    client, *_ = app_env
    resp = client.get("/auth/google/callback?code=abc&state=deadbeefdeadbeef")
    assert resp.headers["location"] == "/?e=state"


def test_nonce_mismatch_rejected(app_env):
    client, st, *_ = app_env
    st["force_nonce"] = "attacker-supplied-nonce"
    state = start_login(client)
    resp = client.get(f"/auth/google/callback?code=abc&state={state}")
    assert resp.headers["location"] == "/?e=token"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-elses-client-id"},
        {"iss": "https://evil.example.com"},
        {"exp": int(time.time()) - 3600},
    ],
)
def test_bad_claims_rejected(app_env, overrides):
    client, st, *_ = app_env
    st["id_token"] = make_id_token(**overrides)
    state = start_login(client)
    resp = client.get(f"/auth/google/callback?code=abc&state={state}")
    assert resp.headers["location"] == "/?e=token"


def test_unverified_email_rejected(app_env):
    client, st, *_ = app_env
    st["id_token"] = make_id_token(email_verified=False)
    state = start_login(client)
    resp = client.get(f"/auth/google/callback?code=abc&state={state}")
    assert resp.headers["location"] == "/?e=email"


def test_email_not_on_allowlist_rejected(app_env):
    client, st, _, db, _ = app_env
    st["id_token"] = make_id_token(email="stranger@example.com")
    state = start_login(client)
    resp = client.get(f"/auth/google/callback?code=abc&state={state}")
    assert resp.headers["location"] == "/?e=nolist"
    assert db.user_count() == 0, "未通過白名單不得建立帳號"


def test_disabled_user_cannot_login(app_env):
    client, _, _, db, google_auth = app_env
    uid = google_auth.uid_for_email(GOOD_EMAIL)
    db.ensure_user(uid, "g-x")
    conn = db._connect()
    with conn:
        conn.execute("UPDATE users SET disabled = 1 WHERE uid = ?", (uid,))
    state = start_login(client)
    resp = client.get(f"/auth/google/callback?code=abc&state={state}")
    assert resp.headers["location"] == "/?e=nolist"


def test_google_disabled_hides_endpoints(tmp_path, monkeypatch):
    """未設定 client id 時，端點必須 404，且 /auth/state 回報 google=false。"""
    monkeypatch.setenv("BLOB_DIR", str(tmp_path / "vapor"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vapor.db"))
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("UID_PEPPER", raising=False)
    for mod in [m for m in list(sys.modules) if m.startswith("app")]:
        sys.modules.pop(mod)

    import fakeredis.aioredis

    from app import config, db, store

    os.makedirs(config.BLOB_DIR, exist_ok=True)
    monkeypatch.setattr(store, "redis_client", lambda: fakeredis.aioredis.FakeRedis(decode_responses=True))
    db.init()
    from app.main import app

    with TestClient(app, follow_redirects=False) as client:
        assert client.get("/auth/google/start").status_code == 404
        assert client.get("/auth/state").json()["google"] is False


# --- 緊急登入（break-glass）------------------------------------------
def test_rescue_code_single_use(app_env):
    client, _, config, db, _ = app_env
    uid = db.create_user("tony")
    code, _expires = db.create_rescue_code(uid, ttl=600)

    resp = client.get(f"/auth/rescue?c={code}")
    assert resp.status_code == 303
    assert config.COOKIE_NAME in resp.cookies

    client.cookies.clear()
    again = client.get(f"/auth/rescue?c={code}")
    assert again.headers["location"] == "/?e=rescue", "緊急登入碼不可重用"


def test_rescue_code_expired_rejected(app_env):
    client, _, _, db, _ = app_env
    uid = db.create_user("tony")
    code, _ = db.create_rescue_code(uid, ttl=-1)
    assert client.get(f"/auth/rescue?c={code}").headers["location"] == "/?e=rescue"


def test_rescue_code_stored_only_as_hash(app_env):
    _client, _, config, db, _ = app_env
    uid = db.create_user("tony")
    code, _ = db.create_rescue_code(uid, ttl=600)
    raw = open(config.DB_PATH, "rb").read()
    assert code.encode() not in raw, "資料庫不得存緊急登入碼原文"


def test_allowed_domain_matching(app_env):
    _client, _, config, _, google_auth = app_env
    monkey_domain = "corp.example"
    config.ALLOWED_DOMAIN = monkey_domain
    config.ALLOWED_EMAILS = []
    assert google_auth.email_allowed("someone@corp.example", monkey_domain) is True
    assert google_auth.email_allowed("someone@other.example", "") is False
    # hd 與網域不一致（Workspace 網域造假）必須拒絕
    assert google_auth.email_allowed("someone@corp.example", "attacker.example") is False
