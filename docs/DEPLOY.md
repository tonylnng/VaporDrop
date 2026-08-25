# 部署指南

寫給執行部署的人或 AI Agent。照順序做即可，全程約 10 分鐘。

---

## 0. 前置條件

| 項目 | 要求 |
|------|------|
| 主機 | Linux（Ubuntu 22.04+ 驗證過），2 vCPU / 2 GB RAM 起 |
| 套件 | Docker Engine 24+ 與 Docker Compose v2 |
| 網域 | 一個可解析到本機的 FQDN，或 Tailscale/Cloudflare 提供的名稱 |
| Google 帳號 | 一個 Google Cloud 專案，用來建立 OAuth 2.0 Web client（免費） |
| RAM | tmpfs 預設佔 512 MB 上限，請確認可用記憶體 |

**重要：兩條登入路徑都需要真實網域 + HTTPS。**
- Google OAuth 的 redirect URI 必須與 Console 登記的字串**完全一致**，且不能是裸 IP。
- WebAuthn（Passkey，選用）只在 HTTPS 或 `http://localhost` 下可用，`RP_ID` 也不接受裸 IP。

所以：先把 DNS 指到這台機器並等它生效，Caddy 才能取到 Let's Encrypt 憑證，之後再做 OAuth 登記。

---

## 1. 取得程式碼

```bash
git clone https://github.com/tonylnng/VaporDrop.git
cd VaporDrop
cp .env.example .env
```

## 2. 建立 Google OAuth client

1. 開 [Google Cloud Console](https://console.cloud.google.com/) → 建立（或選擇）一個專案。
2. **APIs & Services → OAuth consent screen**：User type 選 **External**（只給自己人用也可以，維持 Testing 狀態並把使用者加進 Test users 即可，不必送審）。Scopes 只需要 `openid` 與 `email`。
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**
   - Application type：**Web application**
   - Authorized redirect URIs：`https://vapor.example.com/auth/google/callback`
     （**必須完全一致**：scheme、網域、路徑、無結尾斜線。填錯會得到 `redirect_uri_mismatch`。）
4. 記下 **Client ID** 與 **Client secret**。

> 只需要 `openid email` 兩個 scope。VaporDrop 不要 profile、不要 Drive、不存 access token——`/token` 換到 `id_token` 驗完就丟。

## 3. 填 `.env`

必改的項目：

```ini
SITE_ADDRESS=vapor.example.com          # Caddy 對外站點
RP_ID=vapor.example.com                 # 必須等於網域，不含 scheme / port
ORIGINS=https://vapor.example.com       # 必須含 scheme
ACME_EMAIL=you@example.com

# --- Google 登入 ---
GOOGLE_CLIENT_ID=xxxxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=xxxxx
ALLOWED_EMAILS=you@gmail.com,teammate@gmail.com
UID_PEPPER=<openssl rand -hex 32 的輸出>
```

產生 pepper：

```bash
openssl rand -hex 32
```

`UID_PEPPER` 決定 `uid = HMAC(pepper, email)`。**上線後不可更改**，改了等於所有人變成全新帳號。請與 `.env` 一起備份到密碼管理器。

`RP_ID` 與 `ORIGINS` 填錯是最常見的失敗原因：Passkey 註冊會直接被瀏覽器拒絕，`GOOGLE_REDIRECT_URI` 的預設值也是由 `ORIGINS[0]` 推導出來的。

> 只想用 Passkey、完全不碰 Google？把 `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `UID_PEPPER` 留空即可，`/auth/google/*` 會回 404，前端自動只顯示 Passkey。

## 4. 啟動

```bash
docker compose up -d --build
docker compose ps          # vapordrop-redis / vapordrop-api / vapordrop-caddy 皆應 running / healthy
```

## 5. 第一次登入

開 `https://your-domain/` → 點「用 Google 登入」→ 選你自己的 Google 帳號。
帳號會在第一次成功登入時自動建立，**不需要邀請碼**（白名單就是準入控制）。

確認帳號建好了、而且資料庫沒有 email：

```bash
docker compose exec vapordrop-api python -m app.cli users
# g-3f9a1c2b7d  uid=3f9a1c2b7d…  建立於 …

# 反查（單向重算，不是解密）
docker compose exec vapordrop-api python -m app.cli whois you@gmail.com
```

## 6. 加人 / 減人

**加人**：把對方的 Google email 加進 `.env` 的 `ALLOWED_EMAILS`，然後重啟 api。對方自己點登入即可，不需要邀請流程。

```bash
sed -i 's/^ALLOWED_EMAILS=.*/ALLOWED_EMAILS=you@gmail.com,new@gmail.com/' .env
docker compose up -d vapordrop-api
```

**減人**：從 `ALLOWED_EMAILS` 移除（阻止再登入），並停用既有帳號（立即撤銷現有 session）：

```bash
docker compose exec vapordrop-api python -m app.cli disable <handle>
```

**整個 Workspace 網域放行**：改用 `ALLOWED_DOMAIN=yourcompany.com`（同時會作為 Google 的 `hd` 參數送出，登入畫面直接只顯示該網域帳號）。

## 7. 緊急登入（Google 掛了怎麼辦）

Google 服務中斷、OAuth client 被停用、或 consent screen 過期時，用主機上的 CLI 開一次性後門：

```bash
docker compose exec vapordrop-api python -m app.cli rescue \
    --handle g-3f9a1c2b7d --create --base-url https://vapor.example.com
# 緊急登入連結： https://vapor.example.com/auth/rescue?c=…
# 有效至： …（預設 10 分鐘）
```

一次性、預設 10 分鐘、資料庫只存 SHA-256 雜湊，原文只在終端出現這一次。
建議也保留一把 Passkey（`make invite` → 註冊）作為第二條備援，那條完全不依賴 Google 也不依賴 SSH 進主機。

## 8. 邀請 Passkey 使用者（選用）

想給某人不依賴 Google 的抗釣魚登入：

```bash
docker compose exec vapordrop-api python -m app.cli invite --note "Ian" --base-url https://vapor.example.com
```

輸出的註冊連結 15 分鐘內有效，一次性。請用安全通道遞送。
若你曾開著 `ALLOW_FIRST_USER_BOOTSTRAP=true`，建立完第一個 Passkey 後**立刻**關掉：

```bash
sed -i 's/^ALLOW_FIRST_USER_BOOTSTRAP=.*/ALLOW_FIRST_USER_BOOTSTRAP=false/' .env
docker compose up -d vapordrop-api
```

## 9. 驗收

跑一次自動化檢查：

```bash
./scripts/verify.sh https://vapor.example.com
```

再手動確認 `docs/../README.md` 的驗收清單，特別是這三項：

```bash
# 日誌必須是空的
docker compose logs --since 10m | grep -iE "GET|POST|/s/" && echo "❌ 有日誌洩漏" || echo "✓ 無請求日誌"

# Redis 必須沒有持久化
docker compose exec vapordrop-redis redis-cli CONFIG GET appendonly   # 應為 no
docker compose exec vapordrop-redis redis-cli CONFIG GET save         # 應為空

# 每個 key 都必須有 TTL
docker compose exec vapordrop-redis redis-cli --scan | while read k; do
  echo "$k $(docker compose exec -T vapordrop-redis redis-cli TTL "$k")"
done
```

---

## 部署形態選擇

### A. 純 Tailscale（最高隱私，建議）

不對公網開任何 port。

```bash
# .env
BIND_ADDR=127.0.0.1
SITE_ADDRESS=vapor.your-tailnet.ts.net
RP_ID=vapor.your-tailnet.ts.net
ORIGINS=https://vapor.your-tailnet.ts.net
```

在主機上：

```bash
tailscale cert vapor.your-tailnet.ts.net    # 取得 tailnet TLS 憑證
tailscale serve --bg --https=443 http://127.0.0.1:80
```

好處：只有 tailnet 成員能連到，等於在 Passkey 之外多一層網路層身份。VM 與 Agent 若也在 tailnet 內，`curl` 直接可用。

### B. Cloudflare Tunnel（公網可達，不開 inbound port）

```bash
# .env
BIND_ADDR=127.0.0.1
```

```bash
cloudflared tunnel create vapordrop
cloudflared tunnel route dns vapordrop vapor.example.com
cloudflared tunnel run --url http://127.0.0.1:80 vapordrop
```

可再在 Cloudflare Access 前置一層 Email OTP，形成雙因素。注意 Cloudflare 端會有它自己的日誌，若「不留痕」要求嚴格，選 A。

### C. 直接公網（最簡單）

保持 `BIND_ADDR=0.0.0.0`，開放 80/443，Caddy 自動申請 Let's Encrypt 憑證。DNS A 記錄需先指向主機。

---

## 日常運維

| 目的 | 指令 |
|------|------|
| 列出用戶與裝置 | `docker compose exec vapordrop-api python -m app.cli users` |
| 產生邀請碼（Passkey） | `docker compose exec vapordrop-api python -m app.cli invite` |
| 由 email 反查 uid | `docker compose exec vapordrop-api python -m app.cli whois you@gmail.com` |
| 產生緊急登入連結 | `docker compose exec vapordrop-api python -m app.cli rescue --handle <handle> --create --base-url https://vapor.example.com` |
| 停用某人 | `docker compose exec vapordrop-api python -m app.cli disable <handle>` |
| 緊急清空所有內容 | `docker compose exec vapordrop-api python -m app.cli purge && docker compose exec vapordrop-redis redis-cli FLUSHDB` |
| 更新版本 | `git pull && docker compose up -d --build` |
| 完全銷毀（含憑證） | `docker compose down -v` |

備份需要兩樣東西：`vapordrop-db` volume（帳號列與 Passkey 憑證）**以及 `.env` 裡的 `UID_PEPPER`**。缺了 pepper，即使還原了資料庫，Google 登入也會推導出不同的 `uid`，等於所有人變成新帳號。內容永遠沒有備份 —— 這是設計目標，不是缺陷。

---

## 常見問題

**Google 回 `redirect_uri_mismatch`**
Console 登記的 URI 與實際送出的不是同一個字串。實際值 = `GOOGLE_REDIRECT_URI`，未設時 = `ORIGINS` 第一項 + `/auth/google/callback`。用 `curl -sI https://your-domain/auth/google/start | grep -i location` 看實際送出的 `redirect_uri`，把它原樣貼進 Console。注意 `http` vs `https`、有無 `www`、有無結尾斜線。

**登入後停在首頁，顯示「此帳號不在允許清單內」**
該 email 不在 `ALLOWED_EMAILS`、不屬於 `ALLOWED_DOMAIN`，或該帳號已被 `disable`。改完 `.env` 記得 `docker compose up -d vapordrop-api`。

**顯示「登入流程已逾時，請重新開始」**
`state` 已過期（300 秒）或已被用過。多半是使用者停在 Google 選帳號畫面太久，或按了瀏覽器返回鍵重送 callback。重新點一次登入即可——這個錯誤本身就是重放防護在生效。

**首頁沒有「用 Google 登入」按鈕**
`GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `UID_PEPPER` 三者未全部填妥，Google 登入被自動停用。用 `curl -s https://your-domain/auth/state | grep google` 確認。

**Passkey 註冊時瀏覽器直接報錯**
`RP_ID` 與網址不符，或站點不是 HTTPS。檢查 `.env` 的 `RP_ID` / `ORIGINS`。裸 IP 一定失敗。

**上傳大檔 413**
同時調高 `MAX_ITEM_BYTES`（app）與 `MAX_BODY_SIZE`（Caddy），並確認 tmpfs 夠大。

**容器重啟後要重新登入**
正常。登入 session 在 Redis 且無持久化。帳號與 Passkey 憑證仍在，再點一次登入即可。

**Redis OOM**
`maxmemory-policy` 是 `noeviction`，寫入會被拒而非隨機丟資料（丟資料等於靜默遺失內容）。調高 `maxmemory` 或降低配額。

**想加 access log 來 debug**
不要。若真的必要，請只在臨時排錯期間加上，並在完成後立即移除；README 的驗收清單會因此不通過。

---

## 附錄：Docker 命名對照

所有 Docker 物件統一以 `vapordrop` 為前綴，方便在共用主機上辨識與整批操作。

| 類型 | 名稱 |
|------|------|
| Compose 專案 | `vapordrop` |
| 服務 / 容器 | `vapordrop-api`、`vapordrop-redis`、`vapordrop-caddy` |
| 映像（自建） | `vapordrop-api:latest` |
| 網路 | `vapordrop-net` |
| 持久卷 | `vapordrop-db`（唯一需備份）、`vapordrop-caddy-data`、`vapordrop-caddy-config` |

```bash
docker ps     --filter name=vapordrop
docker volume ls --filter name=vapordrop
docker network ls --filter name=vapordrop
```
