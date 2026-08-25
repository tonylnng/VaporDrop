# 安全模型

## 1. 我們防什麼、不防什麼

| 威脅 | 是否防護 | 做法 |
|------|----------|------|
| 陌生人在網路上找到並使用這個服務 | ✅ | Google 登入需 email 白名單命中；Passkey 需邀請碼；`noindex`；可再套 tailnet / Cloudflare Access |
| 密碼被猜、被撞庫 | ✅ | VaporDrop 本身沒有密碼、沒有可撞的憑證庫 |
| 釣魚 | ⚠️ 依路徑而定 | Passkey 綁定 origin，結構上不可釣。Google 登入則繼承 Google 帳號的防護（建議該帳號開 Google Passkey 或雙重驗證）；仿冒的 VaporDrop 登入頁無法取得 `id_token`，但能騙走使用者的 Google 憑證 |
| 登入 CSRF / 授權碼注入 | ✅ | `state` 存 Redis 單次使用（300s）而非 cookie；PKCE S256 綁定 `code_verifier`；`nonce` 以恆定時間比對 |
| 我的 email 落在被扣押的磁碟上 | ✅ | 資料庫只存 `HMAC-SHA256(UID_PEPPER, email)` 前 32 hex，無 `emails` 表、無 `oauth_tokens` 表 |
| 伺服器被入侵後翻出歷史內容 | ✅ | 內容 10 分鐘即抹除、只在 RAM、只有密文、無日誌、無備份 |
| 硬碟被抄走 / VPS 快照 | ✅ | 內容從不寫磁碟；持久卷只有 `uid`（HMAC）、Passkey 公鑰、邀請碼、緊急碼雜湊 |
| 網路中間人看到內容 | ✅ | TLS + 應用層 AES-256-GCM（伺服器也看不到明文） |
| 其他登入用戶偷看我的 session | ✅ | 所有讀寫檢查 owner；跨用戶一律回 404 |
| 分享連結被轉貼後被反覆下載 | ✅ | token 限次（預設 1 次）＋不長於內容 TTL；可開「讀後即毀」 |
| 事後被追問「誰在何時拿了什麼」 | ✅（設計如此） | 沒有 access log、沒有審計表，答案是「查不到」 |
| 收到連結的人自己把明文存下來 | ❌ | 技術上不可能防。這是信任決定 |
| 拿到連結的任何人（含被轉發者） | ❌ | 連結即憑證。請只用安全通道遞送 |
| 惡意瀏覽器擴充 / 被入侵的端點 | ❌ | 明文在瀏覽器內必然存在 |
| 流量分析（誰在何時上傳了多大的東西） | ⚠️ 部分 | 大小與時間對 proxy/網路觀察者可見 |
| 記憶體取證（RAM dump / swap） | ⚠️ 部分 | tmpfs 在 RAM；已做覆寫抹除，但建議主機關 swap 或全盤加密 |
| Google 知道我何時登入 | ❌（明示接受） | 用 Google 登入即等於讓 Google 看見「此帳號在此時登入了此 OAuth client」。**Google 看不到任何內容**。不接受就留空 `GOOGLE_CLIENT_ID`，只用 Passkey |
| Google 帳號被停權 / Google 服務中斷 | ⚠️ 有備援 | CLI 一次性緊急登入連結（10 分鐘、單次、只存雜湊）＋ Passkey 備援路徑 |

---

## 2. 信任邊界

```mermaid
graph LR
    subgraph T1["受信任：使用者瀏覽器"]
        K[明文 + AES 金鑰]
    end
    subgraph T2["半信任：VaporDrop 伺服器"]
        S[只有密文 + 最小中介資料]
    end
    subgraph T3["受信任：接收端 VM / Agent"]
        D[以 fragment 內金鑰解密]
    end
    K -->|TLS，只送密文| S
    S -->|TLS，只回密文| D
    K -.->|連結含金鑰，走安全通道<br/>不經 VaporDrop| D
    style S stroke-dasharray: 4 4
```

金鑰與 token 只出現在 URL fragment（`#k=…&t=…`）。fragment 依 HTTP 規範不會送往伺服器，所以不進 access log、不進 proxy、不進 Referer。

---

## 3. 已實作的控制項

**身份（主路徑：Google OIDC）**
- Authorization Code + **PKCE S256**；前端不載入任何 Google JS SDK，CSP 維持 `script-src 'self'`
- `state` / `nonce` / `code_verifier` 存 Redis，單次使用、300 秒；`flow_take()` 為 GET+DEL 原子操作
- `id_token` 由伺服器帶 `client_secret` 經 TLS 直接向 Google `/token` 換取（不經瀏覽器）
- 驗 `iss ∈ {https://accounts.google.com, accounts.google.com}`、`aud == client_id`、`exp`/`iat`（±120s 容差）、`nonce`（恆定時間比對）、`email_verified == true`
- **設計決定：不驗 `id_token` 的 RS256 簽章，只驗 claims。** 依據 [Google OIDC 文件](https://developers.google.com/identity/openid-connect/openid-connect)，透過直接 HTTPS 呼叫 token endpoint 取得的 token 可信任其來源。**若日後改為接受前端傳入的 `id_token`，必須改用 Google JWKS 驗簽**，否則等於任何人可自製身份。此警告寫在 `app/google_auth.py` 模組 docstring
- 準入為 email 白名單（`ALLOWED_EMAILS`）或 Workspace 網域（`ALLOWED_DOMAIN`，同時作為 Google `hd` 參數）；未命中不建立帳號
- 失敗一律 `303 → /?e=<code>`，伺服器不區分「不存在」與「被停用」，無法用於帳號枚舉
- access token / refresh token 驗完即丟，不存、不用（只要 `openid email` 兩個 scope）
- **email 不落地**：`uid = HMAC-SHA256(UID_PEPPER, 小寫 email)[:32]`，`handle` 預設 `g-<uid[:10]>`

**身份（備援路徑：Passkey，選用）**
- WebAuthn/FIDO2，`require_user_verification=True`（必須指紋/臉/PIN）
- discoverable credential → 無需輸入帳號即可登入
- `sign_count` 單調遞增檢查（偵測憑證克隆）
- challenge 一次性：`flow_take()` 是 GET+DEL 原子操作
- 註冊需邀請碼；首次部署的 bootstrap 例外可用 `ALLOW_FIRST_USER_BOOTSTRAP=false` 關閉

**身份（逃生門：緊急登入碼）**
- 只能由主機上的 CLI 產生（需 SSH 或 `docker exec` 權限，本身已是一道門）
- 資料庫只存 `SHA-256(碼)`，原文只在終端出現一次
- 單次使用（`used_at` 一寫即失效）、預設 600 秒過期、由 sweeper 定期清除過期列
- 驗證失敗與過期回傳同一個錯誤，不區分

**Session**
- cookie `HttpOnly; Secure; SameSite=Strict`，內容只有隨機 sid
- 30 分鐘無活動即失效（Redis TTL 滑動續期，前端另有 5 分鐘前警告）
- 登出 = 刪 session ＋ **清掉該用戶所有內容**
- 所有寫入端點檢查 same-origin

**內容**
- 瀏覽器端 AES-256-GCM，每 session 一把獨立金鑰
- 檔名/標籤另外加密，走 `X-Vapor-Name` 標頭
- 10 分鐘 TTL，**任何操作都不會延長**
- 三重清理：手動銷毀 / 登出清空 / 背景 sweeper 掃孤兒（30s）
- 刪除時隨機覆寫 + fsync 再 unlink
- 配額：單項 32 MB、單 session 128 MB、50 項、同時 5 個 session

**傳輸與取用**
- token 以 `HINCRBY` 原子扣減，用盡即刪；TTL 不超過內容剩餘時間
- `/s/{cid}/raw` 強制 `Content-Disposition: attachment`（避免內容在瀏覽器被當 HTML 執行）
- 不存在或不屬於你的資源一律 404，不用 403（不洩漏存在性）

**平台**
- CSP `script-src 'self'`，無任何 inline script
- `X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy: no-referrer`、COOP/CORP、`Permissions-Policy` 全關、`Cache-Control: no-store`、`X-Robots-Tag: noindex`
- 移除 `Server` 標頭；`/docs`、`/redoc`、`/openapi.json` 全部 404
- 容器 `read_only`、`cap_drop: ALL`、`no-new-privileges`、uid 10001 非 root
- tmpfs `noexec,nosuid,nodev`
- Redis `--save "" --appendonly no`（零持久化）、`noeviction`（寧可拒寫也不靜默丟資料）
- Caddy 與所有容器 `logging: driver none`；uvicorn `--no-access-log`；所有 logger 掛 `NullHandler`
- 速率限制以 HMAC(IP) 為桶 key，不存 IP 原文
- `/metrics` 只吐兩個聚合數字（`vapor_active_sessions`、`vapor_bytes_in_ram`），無任何識別資訊

---

## 4. 需要你決定的取捨

| 取捨 | 預設 | 說明 |
|------|------|------|
| `ALLOW_SERVER_SIDE_PLAIN` | `false` | 開了之後接收端一條 `curl` 就能拿明文，代價是伺服器看得見內容。只有在純 tailnet 內、且對方無法跑 Python 時才考慮 |
| 部署形態 | 公網 + Let's Encrypt | 隱私最高是純 Tailscale（不開任何公網 port）。Cloudflare Tunnel 方便但 Cloudflare 端有自己的日誌 |
| 無日誌 | 開 | 代價是出事時沒有任何取證線索，只能靠 `/metrics` 的兩個數字 |
| Swap | 由主機決定 | 建議 `swapoff -a` 或全盤加密，否則 RAM 內容理論上可能落到 swap |
| 登入方式 | Google 為主，Passkey 選用 | Google 最方便但讓 Google 看見登入事件；Passkey 抗釣魚且零第三方依賴但需要生物認證且換裝置麻煩。兩者可同時開，各人自選 |
| `STORE_EMAIL_HANDLE` | `false` | `false` 顯示 `g-xxxxxxxxxx`（DB 完全無個資，但看不出誰是誰，需 `cli whois` 反查）；`true` 用 email 的 `@` 前半部當顯示名，好認但在 DB 留下部分個資 |
| `ALLOWED_EMAILS` vs `ALLOWED_DOMAIN` | 用 `ALLOWED_EMAILS` | 逐個 email 最嚴格；整個 Workspace 網域省事但任何新入職者自動有權限 |

---

## 5. 回報漏洞

請直接開 GitHub issue（不含 PoC 的敏感細節），或以私訊聯繫 repo 擁有者。

---

## 6. 驗收清單

部署後跑 `./scripts/verify.sh https://your-domain`（Google 已啟用時 21 項，未啟用 16 項），再手動確認：

- [ ] `docker compose logs --since 10m` 內沒有任何請求路徑
- [ ] `redis-cli CONFIG GET appendonly` → `no`；`CONFIG GET save` → 空
- [ ] `redis-cli --scan` 出來的每個 key，`TTL` 都不是 `-1`
- [ ] 上傳後等 11 分鐘，`/s/{cid}` 回 404，`/vapor/{cid}` 目錄消失
- [ ] 同一個一次性 token 用第二次回 404
- [ ] 登出後原本的 session 連結全部 404
- [ ] 用另一個帳號存取別人的 cid 回 404
- [ ] 從伺服器端看 `/vapor/*/*.bin`，內容為亂數（`strings` 找不到明文）
- [ ] `curl -I https://your-domain/` 沒有 `Server: uvicorn`
- [ ] 瀏覽器 devtools 的 Network 面板，任何請求的 URL 都不含 `#k=`
- [ ] `strings /data/vapor.db | grep '@'` 找不到任何 email 位址
- [ ] 不在白名單內的 Google 帳號登入後，`app.cli users` 沒有新增列
- [ ] 同一個 `/auth/google/callback?...&state=X` 重送第二次 → 轉回 `/?e=state`
- [ ] 緊急登入連結用第二次 → 轉回 `/?e=rescue`
- [ ] `curl -sI https://your-domain/auth/google/start | grep -i location` 內含 `code_challenge_method=S256`，且**不含** `client_secret`
