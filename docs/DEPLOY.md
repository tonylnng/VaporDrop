# 部署指南

寫給執行部署的人或 AI Agent。照順序做即可，全程約 10 分鐘。

---

## 0. 前置條件

| 項目 | 要求 |
|------|------|
| 主機 | Linux（Ubuntu 22.04+ 驗證過），2 vCPU / 2 GB RAM 起 |
| 套件 | Docker Engine 24+ 與 Docker Compose v2 |
| 網域 | 一個可解析到本機的 FQDN，或 Tailscale/Cloudflare 提供的名稱 |
| RAM | tmpfs 預設佔 512 MB 上限，請確認可用記憶體 |

**重要：WebAuthn 只在 HTTPS（或 `http://localhost`）下可用。** 沒有有效 TLS，Passkey 一定失敗。

---

## 1. 取得程式碼

```bash
git clone https://github.com/tonylnng/VaporDrop.git
cd VaporDrop
cp .env.example .env
```

## 2. 填 `.env`

必改的四項：

```ini
SITE_ADDRESS=vapor.example.com          # Caddy 對外站點
RP_ID=vapor.example.com                 # 必須等於網域，不含 scheme / port
ORIGINS=https://vapor.example.com       # 必須含 scheme
ACME_EMAIL=you@example.com
```

`RP_ID` 與 `ORIGINS` 填錯是最常見的失敗原因：Passkey 註冊會直接被瀏覽器拒絕。

## 3. 啟動

```bash
docker compose up -d --build
docker compose ps          # 三個容器都應為 running / healthy
```

## 4. 建立第一個帳號

`ALLOW_FIRST_USER_BOOTSTRAP=true`（預設）時，直接開 `https://your-domain/`，展開「第一次使用」，填 handle 後用 Touch ID 註冊。

建立完成後**立刻**關閉 bootstrap：

```bash
sed -i 's/^ALLOW_FIRST_USER_BOOTSTRAP=.*/ALLOW_FIRST_USER_BOOTSTRAP=false/' .env
docker compose up -d api
```

## 5. 邀請其他人

```bash
docker compose exec api python -m app.cli invite --note "Ian" --base-url https://vapor.example.com
```

輸出的註冊連結 15 分鐘內有效，一次性。請用安全通道遞送。

## 6. 驗收

跑一次自動化檢查：

```bash
./scripts/verify.sh https://vapor.example.com
```

再手動確認 `docs/../README.md` 的驗收清單，特別是這三項：

```bash
# 日誌必須是空的
docker compose logs --since 10m | grep -iE "GET|POST|/s/" && echo "❌ 有日誌洩漏" || echo "✓ 無請求日誌"

# Redis 必須沒有持久化
docker compose exec redis redis-cli CONFIG GET appendonly   # 應為 no
docker compose exec redis redis-cli CONFIG GET save         # 應為空

# 每個 key 都必須有 TTL
docker compose exec redis redis-cli --scan | while read k; do
  echo "$k $(docker compose exec -T redis redis-cli TTL "$k")"
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
| 列出用戶與裝置 | `docker compose exec api python -m app.cli users` |
| 產生邀請碼 | `docker compose exec api python -m app.cli invite` |
| 停用某人 | `docker compose exec api python -m app.cli disable <handle>` |
| 緊急清空所有內容 | `docker compose exec api python -m app.cli purge && docker compose exec redis redis-cli FLUSHDB` |
| 更新版本 | `git pull && docker compose up -d --build` |
| 完全銷毀（含憑證） | `docker compose down -v` |

備份只需要 `vapor-db` volume（Passkey 憑證）。內容永遠沒有備份 —— 這是設計目標，不是缺陷。

---

## 常見問題

**Passkey 註冊時瀏覽器直接報錯**
`RP_ID` 與網址不符，或站點不是 HTTPS。檢查 `.env` 的 `RP_ID` / `ORIGINS`。

**上傳大檔 413**
同時調高 `MAX_ITEM_BYTES`（app）與 `MAX_BODY_SIZE`（Caddy），並確認 tmpfs 夠大。

**容器重啟後要重新登入**
正常。登入 session 在 Redis 且無持久化。Passkey 憑證仍在，一觸即可再登入。

**Redis OOM**
`maxmemory-policy` 是 `noeviction`，寫入會被拒而非隨機丟資料（丟資料等於靜默遺失內容）。調高 `maxmemory` 或降低配額。

**想加 access log 來 debug**
不要。若真的必要，請只在臨時排錯期間加上，並在完成後立即移除；README 的驗收清單會因此不通過。
