#!/usr/bin/env bash
# VaporDrop 部署後自動驗收。
#
#   ./scripts/verify.sh https://vapor.example.com
#
# 只做外部可觀測的檢查（不需要登入）。內部檢查見 docs/DEPLOY.md 第 6 節。
set -uo pipefail

BASE="${1:-}"
if [[ -z "$BASE" ]]; then
  echo "用法：$0 https://your-domain" >&2
  exit 2
fi
BASE="${BASE%/}"

pass=0
fail=0
ok()   { printf '  ✓ %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  ✗ %s\n' "$1"; fail=$((fail+1)); }

hdrs="$(curl -sSI "$BASE/" 2>/dev/null)"
body_code="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null)"

echo "== 可用性 =="
[[ "$body_code" == "200" ]] && ok "首頁回應 200" || bad "首頁回應 $body_code"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/healthz")" == "200" ]] \
  && ok "/healthz 正常" || bad "/healthz 異常"

echo "== 安全標頭 =="
check_header() { # name, expected-substring
  if grep -iq "^$1:.*$2" <<<"$hdrs"; then ok "$1 含 $2"; else bad "$1 缺少 $2"; fi
}
check_header "content-security-policy" "default-src"
check_header "x-content-type-options"  "nosniff"
check_header "x-frame-options"         "DENY"
check_header "referrer-policy"         "no-referrer"
check_header "cache-control"           "no-store"
check_header "x-robots-tag"            "noindex"
if [[ "$BASE" == https://* ]]; then
  check_header "strict-transport-security" "max-age"
fi
grep -iq "^server:.*uvicorn" <<<"$hdrs" && bad "Server 標頭洩漏 uvicorn" || ok "無 Server 版本洩漏"

echo "== 不該存在的端點 =="
for p in /docs /redoc /openapi.json; do
  c="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE$p")"
  [[ "$c" == "404" ]] && ok "$p 已關閉" || bad "$p 回應 $c（應為 404）"
done

echo "== 未授權存取 =="
c="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/sessions")"
[[ "$c" == "401" ]] && ok "未登入列出 session 被拒（401）" || bad "/api/sessions 回應 $c（應為 401）"
c="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/s/doesnotexist0000000000/raw")"
[[ "$c" == "404" ]] && ok "不存在的內容回 404（不洩漏存在性）" || bad "raw 回應 $c（應為 404）"

echo "== Google 登入 =="
state_json="$(curl -sS "$BASE/auth/state")"
if grep -q '"google":true' <<<"$state_json"; then
  loc="$(curl -sS -o /dev/null -D - -w '' "$BASE/auth/google/start" | grep -i '^location:' | tr -d '\r')"
  c="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/auth/google/start")"
  [[ "$c" == "303" ]] && ok "/auth/google/start 轉向（303）" || bad "/auth/google/start 回應 $c（應為 303）"
  grep -q "accounts.google.com" <<<"$loc" \
    && ok "轉向目標為 accounts.google.com" || bad "轉向目標不對：$loc"
  grep -q "code_challenge_method=S256" <<<"$loc" \
    && ok "已啟用 PKCE S256" || bad "轉向網址缺 PKCE code_challenge"
  grep -q "client_secret" <<<"$loc" && bad "轉向網址洩漏 client_secret" || ok "轉向網址未洩漏 client_secret"
  c="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/auth/google/callback?code=x&state=bogusbogusbogus")"
  [[ "$c" == "303" ]] && ok "偽造 state 被拒（轉回首頁）" || bad "偽造 state 回應 $c"
  c="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/auth/rescue?c=bogus")"
  [[ "$c" == "303" ]] && ok "無效緊急碼被拒" || bad "/auth/rescue 回應 $c"
else
  printf '  – Google 登入未啟用（未設 GOOGLE_CLIENT_ID / UID_PEPPER），跳過這組檢查\n'
  c="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/auth/google/start")"
  [[ "$c" == "404" ]] && ok "未啟用時 /auth/google/start 為 404" || bad "/auth/google/start 回應 $c（應為 404）"
fi

echo "== robots =="
curl -sS "$BASE/robots.txt" | grep -q "Disallow: /" \
  && ok "robots.txt 全站禁止索引" || bad "robots.txt 未禁止索引"

echo
printf '通過 %d 項，失敗 %d 項\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1
