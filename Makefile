# VaporDrop 常用指令。詳細說明見 docs/DEPLOY.md
.DEFAULT_GOAL := help
COMPOSE := docker compose

.PHONY: help up down restart build logs ps test dev invite users purge verify nuke

help: ## 顯示可用指令
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

up: ## 建置並啟動全部服務
	$(COMPOSE) up -d --build

down: ## 停止服務（保留 Passkey 資料）
	$(COMPOSE) down

restart: ## 重啟 vapordrop-api（會清掉所有內容與登入狀態）
	$(COMPOSE) up -d --force-recreate vapordrop-api

build: ## 只重新建置映像
	$(COMPOSE) build

ps: ## 服務狀態
	$(COMPOSE) ps

logs: ## 查看容器輸出（正常情況應該幾乎是空的）
	$(COMPOSE) logs --tail 50

test: ## 跑單元/整合測試（需 pip install -r requirements-dev.txt）
	python -m pytest tests -q

dev: ## 本機開發伺服器（fakeredis，http://localhost:8080）
	python tools/devserver.py

invite: ## 產生一次性註冊邀請連結
	$(COMPOSE) exec vapordrop-api python -m app.cli invite --base-url "https://$${SITE_ADDRESS:-localhost}"

users: ## 列出帳號與 Passkey 裝置
	$(COMPOSE) exec vapordrop-api python -m app.cli users

purge: ## 緊急清空所有內容（不影響帳號）
	$(COMPOSE) exec vapordrop-api python -m app.cli purge
	$(COMPOSE) exec vapordrop-redis redis-cli FLUSHDB

verify: ## 部署後驗收（make verify URL=https://your-domain）
	./scripts/verify.sh "$(URL)"

nuke: ## 銷毀一切，包含 Passkey 憑證與 TLS 憑證
	$(COMPOSE) down -v
