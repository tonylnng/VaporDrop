# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY app/requirements.txt /srv/app/requirements.txt
RUN pip install --no-cache-dir -r /srv/app/requirements.txt

COPY app /srv/app
COPY schema.sql /srv/schema.sql

# 非 root 執行；/vapor 與 /data 由 compose 掛載
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vapor \
    && mkdir -p /vapor /data \
    && chown -R 10001:10001 /vapor /data /srv

USER 10001:10001

EXPOSE 8080

# --no-access-log 是硬需求：不留任何請求紀錄
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--no-access-log", \
     "--no-server-header", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--timeout-keep-alive", "20"]
