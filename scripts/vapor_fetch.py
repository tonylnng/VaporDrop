#!/usr/bin/env python3
"""VaporDrop 接收端腳本：給 VM 與 AI Agent 用。

在伺服器上取到的是密文，解密只發生在這裡。伺服器從未持有金鑰。

用法：
    export VAPOR_URL="https://vapor.example.com/s/<cid>"
    export VAPOR_TOKEN="<one-time token>"
    export VAPOR_KEY="<base64url 32-byte key>"

    python3 vapor_fetch.py --list             # 列出項目（不消耗 token 次數）
    python3 vapor_fetch.py                    # 取第一個項目並輸出到 stdout
    python3 vapor_fetch.py --all -o ./inbox   # 全部取下並解密到目錄

相依：python3 標準庫 + cryptography
    pip install cryptography
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    print("需要 cryptography：pip install cryptography", file=sys.stderr)
    raise SystemExit(2)


def b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def request(url: str, token: str) -> tuple[bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return res.read(), dict(res.headers)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print("內容不存在、已蒸發，或 token 已用盡。", file=sys.stderr)
        else:
            print(f"HTTP {exc.code}", file=sys.stderr)
        raise SystemExit(1)


def decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) <= 12:
        raise ValueError("資料長度不合法")
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def main() -> int:
    ap = argparse.ArgumentParser(description="取用並解密 VaporDrop 內容")
    ap.add_argument("--url", default=os.getenv("VAPOR_URL", ""), help="https://host/s/<cid>")
    ap.add_argument("--token", default=os.getenv("VAPOR_TOKEN", ""))
    ap.add_argument("--key", default=os.getenv("VAPOR_KEY", ""), help="base64url 金鑰；明文模式可省略")
    ap.add_argument("--item", default="", help="指定 item_id")
    ap.add_argument("--all", action="store_true", help="取下所有項目")
    ap.add_argument("--list", action="store_true", help="只列出項目")
    ap.add_argument("-o", "--out", default="", help="輸出目錄；未指定則寫 stdout")
    args = ap.parse_args()

    if not args.url or not args.token:
        print("缺少 --url 或 --token（也可用 VAPOR_URL / VAPOR_TOKEN）", file=sys.stderr)
        return 2

    base = args.url.rstrip("/")
    key = b64u_decode(args.key) if args.key else None
    if key is not None and len(key) != 32:
        print("金鑰必須是 32 bytes 的 base64url", file=sys.stderr)
        return 2

    manifest_raw, _ = request(f"{base}/manifest", args.token)
    manifest = json.loads(manifest_raw)
    items = manifest.get("items", [])
    if not items:
        print("這個 session 沒有內容。", file=sys.stderr)
        return 1

    def label(rec: dict) -> str:
        if key is None:
            try:
                return b64u_decode(rec.get("name", "")).decode()
            except Exception:
                return rec["item_id"]
        try:
            return decrypt(key, b64u_decode(rec["name"])).decode()
        except Exception:
            return rec["item_id"]

    if args.list:
        print(f"剩餘 {manifest.get('ttl', 0)} 秒，共 {len(items)} 項：")
        for rec in items:
            print(f"  {rec['item_id']}  {label(rec)}  ({rec['kind']}, {rec['size']} bytes)")
        return 0

    targets = items if args.all else [next((i for i in items if i["item_id"] == args.item), items[0])]

    if args.out:
        os.makedirs(args.out, mode=0o700, exist_ok=True)

    for rec in targets:
        blob, headers = request(f"{base}/raw?item={rec['item_id']}", args.token)
        data = blob if key is None or headers.get("X-Vapor-Plain") == "1" else decrypt(key, blob)
        name = label(rec)
        if args.out:
            safe = os.path.basename(name) or f"{rec['item_id']}.bin"
            path = os.path.join(args.out, safe)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            print(f"已寫入 {path} ({len(data)} bytes)", file=sys.stderr)
        else:
            sys.stdout.buffer.write(data)
            if len(targets) > 1:
                sys.stdout.buffer.write(b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
