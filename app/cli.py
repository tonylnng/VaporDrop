"""管理 CLI。在容器內執行：

    docker compose exec api python -m app.cli invite --note "Ian 的 MacBook"
    docker compose exec api python -m app.cli users
    docker compose exec api python -m app.cli purge
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys

from . import config, db


def _fmt(ts: int | None) -> str:
    if not ts:
        return "-"
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def cmd_invite(args: argparse.Namespace) -> int:
    db.init()
    code, expires = db.create_invite(note=args.note, ttl=args.ttl)
    base = args.base_url or (config.ORIGINS[0] if config.ORIGINS else "https://localhost")
    print("邀請碼：", code)
    print("有效至：", _fmt(expires))
    print("註冊連結：", f"{base}/?invite={code}")
    print()
    print("提醒：一次性使用，過期或用畢即失效。請以安全通道遞送。")
    return 0


def cmd_users(args: argparse.Namespace) -> int:
    db.init()
    conn = db._connect()
    rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    if not rows:
        print("尚無用戶。首次部署時直接開首頁即可 bootstrap 第一個帳號。")
        return 0
    for row in rows:
        creds = db.credentials_for_uid(row["uid"])
        flag = " [已停用]" if row["disabled"] else ""
        print(f"{row['handle']}{flag}  uid={row['uid']}  建立於 {_fmt(row['created_at'])}")
        for c in creds:
            print(
                f"    passkey {c['credential_id'][:16]}…  "
                f"label={c['label'] or '-'}  transports={c['transports'] or '-'}  "
                f"最近使用 {_fmt(c['last_used_at'])}"
            )
    return 0


def cmd_disable(args: argparse.Namespace) -> int:
    db.init()
    conn = db._connect()
    with conn:
        cur = conn.execute(
            "UPDATE users SET disabled = ? WHERE handle = ?",
            (0 if args.enable else 1, args.handle),
        )
    if cur.rowcount == 0:
        print("找不到該 handle", file=sys.stderr)
        return 1
    print(("已啟用 " if args.enable else "已停用 ") + args.handle)
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """緊急清除：抹掉 tmpfs 上所有密文。不影響 Passkey 憑證。"""
    import shutil

    count = 0
    if os.path.isdir(config.BLOB_DIR):
        for entry in os.listdir(config.BLOB_DIR):
            path = os.path.join(config.BLOB_DIR, entry)
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                count += 1
    print(f"已清除 {count} 個 session 目錄。Redis metadata 會在 TTL 內自然消失，")
    print("如需立即清空可執行： docker compose exec redis redis-cli FLUSHDB")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vapor", description="VaporDrop 管理工具")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("invite", help="產生一次性註冊邀請碼")
    p.add_argument("--note", default="", help="備註，僅供你自己辨識")
    p.add_argument("--ttl", type=int, default=None, help="有效秒數，預設 900")
    p.add_argument("--base-url", default="", help="用於組出註冊連結")
    p.set_defaults(func=cmd_invite)

    p = sub.add_parser("users", help="列出用戶與其 Passkey")
    p.set_defaults(func=cmd_users)

    p = sub.add_parser("disable", help="停用或啟用某個 handle")
    p.add_argument("handle")
    p.add_argument("--enable", action="store_true", help="改為啟用")
    p.set_defaults(func=cmd_disable)

    p = sub.add_parser("purge", help="立即抹除 tmpfs 上所有密文")
    p.set_defaults(func=cmd_purge)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
