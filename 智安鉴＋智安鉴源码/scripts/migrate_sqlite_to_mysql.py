#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把旧版 SQLite 数据库迁移到 MySQL（一次性脚本，可重复执行）
=========================================================
用法（在仓库根目录）：

    # 目标库连接通过环境变量指定，默认连 127.0.0.1:3306/zhianjian
    export ZS_DB_HOST=127.0.0.1 ZS_DB_PORT=3306
    export ZS_DB_USER=zhianjian ZS_DB_PASSWORD=zhianjian_pass_2026 ZS_DB_NAME=zhianjian
    python3 scripts/migrate_sqlite_to_mysql.py

    # 可选参数
    --sqlite data/zhianjian.db   # 源文件（默认 data/zhianjian.db）
    --truncate                   # 导入前清空 MySQL 目标表（谨慎）
    --dry-run                    # 只统计不写入

脚本幂等：目标表已有同主键记录时跳过（INSERT IGNORE），不会产生重复。
"""
import argparse
import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import database as db  # noqa: E402

# 按外键/引用顺序迁移
TABLES = [
    "tags",
    "units",
    "unit_tags",
    "domains",
    "vulnerabilities",
    "reports",
    "templates",
    "settings",
    "scan_meta",
    "users",
]
# 含自增 id 的表，导入后重置 AUTO_INCREMENT
AUTO_ID_TABLES = ["tags", "units", "domains", "vulnerabilities", "reports", "templates", "users"]


def _sqlite_columns(conn, table):
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def main() -> int:
    parser = argparse.ArgumentParser(description="SQLite → MySQL 数据迁移")
    parser.add_argument("--sqlite", default=str(ROOT / "data" / "zhianjian.db"))
    parser.add_argument("--truncate", action="store_true", help="导入前清空目标表")
    parser.add_argument("--dry-run", action="store_true", help="只统计，不写入")
    args = parser.parse_args()

    src_path = Path(args.sqlite)
    if not src_path.exists():
        print(f"[错误] 找不到 SQLite 文件：{src_path}")
        return 1

    print(f"源库：{src_path}")
    print(f"目标：MySQL {db.DB_USER}@{db.DB_HOST}:{db.DB_PORT}/{db.DB_NAME}")
    if args.dry_run:
        print("（dry-run：只统计，不写入）")

    src = sqlite3.connect(str(src_path))
    src.row_factory = sqlite3.Row

    if not args.dry_run:
        db.init_db()
    dst = None if args.dry_run else db.get_db()

    if args.truncate and dst:
        print("清空目标表…")
        for table in reversed(TABLES):
            dst.execute(f"DELETE FROM {table}")

    total = 0
    for table in TABLES:
        src_cols = _sqlite_columns(src, table)
        if not src_cols:
            print(f"  跳过 {table}（源库不存在该表）")
            continue
        rows = src.execute(f"SELECT * FROM {table}").fetchall()
        if not rows:
            print(f"  {table}: 0 行")
            continue
        if args.dry_run:
            print(f"  {table}: {len(rows)} 行")
            total += len(rows)
            continue

        dst_cols = {r["name"] for r in dst.cursor().execute(
            "SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", (table,)).fetchall()}
        cols = [c for c in src_cols if c in dst_cols]
        placeholders = ",".join(["?"] * len(cols))
        col_sql = ",".join(f"`{c}`" for c in cols)
        sql = f"INSERT IGNORE INTO {table} ({col_sql}) VALUES ({placeholders})"
        ok, skipped = 0, 0
        for row in rows:
            try:
                cur = dst.execute(sql, tuple(row[c] for c in cols))
                if cur.rowcount > 0:
                    ok += 1
                else:
                    skipped += 1
            except Exception as e:
                print(f"    [跳过] {table} 行 id={row['id'] if 'id' in row.keys() else '?'}: {e}")
                skipped += 1
        print(f"  {table}: 新增 {ok} / 共 {len(rows)} 行" + (f"（重复跳过 {skipped}）" if skipped else ""))
        total += ok

    if dst:
        # 让自增 id 从现有最大值之后继续
        for table in AUTO_ID_TABLES:
            dst.execute(f"ALTER TABLE {table} AUTO_INCREMENT = 1")
        dst.commit()

    print(f"完成，共处理 {total} 行")
    if dst:
        dst.close()
    src.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
