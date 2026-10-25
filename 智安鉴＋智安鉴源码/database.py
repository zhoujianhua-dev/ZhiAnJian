# -*- coding: utf-8 -*-
"""
智安鉴 · 数据访问层（MySQL）
===========================
基于 PyMySQL 的轻量数据层，无 ORM 依赖。所有模块通过 get_db() 获取连接，
首次启动自动建库建表（幂等）。

连接参数由环境变量提供（docker compose 中已配置）：
  ZS_DB_HOST      默认 127.0.0.1
  ZS_DB_PORT      默认 3306
  ZS_DB_USER      默认 root
  ZS_DB_PASSWORD  默认 空
  ZS_DB_NAME      默认 zhianjian

表结构：
  tags            单位标签
  units           单位资产（企业信息）
  unit_tags       单位-标签 多对多
  domains         域名资产（ICP 备案信息）
  vulnerabilities 漏洞知识库
  reports         漏洞报告记录
  templates       报告 Word 模板（自定义）
  settings        KV 系统设置
  scan_meta       扫描任务的归属信息（单位/系统）
  users           登录账号（管理员 / 普通用户）
"""
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime

import pymysql
from pymysql.cursors import DictCursor

DB_HOST = os.environ.get("ZS_DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("ZS_DB_PORT", "3306") or 3306)
DB_USER = os.environ.get("ZS_DB_USER", "root")
DB_PASSWORD = os.environ.get("ZS_DB_PASSWORD", "")
DB_NAME = os.environ.get("ZS_DB_NAME", "zhianjian")

_local = threading.local()


class DbRow(dict):
    """查询结果行：支持 row["列名"]，也兼容旧代码里的 row[0]。"""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def _to_mysql(sql):
    """把 SQLite 风格 SQL 转成 MySQL 风格（占位符与少数语法糖）。"""
    text = sql.strip()
    upper = text.upper()
    if upper.startswith("INSERT OR IGNORE"):
        text = "INSERT IGNORE" + text[len("INSERT OR IGNORE"):]
    elif upper.startswith("INSERT OR REPLACE"):
        text = "REPLACE" + text[len("INSERT OR REPLACE"):]
    return text.replace("?", "%s")


def _split_statements(script):
    return [part.strip() for part in script.split(";") if part.strip()]


class DbCursor:
    """游标包装：统一占位符、Row 类型与 lastrowid 行为。"""

    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        if params is None:
            self._cur.execute(_to_mysql(sql))
        else:
            self._cur.execute(_to_mysql(sql), params)
        return self

    def executemany(self, sql, seq_params):
        self._cur.executemany(_to_mysql(sql), seq_params)
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        return DbRow(row) if row is not None else None

    def fetchall(self):
        return [DbRow(r) for r in self._cur.fetchall()]

    @property
    def lastrowid(self):
        return self._cur.lastrowid

    @property
    def rowcount(self):
        return self._cur.rowcount

    def close(self):
        self._cur.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class DbConnection:
    """连接包装：自动重连 + 支持 executescript（多条语句）。"""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        self._conn.ping(reconnect=True)
        return DbCursor(self._conn.cursor())

    def execute(self, sql, params=()):
        return self.cursor().execute(sql, params)

    def executescript(self, script):
        cur = self.cursor()
        for stmt in _split_statements(script):
            cur.execute(stmt)
        cur.close()

    def commit(self):
        # 连接为 autocommit，保留该方法兼容旧调用
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def _connect(with_db=True):
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
        database=DB_NAME if with_db else None,
        charset="utf8mb4", cursorclass=DictCursor,
        autocommit=True, connect_timeout=10,
    )


def _ensure_database():
    """首次启动自动建库（compose 里也会通过 MYSQL_DATABASE 创建）。"""
    conn = _connect(with_db=False)
    try:
        cur = conn.cursor()
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` "
            "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cur.close()
    finally:
        conn.close()


def get_db():
    """获取当前线程的数据库连接（断线自动重连）。"""
    conn = getattr(_local, "conn", None)
    if conn is None:
        last_err = None
        for _ in range(10):
            try:
                conn = DbConnection(_connect())
                break
            except Exception as e:  # 容器启动时数据库可能还没就绪
                last_err = e
                time.sleep(2)
        if conn is None:
            raise RuntimeError(f"无法连接 MySQL：{last_err}")
        _local.conn = conn
    return conn


@contextmanager
def db_cursor():
    """事务化游标上下文（连接为 autocommit，保留接口兼容）"""
    conn = get_db()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


SCHEMA = """
CREATE TABLE IF NOT EXISTS tags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(191) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT (''),
    created_at VARCHAR(19) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS units (
    id INT AUTO_INCREMENT PRIMARY KEY,
    enterprise_name VARCHAR(255) NOT NULL,
    business_status VARCHAR(64) NOT NULL DEFAULT '',
    legal_representative VARCHAR(64) NOT NULL DEFAULT '',
    registered_capital VARCHAR(64) NOT NULL DEFAULT '',
    paid_in_capital VARCHAR(64) NOT NULL DEFAULT '',
    province VARCHAR(64) NOT NULL DEFAULT '',
    city VARCHAR(64) NOT NULL DEFAULT '',
    district VARCHAR(64) NOT NULL DEFAULT '',
    credit_code VARCHAR(64) NOT NULL DEFAULT '',
    industry VARCHAR(128) NOT NULL DEFAULT '',
    former_names VARCHAR(500) NOT NULL DEFAULT '',
    registered_address VARCHAR(500) NOT NULL DEFAULT '',
    filing_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    icp_total INT NOT NULL DEFAULT -1,
    domain_count INT NOT NULL DEFAULT -1,
    created_at VARCHAR(19) NOT NULL DEFAULT '',
    updated_at VARCHAR(19) NOT NULL DEFAULT '',
    INDEX idx_units_name (enterprise_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS unit_tags (
    unit_id INT NOT NULL,
    tag_id INT NOT NULL,
    PRIMARY KEY (unit_id, tag_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    unit_name VARCHAR(255) NOT NULL DEFAULT '',
    domain VARCHAR(255) NOT NULL,
    main_licence VARCHAR(128) NOT NULL DEFAULT '',
    service_licence VARCHAR(128) NOT NULL DEFAULT '',
    nature_name VARCHAR(64) NOT NULL DEFAULT '',
    content_type_name VARCHAR(128) NOT NULL DEFAULT '',
    limit_access VARCHAR(64) NOT NULL DEFAULT '',
    update_record_time VARCHAR(19) NOT NULL DEFAULT '',
    is_deleted TINYINT NOT NULL DEFAULT 0,
    created_at VARCHAR(19) NOT NULL DEFAULT '',
    INDEX idx_domains_domain (domain),
    INDEX idx_domains_unit (unit_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(500) NOT NULL,
    name_en VARCHAR(500) NOT NULL DEFAULT '',
    description MEDIUMTEXT NOT NULL DEFAULT (''),
    harm MEDIUMTEXT NOT NULL DEFAULT (''),
    suggestion MEDIUMTEXT NOT NULL DEFAULT (''),
    severity VARCHAR(32) NOT NULL DEFAULT 'unknown',
    created_at VARCHAR(19) NOT NULL DEFAULT '',
    updated_at VARCHAR(19) NOT NULL DEFAULT '',
    INDEX idx_vuln_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    record_id VARCHAR(64) NOT NULL UNIQUE,
    unit_name VARCHAR(255) NOT NULL DEFAULT '',
    vul_name VARCHAR(500) NOT NULL DEFAULT '',
    vul_name_en VARCHAR(500) NOT NULL DEFAULT '',
    system_name VARCHAR(255) NOT NULL DEFAULT '',
    domain VARCHAR(255) NOT NULL DEFAULT '',
    address VARCHAR(1000) NOT NULL DEFAULT '',
    description MEDIUMTEXT NOT NULL DEFAULT (''),
    severity VARCHAR(32) NOT NULL DEFAULT 'unknown',
    harm MEDIUMTEXT NOT NULL DEFAULT (''),
    detail MEDIUMTEXT NOT NULL DEFAULT (''),
    suggestion MEDIUMTEXT NOT NULL DEFAULT (''),
    prove MEDIUMTEXT NOT NULL DEFAULT (''),
    detail_images MEDIUMTEXT NOT NULL DEFAULT (''),
    prove_images MEDIUMTEXT NOT NULL DEFAULT (''),
    status TINYINT NOT NULL DEFAULT 0,
    lifecycle VARCHAR(32) NOT NULL DEFAULT 'open',
    lifecycle_remark VARCHAR(1000) NOT NULL DEFAULT '',
    lifecycle_at VARCHAR(19) NOT NULL DEFAULT '',
    created_at VARCHAR(19) NOT NULL DEFAULT '',
    updated_at VARCHAR(19) NOT NULL DEFAULT '',
    INDEX idx_reports_unit (unit_name),
    INDEX idx_reports_vul (vul_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(191) NOT NULL UNIQUE,
    filename VARCHAR(255) NOT NULL,
    is_default TINYINT NOT NULL DEFAULT 0,
    created_at VARCHAR(19) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
    `key` VARCHAR(191) PRIMARY KEY,
    `value` MEDIUMTEXT NOT NULL DEFAULT ('')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 扫描任务归属信息（扫描引擎侧没有单位/系统字段，由智安鉴本地补存）
CREATE TABLE IF NOT EXISTS scan_meta (
    scan_id VARCHAR(64) PRIMARY KEY,
    target VARCHAR(500) NOT NULL DEFAULT '',
    unit_name VARCHAR(255) NOT NULL DEFAULT '',
    system_name VARCHAR(255) NOT NULL DEFAULT '',
    remark VARCHAR(500) NOT NULL DEFAULT '',
    created_at VARCHAR(19) NOT NULL DEFAULT '',
    updated_at VARCHAR(19) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(191) NOT NULL DEFAULT '',
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    is_active TINYINT NOT NULL DEFAULT 1,
    remark VARCHAR(500) NOT NULL DEFAULT '',
    created_at VARCHAR(19) NOT NULL DEFAULT '',
    updated_at VARCHAR(19) NOT NULL DEFAULT '',
    last_login_at VARCHAR(19) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

# 首次启动自动创建的内置管理员（仅当 users 表为空时写入，之后完全由「用户管理」维护）
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123456"


def _table_columns(conn, table):
    rows = conn.cursor().execute(
        "SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", (table,)).fetchall()
    return {r["name"] for r in rows}


def init_db():
    """初始化数据库（幂等）：建库、建表、补齐历史版本新增列。"""
    _ensure_database()
    conn = get_db()
    conn.executescript(SCHEMA)
    # 老库增量迁移：补齐历史上逐步新增的列（新库建表时已包含，自动跳过）
    cols = _table_columns(conn, "reports")
    report_columns = (
        ("detail_images", "MEDIUMTEXT NOT NULL DEFAULT ('')"),
        ("prove_images", "MEDIUMTEXT NOT NULL DEFAULT ('')"),
        ("lifecycle", "VARCHAR(32) NOT NULL DEFAULT 'open'"),
        ("lifecycle_remark", "VARCHAR(1000) NOT NULL DEFAULT ''"),
        ("lifecycle_at", "VARCHAR(19) NOT NULL DEFAULT ''"),
        ("vul_name_en", "VARCHAR(500) NOT NULL DEFAULT ''"),
    )
    for name, ddl in report_columns:
        if name not in cols:
            conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {ddl}")
    if "name_en" not in _table_columns(conn, "vulnerabilities"):
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN name_en VARCHAR(500) NOT NULL DEFAULT ''")
    conn.commit()


def ensure_default_admin():
    """首次启动写入内置管理员账号；已存在任何账号时直接跳过（幂等）。

    返回 {"created": True, "username": ..., "password": ...} 便于启动日志提示一次默认口令。
    """
    from core.auth import hash_password

    cur = get_db().cursor()
    n = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    cur.close()
    if n:
        return {"created": False}

    now = now_str()
    execute("""INSERT INTO users(username,password_hash,display_name,role,is_active,remark,created_at,updated_at)
        VALUES(?,?,?,?,1,?,?,?)""",
            (DEFAULT_ADMIN_USER, hash_password(DEFAULT_ADMIN_PASSWORD), "系统管理员", "admin",
             "内置管理员账号，登录后请及时修改密码", now, now))
    return {"created": True, "username": DEFAULT_ADMIN_USER, "password": DEFAULT_ADMIN_PASSWORD}


def seed_demo_data():
    """写入演示数据（非敏感，便于演示与测试；可在设置页一键清空）"""
    from core import tools as T

    def has_data():
        cur = get_db().cursor()
        n = cur.execute("SELECT COUNT(*) FROM units").fetchone()[0]
        cur.close()
        return n > 0

    if has_data():
        return {"code": 0, "msg": "已存在数据，跳过演示数据导入"}

    conn = get_db()
    cur = conn.cursor()
    now = now_str()

    # 演示标签
    cur.execute("INSERT INTO tags(name, description, created_at) VALUES(?,?,?)",
                ("重点监管单位", "演示标签：行业重点单位", now))
    cur.execute("INSERT INTO tags(name, description, created_at) VALUES(?,?,?)",
                ("测试资产", "演示标签：测试用资产", now))

    # 演示单位
    demo_units = [
        ("演示科技有限公司", "存续", "张**", "1000万元", "500万元", "浙江省", "杭州市", "西湖区",
         "91330100MA0000DEMO", "软件和信息技术服务业", "演示信息科技有限公司",
         "浙江省杭州市西湖区演示路 1 号", "has_filing", 3, 5),
        ("示例智慧能源有限公司", "存续", "李**", "5000万元", "2000万元", "浙江省", "宁波市", "鄞州区",
         "91330200MA0000DEMO", "电力、热力生产和供应业", "", "浙江省宁波市鄞州区示例路 88 号", "has_filing", 2, 4),
        ("样例网络科技有限公司", "存续", "王**", "100万元", "50万元", "浙江省", "金华市", "婺城区",
         "91330700MA0000DEMO", "互联网和相关服务", "", "浙江省金华市婺城区样例街 6 号", "unknown", -1, -1),
    ]
    for u in demo_units:
        cur.execute("""INSERT INTO units(enterprise_name,business_status,legal_representative,
            registered_capital,paid_in_capital,province,city,district,credit_code,industry,
            former_names,registered_address,filing_status,icp_total,domain_count,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (*u, now, now))
        unit_id = cur.lastrowid
        cur.execute("INSERT INTO unit_tags(unit_id, tag_id) VALUES(?,1)", (unit_id,))

    # 演示域名
    demo_domains = [
        ("演示科技有限公司", "demo-tech.com", "浙ICP备2026000000号-1", "浙ICP备2026000000号-1", "企业", "", "否", "2026-01-01 00:00:00"),
        ("演示科技有限公司", "www.demo-tech.com", "浙ICP备2026000000号-1", "浙ICP备2026000000号-2", "企业", "", "否", "2026-01-01 00:00:00"),
        ("示例智慧能源有限公司", "example-energy.cn", "浙ICP备2026000001号-1", "浙ICP备2026000001号-1", "企业", "", "否", "2026-01-01 00:00:00"),
        ("示例智慧能源有限公司", "app.example-energy.cn", "浙ICP备2026000001号-1", "浙ICP备2026000001号-3", "企业", "", "否", "2026-01-01 00:00:00"),
    ]
    for d in demo_domains:
        cur.execute("""INSERT INTO domains(unit_name,domain,main_licence,service_licence,
            nature_name,content_type_name,limit_access,update_record_time,is_deleted,created_at)
            VALUES(?,?,?,?,?,?,?,?,0,?)""", (*d, now))

    # 演示漏洞库
    demo_vulns = [
        ("SQL 注入漏洞", "应用程序未对用户输入进行参数化校验，攻击者可通过构造恶意 SQL 语句操纵数据库查询，获取敏感数据。",
         "可导致数据库信息泄露、数据被篡改或删除；严重时可被进一步利用获取服务器控制权。",
         "1. 使用参数化查询/预编译语句；2. 对输入做严格白名单校验；3. 最小权限原则配置数据库账户。", "high"),
        ("未授权访问漏洞", "系统管理接口或敏感功能未做身份校验，任意用户可直接访问。",
         "攻击者可绕过认证直接操作业务数据，造成数据泄露或功能滥用。",
         "1. 为所有管理接口增加身份认证；2. 配置访问控制策略；3. 定期审计访问日志。", "medium"),
        ("敏感信息泄露", "网站源码、配置文件、备份文件或接口响应中暴露了账号口令、内部地址等敏感信息。",
         "泄露的敏感信息可被攻击者用于进一步渗透、撞库或社工攻击。",
         "1. 排查并下线泄露文件；2. 配置 Web 服务器禁止目录浏览；3. 使用密钥管理服务替代硬编码。", "medium"),
        ("跨站脚本攻击（XSS）", "程序未对输出内容进行转义过滤，攻击者可注入恶意脚本在用户浏览器中执行。",
         "可窃取用户 Cookie、会话令牌，实现会话劫持、钓鱼或页面篡改。",
         "1. 对输出进行 HTML 实体编码；2. 启用 CSP 策略；3. 对输入做白名单校验。", "high"),
    ]
    for v in demo_vulns:
        cur.execute("""INSERT INTO vulnerabilities(name,description,harm,suggestion,severity,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?)""", (*v, now, now))

    # 演示报告（覆盖不同单位/等级，字段含富文本检测过程与归属证明，便于直接演示导出与体检）
    demo_reports = [
        ("ZD2026DEMO001", "演示科技有限公司", "SQL 注入漏洞", "会员中心系统", "demo-tech.com",
         "https://demo-tech.com/member/login",
         "登录接口未对用户参数进行参数化校验，存在 SQL 注入。", "high",
         "攻击者可绕过登录、拖取会员库，造成大规模敏感信息泄露，甚至写入 WebShell 控制服务器。",
         "<p>1. 在登录口用户名处输入单引号，页面返回数据库报错信息。</p>"
         "<p>2. 构造载荷 ' OR '1'='1 可成功绕过认证进入后台。</p>"
         "<p>3. 使用 sqlmap 对 id 参数进行注入，可获取当前数据库名与全部表结构，风险可稳定复现。</p>",
         "1. 全站改用参数化查询/预编译语句；2. 对输入做白名单校验并统一错误页；3. 数据库账户最小权限并开启审计。",
         "归属证明：域名 demo-tech.com 的 ICP 备案主体为“演示科技有限公司”（浙ICP备2026000000号-1）。"),
        ("ZD2026DEMO002", "演示科技有限公司", "跨站脚本攻击（XSS）", "官网内容管理系统", "www.demo-tech.com",
         "https://www.demo-tech.com/feedback",
         "意见反馈页对提交内容未做输出转义，存在存储型 XSS。", "high",
         "恶意脚本会在管理员查看反馈时执行，可窃取后台会话令牌、劫持管理员账户。",
         "<p>1. 在反馈内容中提交 &lt;script&gt;alert(document.cookie)&lt;/script&gt;。</p>"
         "<p>2. 管理员在后台打开该条反馈时脚本被执行，弹出会话 Cookie。</p>",
         "1. 输出进行 HTML 实体编码；2. 启用 CSP 策略；3. 对富文本做白名单过滤。",
         "归属证明：域名 www.demo-tech.com 的 ICP 备案主体为“演示科技有限公司”（浙ICP备2026000000号-2）。"),
        ("ZD2026DEMO003", "示例智慧能源有限公司", "未授权访问漏洞", "能源数据采集平台", "app.example-energy.cn",
         "https://app.example-energy.cn/api/user/list",
         "用户列表接口未校验身份令牌，可直接遍历访问。", "medium",
         "任意人员可拉取全量用户信息，造成客户资料泄露与越权操作。",
         "<p>1. 未登录状态直接请求 /api/user/list，返回完整用户数据。</p>"
         "<p>2. 递增 id 参数可遍历更多用户记录，无任何鉴权拦截。</p>",
         "1. 所有敏感接口强制身份认证与权限校验；2. 增加对象级访问控制；3. 记录并审计异常访问。",
         "归属证明：域名 app.example-energy.cn 的 ICP 备案主体为“示例智慧能源有限公司”（浙ICP备2026000001号-3）。"),
        ("ZD2026DEMO004", "样例网络科技有限公司", "敏感信息泄露", "对外门户系统", "",
         "",
         "站点根目录可访问备份压缩包，内含配置文件与账号口令。", "medium",
         "泄露的数据库账号与后台口令可被用于进一步入侵，风险高。",
         "<p>1. 访问 /backup/www.zip 可直接下载站点备份。</p>"
         "<p>2. 解压后配置文件中存在明文数据库账号口令。</p>",
         "1. 立即下线备份文件并清理 Web 目录；2. 禁止目录浏览；3. 轮换泄露口令并使用密钥管理。",
         ""),
    ]
    # 处置生命周期演示分布：001 已修复待复测 / 002 复测通过 / 003 整改中 / 004 待整改
    demo_lifecycle = ["fixed", "verified", "fixing", "open"]
    for idx, rep in enumerate(demo_reports):
        lc = demo_lifecycle[idx] if idx < len(demo_lifecycle) else "open"
        cur.execute("""INSERT INTO reports(record_id,unit_name,vul_name,system_name,domain,address,
            description,severity,harm,detail,suggestion,prove,status,lifecycle,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)""", (*rep, lc, now, now))

    conn.commit()
    cur.close()
    return {"code": 0, "msg": "演示数据导入完成"}


def clear_all_data():
    """清空全部业务数据（保留标签/设置等表结构）"""
    conn = get_db()
    conn.executescript("""
        DELETE FROM unit_tags;
        DELETE FROM reports;
        DELETE FROM vulnerabilities;
        DELETE FROM domains;
        DELETE FROM units;
        DELETE FROM tags;
    """)
    conn.commit()
    return {"code": 0, "msg": "已清空全部业务数据"}


# ---------------- 设置 KV ----------------
def get_setting(key, default=""):
    cur = get_db().cursor()
    row = cur.execute("SELECT `value` FROM settings WHERE `key`=?", (key,)).fetchone()
    cur.close()
    return row["value"] if row else default


def set_setting(key, value):
    cur = get_db().cursor()
    cur.execute("INSERT INTO settings(`key`,`value`) VALUES(?,?) "
                "ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", (key, str(value)))
    get_db().commit()
    cur.close()


# ---------------- 分页工具 ----------------
def paginate(query_sql, params, page, limit):
    """通用分页：返回 (rows, total)"""
    conn = get_db()
    cur = conn.cursor()
    total = cur.execute(f"SELECT COUNT(*) FROM ({query_sql}) AS _t", params).fetchone()[0]
    offset = (page - 1) * limit
    rows = cur.execute(query_sql + f" LIMIT {limit} OFFSET {offset}", params).fetchall()
    cur.close()
    return rows, total


# ---------------- 通用查询 ----------------
def query_all(sql, params=()):
    cur = get_db().cursor()
    rows = cur.execute(sql, params).fetchall()
    cur.close()
    return rows


def query_one(sql, params=()):
    cur = get_db().cursor()
    row = cur.execute(sql, params).fetchone()
    cur.close()
    return row


def execute(sql, params=()):
    cur = get_db().cursor()
    cur.execute(sql, params)
    get_db().commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id
