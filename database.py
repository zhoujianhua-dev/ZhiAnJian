# -*- coding: utf-8 -*-
"""
智安鉴 · 数据访问层
===================
基于 Python 内置 sqlite3 的轻量数据层，无第三方 ORM 依赖。
所有模块通过 get_db() 获取连接；首次启动自动建表。

表结构：
  tags            单位标签
  units           单位资产（企业信息）
  unit_tags       单位-标签 多对多
  domains         域名资产（ICP 备案信息）
  vulnerabilities 漏洞知识库
  reports         漏洞报告记录
  templates       报告 Word 模板（自定义）
  settings        KV 系统设置
  users           登录账号（管理员 / 普通用户）
"""
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

from config import DB_PATH

_local = threading.local()


def get_db():
    """获取当前线程的数据库连接"""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _local.conn = conn
    return conn


@contextmanager
def db_cursor():
    """事务化游标上下文"""
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enterprise_name TEXT NOT NULL,
    business_status TEXT DEFAULT '',
    legal_representative TEXT DEFAULT '',
    registered_capital TEXT DEFAULT '',
    paid_in_capital TEXT DEFAULT '',
    province TEXT DEFAULT '',
    city TEXT DEFAULT '',
    district TEXT DEFAULT '',
    credit_code TEXT DEFAULT '',
    industry TEXT DEFAULT '',
    former_names TEXT DEFAULT '',
    registered_address TEXT DEFAULT '',
    filing_status TEXT DEFAULT 'unknown',
    icp_total INTEGER DEFAULT -1,
    domain_count INTEGER DEFAULT -1,
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_units_name ON units(enterprise_name);

CREATE TABLE IF NOT EXISTS unit_tags (
    unit_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (unit_id, tag_id)
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unit_name TEXT DEFAULT '',
    domain TEXT NOT NULL,
    main_licence TEXT DEFAULT '',
    service_licence TEXT DEFAULT '',
    nature_name TEXT DEFAULT '',
    content_type_name TEXT DEFAULT '',
    limit_access TEXT DEFAULT '',
    update_record_time TEXT DEFAULT '',
    is_deleted INTEGER DEFAULT 0,
    created_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_domains_unit ON domains(unit_name);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    harm TEXT DEFAULT '',
    suggestion TEXT DEFAULT '',
    severity TEXT DEFAULT 'unknown',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_vuln_name ON vulnerabilities(name);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL UNIQUE,
    unit_name TEXT DEFAULT '',
    vul_name TEXT DEFAULT '',
    system_name TEXT DEFAULT '',
    domain TEXT DEFAULT '',
    address TEXT DEFAULT '',
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'unknown',
    harm TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    suggestion TEXT DEFAULT '',
    prove TEXT DEFAULT '',
    detail_images TEXT DEFAULT '',
    prove_images TEXT DEFAULT '',
    status INTEGER DEFAULT 0,
    lifecycle TEXT DEFAULT 'open',
    lifecycle_remark TEXT DEFAULT '',
    lifecycle_at TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reports_unit ON reports(unit_name);
CREATE INDEX IF NOT EXISTS idx_reports_vul ON reports(vul_name);

CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    is_default INTEGER DEFAULT 0,
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    role TEXT DEFAULT 'user',
    is_active INTEGER DEFAULT 1,
    remark TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT '',
    last_login_at TEXT DEFAULT ''
);
"""

# 首次启动自动创建的内置管理员（仅当 users 表为空时写入，之后完全由「用户管理」维护）
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123456"


def init_db():
    """初始化数据库（幂等）"""
    conn = get_db()
    conn.executescript(SCHEMA)
    # 旧库增量迁移：reports 增加独立图片字段（检测过程图片 / 归属证明图片，JSON 数组）
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
    if "detail_images" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN detail_images TEXT DEFAULT ''")
    if "prove_images" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN prove_images TEXT DEFAULT ''")
    # 漏洞处置全生命周期：open 待整改 / fixing 整改中 / fixed 已修复待复测 / verified 复测通过
    if "lifecycle" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN lifecycle TEXT DEFAULT 'open'")
    if "lifecycle_remark" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN lifecycle_remark TEXT DEFAULT ''")
    if "lifecycle_at" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN lifecycle_at TEXT DEFAULT ''")
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
    row = cur.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    cur.close()
    return row["value"] if row else default


def set_setting(key, value):
    cur = get_db().cursor()
    cur.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    get_db().commit()
    cur.close()


# ---------------- 分页工具 ----------------
def paginate(query_sql, params, page, limit):
    """通用分页：返回 (rows, total)"""
    conn = get_db()
    cur = conn.cursor()
    total = cur.execute(f"SELECT COUNT(*) FROM ({query_sql})", params).fetchone()[0]
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
