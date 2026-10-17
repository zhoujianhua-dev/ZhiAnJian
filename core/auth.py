# -*- coding: utf-8 -*-
"""
智安鉴 · 登录与账号权限
======================
账号保存在 SQLite 的 users 表，密码经 PBKDF2 加盐哈希后存储（不落明文、不可逆）；
登录状态放在 Flask 的签名 session cookie 里，由 config.json 里的 secret_key 签名，
因此重启容器不会把已登录的用户踢下线。

角色：
  admin  管理员   —— 全部业务功能 + 「用户管理」（增删账号、改角色、重置密码、停用）
  user   普通用户 —— 全部业务功能，看不到「用户管理」入口，接口层也会拒绝
"""
import re
import secrets
import hashlib

from flask import g, session
from werkzeug.security import check_password_hash, generate_password_hash

import database as db

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LEN = 6
ROLES = ("admin", "user")
ROLE_CN = {"admin": "管理员", "user": "普通用户"}


# ---------------- 口令 ----------------
def hash_password(raw):
    return generate_password_hash(raw or "")


def verify_password(raw, hashed):
    try:
        return check_password_hash(hashed or "", raw or "")
    except Exception:
        return False


def validate_username(name):
    if not USERNAME_RE.match(name or ""):
        return "用户名需为 3-32 位字母、数字、下划线、点或短横线"
    return None


def validate_password(pwd):
    if len(pwd or "") < MIN_PASSWORD_LEN:
        return f"密码至少 {MIN_PASSWORD_LEN} 位"
    return None


# ---------------- 账号查询 ----------------
def get_user(uid):
    """按 id 取原始行（含 password_hash，仅内部校验用）"""
    return db.query_one("SELECT * FROM users WHERE id=?", (uid,))


def get_user_by_name(username):
    return db.query_one("SELECT * FROM users WHERE username=?", (username,))


def active_admin_count(exclude_id=None):
    """启用状态的管理员数量（用于「不能没有管理员」的保护）"""
    sql = "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1"
    params = ()
    if exclude_id:
        sql += " AND id<>?"
        params = (exclude_id,)
    return db.query_one(sql, params)[0]


def password_tag(hashed):
    """密码指纹：会话里记一份，密码被改/被管理员重置后旧会话立即失效。

    注意不能直接截取哈希前缀 —— Werkzeug 的哈希形如 `scrypt:32768:8:1$salt$digest`，
    前缀是算法与参数，对所有密码都一样，必须整串摘要后才可区分。
    """
    return hashlib.sha256((hashed or "").encode("utf-8")).hexdigest()[:16]


def current_user():
    """当前登录用户（dict，不含密码哈希）；未登录、账号被删除或被停用时返回 None。

    同一次请求内只查一次库（结果挂在 flask.g 上）。
    """
    if "user" in g:
        return g.user
    uid = session.get("uid")
    if not uid:
        g.user = None
        return None
    row = get_user(uid)
    if not row or not row["is_active"]:
        g.user = None
        return None
    if session.get("pwh") and session["pwh"] != password_tag(row["password_hash"]):
        g.user = None
        return None
    d = dict(row)
    d.pop("password_hash", None)
    g.user = d
    return d


def is_admin():
    u = current_user()
    return bool(u and u["role"] == "admin")


# ---------------- 登录态 ----------------
def login_session(user):
    """登录成功：重开一份会话并换发新的 CSRF token（避免沿用登录前的旧会话）"""
    default_pwd = (user["role"] == "admin"
                   and verify_password(db.DEFAULT_ADMIN_PASSWORD, user["password_hash"]))
    session.clear()
    session["uid"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["pwh"] = password_tag(user["password_hash"])
    session["default_pwd"] = bool(default_pwd)
    session["_csrf"] = secrets.token_hex(16)
    session.permanent = True
    db.execute("UPDATE users SET last_login_at=? WHERE id=?", (db.now_str(), user["id"]))


def logout_session():
    session.clear()
