# -*- coding: utf-8 -*-
"""登录 / 退出 / 修改密码 / 用户管理 路由"""
from flask import Blueprint, jsonify, redirect, render_template, request, session

import database as db
from core import auth

bp = Blueprint("users", __name__)


def _deny_admin():
    """非管理员访问用户管理接口时的统一响应"""
    if auth.is_admin():
        return None
    return jsonify(code=1, msg="需要管理员权限"), 403


# ==================== 页面 ====================
@bp.get("/login")
def login_page():
    if auth.current_user():
        return redirect("/")
    return render_template("login.html")


@bp.get("/users")
def users_page():
    return render_template("users.html")


# ==================== 登录 / 退出 ====================
@bp.post("/api/auth/login")
def do_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify(code=1, msg="请输入用户名和密码"), 400

    row = auth.get_user_by_name(username)
    if not row or not auth.verify_password(password, row["password_hash"]):
        return jsonify(code=1, msg="用户名或密码错误"), 401
    if not row["is_active"]:
        return jsonify(code=1, msg="该账号已被停用，请联系管理员"), 403

    auth.login_session(row)
    return jsonify(code=0, msg="登录成功", data={
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "role_cn": auth.ROLE_CN.get(row["role"], row["role"]),
    })


@bp.post("/api/auth/logout")
def do_logout():
    auth.logout_session()
    return jsonify(code=0, msg="已退出登录")


@bp.get("/api/auth/me")
def me():
    u = auth.current_user()
    if not u:
        return jsonify(code=1, msg="未登录"), 401
    return jsonify(code=0, data={
        "id": u["id"],
        "username": u["username"],
        "display_name": u["display_name"],
        "role": u["role"],
        "role_cn": auth.ROLE_CN.get(u["role"], u["role"]),
        "last_login_at": u["last_login_at"],
        "default_pwd": bool(session.get("default_pwd")),
    })


@bp.post("/api/auth/password")
def change_own_password():
    """修改自己的登录密码（需校验原密码）"""
    u = auth.current_user()
    if not u:
        return jsonify(code=1, msg="未登录"), 401
    row = auth.get_user(u["id"])
    data = request.get_json(silent=True) or {}
    old_pwd = data.get("old_password") or ""
    new_pwd = data.get("new_password") or ""
    if not auth.verify_password(old_pwd, row["password_hash"]):
        return jsonify(code=1, msg="原密码不正确"), 400
    err = auth.validate_password(new_pwd)
    if err:
        return jsonify(code=1, msg=err), 400
    if new_pwd == old_pwd:
        return jsonify(code=1, msg="新密码不能与原密码相同"), 400

    new_hash = auth.hash_password(new_pwd)
    db.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
               (new_hash, db.now_str(), u["id"]))
    # 自己改密码不应该把自己踢下线：同步刷新本会话的密码指纹
    session["pwh"] = auth.password_tag(new_hash)
    session["default_pwd"] = False
    return jsonify(code=0, msg="密码已修改，请牢记新密码")


# ==================== 用户管理（仅管理员）====================
@bp.get("/api/users")
def user_list():
    denied = _deny_admin()
    if denied:
        return denied
    kw = (request.args.get("keyword") or "").strip()
    sql = ("SELECT id,username,display_name,role,is_active,remark,"
           "created_at,updated_at,last_login_at FROM users WHERE 1=1")
    params = []
    if kw:
        sql += " AND (username LIKE ? OR display_name LIKE ?)"
        params += [f"%{kw}%", f"%{kw}%"]
    sql += " ORDER BY id ASC"
    rows = []
    for r in db.query_all(sql, tuple(params)):
        d = dict(r)
        d["role_cn"] = auth.ROLE_CN.get(d["role"], d["role"])
        rows.append(d)
    return jsonify(code=0, msg="ok", count=len(rows), data=rows)


@bp.post("/api/users/add")
def user_add():
    denied = _deny_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "user"
    display_name = (data.get("display_name") or "").strip()
    remark = (data.get("remark") or "").strip()

    err = auth.validate_username(username)
    if err:
        return jsonify(code=1, msg=err), 400
    err = auth.validate_password(password)
    if err:
        return jsonify(code=1, msg=err), 400
    if role not in auth.ROLES:
        return jsonify(code=1, msg="角色不合法"), 400
    if auth.get_user_by_name(username):
        return jsonify(code=1, msg=f"用户名「{username}」已存在"), 400

    now = db.now_str()
    uid = db.execute(
        """INSERT INTO users(username,password_hash,display_name,role,is_active,remark,created_at,updated_at)
           VALUES(?,?,?,?,1,?,?,?)""",
        (username, auth.hash_password(password), display_name or username, role, remark, now, now))
    return jsonify(code=0, msg=f"已新增账号「{username}」", data={"id": uid})


@bp.post("/api/users/update")
def user_update():
    denied = _deny_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    try:
        uid = int(data.get("id") or 0)
    except (TypeError, ValueError):
        uid = 0
    row = auth.get_user(uid)
    if not row:
        return jsonify(code=1, msg="账号不存在"), 404

    me = auth.current_user()
    role = data.get("role") or row["role"]
    is_active = 1 if data.get("is_active", row["is_active"]) in (1, True, "1", "true") else 0
    display_name = (data.get("display_name") if data.get("display_name") is not None
                    else row["display_name"])
    remark = data.get("remark") if data.get("remark") is not None else row["remark"]
    password = data.get("password") or ""

    if role not in auth.ROLES:
        return jsonify(code=1, msg="角色不合法"), 400
    if uid == me["id"] and (role != "admin" or not is_active):
        return jsonify(code=1, msg="不能修改自己的角色或停用自己的账号"), 400
    # 不能把最后一名启用状态的管理员降级或停用
    if row["role"] == "admin" and row["is_active"] and (role != "admin" or not is_active):
        if auth.active_admin_count(exclude_id=uid) < 1:
            return jsonify(code=1, msg="系统至少要保留一名启用的管理员"), 400
    if password:
        err = auth.validate_password(password)
        if err:
            return jsonify(code=1, msg=err), 400

    sql = "UPDATE users SET display_name=?,role=?,is_active=?,remark=?,updated_at=?"
    params = [display_name, role, is_active, remark, db.now_str()]
    if password:
        sql += ",password_hash=?"
        params.append(auth.hash_password(password))
    sql += " WHERE id=?"
    params.append(uid)
    db.execute(sql, tuple(params))
    return jsonify(code=0, msg=("已更新账号「%s」" % row["username"])
                   + ("（密码已重置）" if password else ""))


@bp.post("/api/users/delete")
def user_delete():
    denied = _deny_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    try:
        uid = int(data.get("id") or 0)
    except (TypeError, ValueError):
        uid = 0
    row = auth.get_user(uid)
    if not row:
        return jsonify(code=1, msg="账号不存在"), 404

    me = auth.current_user()
    if uid == me["id"]:
        return jsonify(code=1, msg="不能删除当前登录的账号"), 400
    if row["role"] == "admin" and row["is_active"] and auth.active_admin_count(exclude_id=uid) < 1:
        return jsonify(code=1, msg="系统至少要保留一名启用的管理员"), 400

    db.execute("DELETE FROM users WHERE id=?", (uid,))
    return jsonify(code=0, msg=f"已删除账号「{row['username']}」")
