# -*- coding: utf-8 -*-
"""漏洞知识库路由"""
from flask import Blueprint, request, jsonify, render_template

import database as db
from core.helpers import now_display

bp = Blueprint("vulns", __name__)


@bp.get("/vulnerabilities")
def page():
    return render_template("vulnerabilities.html")


@bp.get("/api/vulnerabilities")
def vuln_list():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(1, int(request.args.get("limit", 10))))
    name = request.args.get("name", "").strip()
    severity = request.args.get("severity", "").strip()
    sql = "SELECT * FROM vulnerabilities WHERE 1=1"
    params = []
    if name:
        sql += " AND name LIKE ?"
        params.append(f"%{name}%")
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    sql += " ORDER BY id DESC"
    rows, total = db.paginate(sql, params, page, limit)
    return jsonify(code=0, data=[dict(r) for r in rows], count=total)


@bp.get("/api/vulnerabilities/options")
def vuln_options():
    rows = db.query_all("SELECT id, name, severity, description, harm, suggestion FROM vulnerabilities ORDER BY name")
    return jsonify(code=0, data=[dict(r) for r in rows])


@bp.get("/api/vulnerability/detail")
def vuln_detail():
    vid = request.args.get("id")
    row = db.query_one("SELECT * FROM vulnerabilities WHERE id=?", (vid,))
    if not row:
        return jsonify(code=1, msg="记录不存在")
    return jsonify(code=0, data=dict(row))


@bp.post("/api/vulnerability/add")
def vuln_add():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(code=1, msg="漏洞名称不能为空")
    vid = db.execute(
        """INSERT INTO vulnerabilities(name, description, harm, suggestion, severity, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?)""",
        (name, data.get("description", ""), data.get("harm", ""), data.get("suggestion", ""),
         data.get("severity", "unknown"), now_display(), now_display()))
    return jsonify(code=0, msg="新增成功", id=vid)


@bp.post("/api/vulnerability/update")
def vuln_update():
    data = request.get_json(silent=True) or {}
    vid = data.get("id")
    if not vid:
        return jsonify(code=1, msg="缺少 id")
    fields = ["name", "description", "harm", "suggestion", "severity"]
    sets, params = [], []
    for f in fields:
        if f in data and data[f] is not None:
            sets.append(f"{f}=?")
            params.append(data[f])
    if not sets:
        return jsonify(code=1, msg="没有可更新的字段")
    params.append(now_display())
    params.append(vid)
    db.execute(f"UPDATE vulnerabilities SET {','.join(sets)}, updated_at=? WHERE id=?", (*params,))
    return jsonify(code=0, msg="更新成功")


@bp.post("/api/vulnerability/delete")
def vuln_delete():
    data = request.get_json(silent=True) or {}
    vid = data.get("id")
    db.execute("DELETE FROM vulnerabilities WHERE id=?", (vid,))
    return jsonify(code=0, msg="删除成功")
