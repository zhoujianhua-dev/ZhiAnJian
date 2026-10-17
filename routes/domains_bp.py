# -*- coding: utf-8 -*-
"""域名资产（ICP 备案）路由"""
import json
from datetime import datetime

from flask import Blueprint, request, jsonify, render_template

import database as db
from core.helpers import now_display

bp = Blueprint("domains", __name__)


@bp.get("/domains")
def page():
    return render_template("domains.html")


@bp.get("/api/domains")
def domain_list():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(1, int(request.args.get("limit", 10))))
    unit = request.args.get("unitName", "").strip()
    dom = request.args.get("domain", "").strip()
    sql = "SELECT * FROM domains WHERE is_deleted=0"
    params = []
    if unit:
        sql += " AND unit_name LIKE ?"
        params.append(f"%{unit}%")
    if dom:
        sql += " AND domain LIKE ?"
        params.append(f"%{dom}%")
    sql += " ORDER BY id DESC"
    rows, total = db.paginate(sql, params, page, limit)
    return jsonify(code=0, data=[dict(r) for r in rows], count=total)


def import_domains_from_json(json_data):
    """
    通用域名导入函数（兼容三种数据格式）：
      1. 列表 [{domain, unitName, ...}]
      2. {"params": {"list": [...]}}
      3. {"result": {"params": {"list": [...]}}}
    :return: (成功数量, 错误列表)
    """
    if isinstance(json_data, str):
        try:
            json_data = json.loads(json_data)
        except json.JSONDecodeError:
            return 0, ["无效的 JSON 格式"]
    domain_list = []
    if isinstance(json_data, list):
        domain_list = json_data
    elif isinstance(json_data, dict):
        if "params" in json_data and isinstance(json_data["params"], dict):
            domain_list = json_data["params"].get("list", [])
        elif "result" in json_data and isinstance(json_data["result"], dict):
            domain_list = json_data["result"].get("params", {}).get("list", [])
    if not domain_list:
        return 0, ["JSON 格式不符合预期，未找到 'list' 数据"]

    success, errors, now = 0, [], now_display()
    for item in domain_list:
        if not isinstance(item, dict):
            continue
        domain = (item.get("domain") or "").strip()
        if not domain:
            errors.append(f"缺少 'domain' 字段: {item}")
            continue
        try:
            rt = item.get("updateRecordTime") or item.get("update_record_time") or ""
            if rt and len(rt) <= 16:
                rt += ":00"
            existing = db.query_one("SELECT id FROM domains WHERE domain=?", (domain,))
            if existing:
                db.execute(
                    """UPDATE domains SET unit_name=?, main_licence=?, service_licence=?, nature_name=?,
                       content_type_name=?, limit_access=?, update_record_time=?, is_deleted=0 WHERE id=?""",
                    (item.get("unitName", ""), item.get("mainLicence", ""), item.get("serviceLicence", ""),
                     item.get("natureName", ""), item.get("contentTypeName", ""),
                     item.get("limitAccess", ""), rt, existing["id"]))
            else:
                db.execute(
                    """INSERT INTO domains(unit_name, domain, main_licence, service_licence, nature_name,
                       content_type_name, limit_access, update_record_time, is_deleted, created_at)
                       VALUES(?,?,?,?,?,?,?,?,0,?)""",
                    (item.get("unitName", ""), domain, item.get("mainLicence", ""),
                     item.get("serviceLicence", ""), item.get("natureName", ""),
                     item.get("contentTypeName", ""), item.get("limitAccess", ""), rt, now))
            success += 1
        except Exception as e:
            errors.append(f"处理失败: {domain} 错误: {e}")
    return success, errors


@bp.post("/api/domains/import-json")
def domain_import_json():
    data = request.get_json(silent=True) or {}
    payload = data.get("data", "")
    success, errors = import_domains_from_json(payload)
    return jsonify(code=0, msg="导入完成", success_count=success, error_count=len(errors), errors=errors[:50])


@bp.post("/api/domains/edit")
def domain_edit():
    """新增（无 id）或更新（有 id）域名。更新时只改传入字段，不强制回传 domain。"""
    data = request.get_json(silent=True) or {}
    did = data.get("id")
    domain = (data.get("domain") or "").strip()
    fields = ["unit_name", "domain", "main_licence", "service_licence", "nature_name",
              "content_type_name", "limit_access", "update_record_time"]
    if not did:
        # 新增：必须提供域名；同域名存在则更新
        if not domain:
            return jsonify(code=1, msg="域名不能为空")
        existing = db.query_one("SELECT id FROM domains WHERE domain=? AND is_deleted=0", (domain,))
        if existing:
            did = existing["id"]
        else:
            did = db.execute(
                """INSERT INTO domains(unit_name, domain, main_licence, service_licence, nature_name,
                   content_type_name, limit_access, update_record_time, is_deleted, created_at)
                   VALUES(?,?,?,?,?,?,?,?,0,?)""",
                (data.get("unit_name", ""), domain, data.get("main_licence", ""),
                 data.get("service_licence", ""), data.get("nature_name", ""),
                 data.get("content_type_name", ""), data.get("limit_access", ""),
                 data.get("update_record_time", ""), now_display()))
            return jsonify(code=0, msg="新增成功", id=did)
    if not db.query_one("SELECT id FROM domains WHERE id=?", (did,)):
        return jsonify(code=1, msg="域名记录不存在")
    sets, params = [], []
    for f in fields:
        if f in data and data[f] is not None:
            sets.append(f"{f}=?")
            params.append(data[f])
    if sets:
        params.append(did)
        db.execute(f"UPDATE domains SET {','.join(sets)} WHERE id=?", (*params,))
    return jsonify(code=0, msg="更新成功")


@bp.post("/api/domains/delete")
def domain_delete():
    data = request.get_json(silent=True) or {}
    did = data.get("id")
    db.execute("UPDATE domains SET is_deleted=1 WHERE id=?", (did,))
    return jsonify(code=0, msg="删除成功")


@bp.post("/api/domains/batch-query")
def batch_query():
    data = request.get_json(silent=True) or {}
    qtype = data.get("query_type")
    values = data.get("values", [])
    if not values:
        return jsonify(code=1, msg="缺少查询值")
    if qtype == "unit":
        sql = "SELECT unit_name, domain FROM domains WHERE is_deleted=0 AND (" + \
              " OR ".join(["unit_name LIKE ?"] * len(values)) + ")"
    else:
        sql = "SELECT unit_name, domain FROM domains WHERE is_deleted=0 AND (" + \
              " OR ".join(["domain LIKE ?"] * len(values)) + ")"
    rows = db.query_all(sql, [f"%{v}%" for v in values])
    return jsonify(code=0, data=[dict(r) for r in rows])


@bp.get("/api/domains/by-unit")
def by_unit():
    name = request.args.get("unitName", "").strip()
    rows = db.query_all("SELECT * FROM domains WHERE is_deleted=0 AND unit_name LIKE ? ORDER BY id", (f"%{name}%",))
    return jsonify(code=0, data=[dict(r) for r in rows])
