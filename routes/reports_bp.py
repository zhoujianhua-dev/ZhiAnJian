# -*- coding: utf-8 -*-
"""报告管理路由（CRUD / 模板 / 导出 / 文件历史）"""
import os
import json as _json
import uuid

from flask import Blueprint, request, jsonify, render_template, send_file, Response

import database as db
from config import TEMPLATE_DIR, EXPORT_DIR, UPLOAD_DIR
from core import exporter
from core.asset_sync import sync_unit_and_domain
from core.tpl_bootstrap import extract_placeholders
from core import tpl_extract
from core.helpers import (sanitize_filename, now_display, now_ts, gen_record_id,
                          content_disposition, severity_cn, lifecycle_cn, lifecycle_can_move,
                          LIFECYCLE_ACTION, LIFECYCLE_CN)

bp = Blueprint("reports", __name__)


@bp.get("/reports")
def page():
    return render_template("reports.html")


@bp.get("/reports/ai")
def ai_page():
    return render_template("report_ai.html")


# ---------------- 报告 CRUD ----------------
@bp.get("/api/reports")
def report_list():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(1, int(request.args.get("limit", 10))))
    unit = request.args.get("unitName", "").strip()
    vul = request.args.get("vulName", "").strip()
    severity = request.args.get("severity", "").strip()
    lifecycle = request.args.get("lifecycle", "").strip()
    sql = "SELECT * FROM reports WHERE status=0"
    params = []
    if unit:
        sql += " AND unit_name LIKE ?"
        params.append(f"%{unit}%")
    if vul:
        sql += " AND vul_name LIKE ?"
        params.append(f"%{vul}%")
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if lifecycle in LIFECYCLE_CN:
        sql += " AND lifecycle=?"
        params.append(lifecycle)
    sql += " ORDER BY id DESC"
    rows, total = db.paginate(sql, params, page, limit)
    data = []
    for r in rows:
        d = dict(r)
        d["severity_cn"] = severity_cn(d["severity"])
        d["lifecycle_cn"] = lifecycle_cn(d.get("lifecycle"))
        data.append(d)
    return jsonify(code=0, data=data, count=total)


@bp.get("/api/report/detail")
def report_detail():
    rid = request.args.get("id")
    row = db.query_one("SELECT * FROM reports WHERE id=?", (rid,))
    if not row:
        return jsonify(code=1, msg="报告不存在")
    d = dict(row)
    d["lifecycle_cn"] = lifecycle_cn(d.get("lifecycle"))
    return jsonify(code=0, data=d)


def _norm_img_list(v):
    """检测过程 / 归属证明图片 → JSON 数组字符串（兼容数组、JSON 字符串、逗号/换行分隔），去重保序。"""
    if isinstance(v, list):
        items = [str(x).strip() for x in v if str(x).strip()]
    elif isinstance(v, str) and v.strip():
        s = v.strip()
        try:
            arr = _json.loads(s)
            items = [str(x).strip() for x in arr if str(x).strip()] if isinstance(arr, list) else []
        except Exception:
            items = [x.strip() for x in s.replace("\n", ",").split(",") if x.strip()]
    else:
        items = []
    seen, uniq = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            uniq.append(it)
    return _json.dumps(uniq, ensure_ascii=False) if uniq else ""


@bp.post("/api/report/add")
def report_add():
    data = request.get_json(silent=True) or {}
    unit_name = (data.get("unit_name") or "").strip()
    vul_name = (data.get("vul_name") or "").strip()
    if not unit_name or not vul_name:
        return jsonify(code=1, msg="单位名称与漏洞名称不能为空")

    # 同步写入漏洞库（若不存在）
    if data.get("sync_vuln", True) and vul_name:
        existing = db.query_one("SELECT id FROM vulnerabilities WHERE name=?", (vul_name,))
        if not existing:
            db.execute(
                """INSERT INTO vulnerabilities(name, description, harm, suggestion, severity, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (vul_name, data.get("description", ""), data.get("harm", ""),
                 data.get("suggestion", ""), data.get("severity", "unknown"),
                 now_display(), now_display()))

    detail_images = _norm_img_list(data.get("detail_images"))
    prove_images = _norm_img_list(data.get("prove_images"))
    rid = db.execute(
        """INSERT INTO reports(record_id, unit_name, vul_name, system_name, domain, address,
           description, severity, harm, detail, suggestion, prove, detail_images, prove_images,
           status, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)""",
        (gen_record_id(), unit_name, vul_name, data.get("system_name", ""), data.get("domain", ""),
         data.get("address", ""), data.get("description", ""), data.get("severity", "unknown"),
         data.get("harm", ""), data.get("detail", ""), data.get("suggestion", ""),
         data.get("prove", ""), detail_images, prove_images, now_display(), now_display()))

    # 新增报告 → 自动联动单位库 / 域名库（失败不影响报告保存）
    msg = "新增成功"
    try:
        res = sync_unit_and_domain(unit_name, data.get("domain", ""), data.get("address", ""))
        host = res.get("host") or ""
        if not (data.get("domain", "") or "").strip() and host:
            db.execute("UPDATE reports SET domain=? WHERE id=?", (host, rid))
        tips = []
        if res.get("unit_created"):
            tips.append(f"已自动登记新单位「{unit_name}」")
        if host:
            tips.append(f"已自动登记新域名「{host}」" if res.get("domain_created")
                        else f"域名「{host}」已在资产库")
        if tips:
            msg += "，" + "，".join(tips)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("资产联动失败: %s", e)
        msg = "新增成功（资产自动登记异常，请稍后在资产页核对）"
    return jsonify(code=0, msg=msg, id=rid)


@bp.get("/api/report/unit-assets")
def report_unit_assets():
    """同单位再次写报告时，返回其历史域名/系统/地址，前端据此自动匹配，免重复录入。"""
    name = (request.args.get("unit_name") or "").strip()
    if not name:
        return jsonify(code=0, data={"domains": [], "systems": [], "addresses": []})
    domains = [r["domain"] for r in db.query_all(
        "SELECT DISTINCT domain FROM domains WHERE is_deleted=0 AND unit_name=? AND domain<>'' ORDER BY id",
        (name,))]
    rows = db.query_all(
        "SELECT DISTINCT system_name, domain, address FROM reports WHERE unit_name=? "
        "ORDER BY id DESC LIMIT 50", (name,))
    systems, rep_domains, addresses = set(), set(), set()
    for r in rows:
        if (r["system_name"] or "").strip():
            systems.add(r["system_name"].strip())
        if (r["domain"] or "").strip():
            rep_domains.add(r["domain"].strip())
        for line in (r["address"] or "").splitlines():
            line = line.strip()
            if line:
                addresses.add(line)
    for d in rep_domains:
        if d not in domains:
            domains.append(d)
    return jsonify(code=0, data={
        "domains": domains,
        "systems": sorted(systems),
        "addresses": sorted(addresses),
    })


@bp.post("/api/report/update")
def report_update():
    data = request.get_json(silent=True) or {}
    rid = data.get("id")
    if not rid:
        return jsonify(code=1, msg="缺少报告 ID")
    fields = ["unit_name", "vul_name", "system_name", "domain", "address", "description",
              "severity", "harm", "detail", "suggestion", "prove"]
    sets, params = [], []
    for f in fields:
        if f in data and data[f] is not None:
            sets.append(f"{f}=?")
            params.append(data[f])
    # 独立图片字段：规范化为 JSON 数组
    for imgf in ("detail_images", "prove_images"):
        if imgf in data:
            sets.append(f"{imgf}=?")
            params.append(_norm_img_list(data[imgf]))
    if not sets:
        return jsonify(code=1, msg="没有可更新的字段")
    params.append(now_display())
    params.append(rid)
    db.execute(f"UPDATE reports SET {','.join(sets)}, updated_at=? WHERE id=?", (*params,))
    # 编辑后同样联动单位 / 域名资产
    msg = "更新成功"
    try:
        row = db.query_one("SELECT unit_name, domain, address FROM reports WHERE id=?", (rid,))
        if row:
            dom = data.get("domain", row["domain"] or "")
            addr = data.get("address", row["address"] or "")
            res = sync_unit_and_domain(row["unit_name"] or "", dom, addr)
            if not (dom or "").strip() and res.get("host"):
                db.execute("UPDATE reports SET domain=? WHERE id=?", (res["host"], rid))
            tips = []
            if res.get("unit_created"):
                tips.append(f"已自动登记新单位「{row['unit_name']}」")
            if res.get("host"):
                tips.append(f"已自动登记新域名「{res['host']}」" if res.get("domain_created")
                            else f"域名「{res['host']}」已在资产库")
            if tips:
                msg += "，" + "，".join(tips)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("资产联动失败: %s", e)
        msg = "更新成功（资产自动登记异常，请稍后在资产页核对）"
    return jsonify(code=0, msg=msg)


@bp.post("/api/report/lifecycle")
def report_lifecycle():
    """漏洞处置闭环：按 open->fixing->fixed->verified 合法路径流转，记录操作备注与时间。"""
    data = request.get_json(silent=True) or {}
    rid = data.get("id")
    target = (data.get("lifecycle") or "").strip()
    remark = (data.get("remark") or "").strip()
    if not rid:
        return jsonify(code=1, msg="缺少报告 ID")
    if target not in LIFECYCLE_CN:
        return jsonify(code=1, msg="非法的处置状态")
    row = db.query_one("SELECT lifecycle FROM reports WHERE id=?", (rid,))
    if not row:
        return jsonify(code=1, msg="报告不存在")
    cur_state = row["lifecycle"] or "open"
    if cur_state == target:
        return jsonify(code=1, msg=f"当前已是「{lifecycle_cn(target)}」状态")
    if not lifecycle_can_move(cur_state, target):
        return jsonify(code=1,
                       msg=f"不能从「{lifecycle_cn(cur_state)}」直接变更为「{lifecycle_cn(target)}」，请按整改流程操作")
    ts = now_display()
    action = LIFECYCLE_ACTION.get((cur_state, target), "状态变更")
    log = remark.strip()
    full_remark = f"[{ts}] {action}" + (f"：{log}" if log else "")
    # 备注追加式保留处置轨迹
    old = db.query_one("SELECT lifecycle_remark FROM reports WHERE id=?", (rid,))
    prev = (old["lifecycle_remark"] or "").strip() if old else ""
    merged = (prev + "\n" + full_remark).strip() if prev else full_remark
    db.execute(
        "UPDATE reports SET lifecycle=?, lifecycle_remark=?, lifecycle_at=?, updated_at=? WHERE id=?",
        (target, merged, ts, ts, rid))
    return jsonify(code=0, msg=f"已{action}", data={
        "lifecycle": target, "lifecycle_cn": lifecycle_cn(target),
        "lifecycle_at": ts, "lifecycle_remark": merged})


@bp.post("/api/report/delete")
def report_delete():
    data = request.get_json(silent=True) or {}
    rid = data.get("id")
    db.execute("DELETE FROM reports WHERE id=?", (rid,))
    return jsonify(code=0, msg="删除成功")


# ---------------- 辅助查询 ----------------
@bp.get("/api/unit/search")
def unit_search():
    q = request.args.get("q", "").strip()
    rows = db.query_all("SELECT id, enterprise_name FROM units WHERE enterprise_name LIKE ? LIMIT 10",
                        (f"%{q}%",))
    return jsonify(code=0, data=[dict(r) for r in rows])


@bp.get("/api/vulnerability/search")
def vuln_search():
    q = request.args.get("q", "").strip()
    rows = db.query_all(
        "SELECT id, name, severity, description, harm, suggestion FROM vulnerabilities WHERE name LIKE ? LIMIT 10",
        (f"%{q}%",))
    return jsonify(code=0, data=[dict(r) for r in rows])


@bp.get("/api/unit/by-domain")
def unit_by_domain():
    dom = request.args.get("domain", "").strip()
    row = db.query_one("SELECT id, unit_name FROM domains WHERE domain=? AND is_deleted=0", (dom,))
    if row:
        return jsonify(code=0, data={"id": row["id"], "unitName": row["unit_name"]})
    return jsonify(code=0, data=None)


@bp.get("/api/report/latest-prove")
def latest_prove():
    dom = request.args.get("domain", "").strip()
    row = db.query_one(
        "SELECT prove, prove_images FROM reports WHERE domain=? "
        "AND (prove!='' OR IFNULL(prove_images,'')!='') ORDER BY id DESC LIMIT 1",
        (dom,))
    if row:
        imgs = []
        raw = row["prove_images"] if "prove_images" in row.keys() else ""
        if raw:
            try:
                v = _json.loads(raw)
                imgs = v if isinstance(v, list) else [x.strip() for x in str(raw).replace("\n", ",").split(",") if x.strip()]
            except Exception:
                imgs = [x.strip() for x in str(raw).replace("\n", ",").split(",") if x.strip()]
        return jsonify(code=0, data={"prove": row["prove"] or "", "prove_images": imgs})
    return jsonify(code=1, msg="未找到该域名的历史记录")


@bp.post("/api/report/auto-attrib")
def auto_attrib():
    """根据域名 / 漏洞地址自动做归属取证：返回归属说明文字 + 归属证明图片URL。"""
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    address = (data.get("address") or "").strip()
    target = domain or address
    if not target:
        return jsonify(code=1, msg="请先填写域名或漏洞地址")
    try:
        from core.attrib import fetch_attribution
        res = fetch_attribution(target)
    except Exception as e:
        return jsonify(code=1, msg="自动取证失败：%s" % str(e)[:120])
    if not res.get("ok"):
        return jsonify(code=1, msg=res.get("error") or "未能获取归属信息，请手动补充截图", data=res)
    return jsonify(code=0, msg="已自动完成归属取证", data=res)


# ---------------- 图片上传（富文本） ----------------
@bp.post("/api/upload/image")
def upload_image():
    f = request.files.get("file")
    if not f:
        return jsonify(code=1, msg="未选择文件")
    ext = os.path.splitext(f.filename or "")[1].lower()
    if ext not in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"):
        return jsonify(code=1, msg="不支持的图片格式")
    date_dir = now_ts()[:8]
    save_dir = os.path.join(str(UPLOAD_DIR), date_dir)
    os.makedirs(save_dir, exist_ok=True)
    filename = f"{uuid.uuid4().hex}{ext}"
    f.save(os.path.join(save_dir, filename))
    url = f"/uploads/{date_dir}/{filename}"
    return jsonify(code=0, msg="上传成功", data={"location": url, "title": f.filename})


# ---------------- 模板管理 ----------------
@bp.get("/api/report/templates")
def template_list():
    rows = db.query_all("SELECT * FROM templates ORDER BY is_default DESC, id DESC")
    data = []
    for t in rows:
        path = os.path.join(str(TEMPLATE_DIR), t["filename"])
        d = dict(t)
        d["exists"] = os.path.exists(path)
        d["placeholders"] = extract_placeholders(path) if d["exists"] else []
        data.append(d)
    return jsonify(code=0, data=data)


@bp.post("/api/report/template/upload")
def template_upload():
    name = (request.form.get("name") or "").strip()
    f = request.files.get("file")
    if not name or not f:
        return jsonify(code=1, msg="模板名称和文件不能为空")
    if not f.filename.endswith(".docx"):
        return jsonify(code=1, msg="仅支持 .docx 模板文件")
    if db.query_one("SELECT id FROM templates WHERE name=?", (name,)):
        return jsonify(code=1, msg="模板名称已存在")
    filename = f"{uuid.uuid4().hex}.docx"
    save_path = os.path.join(str(TEMPLATE_DIR), filename)
    f.save(save_path)
    placeholders = extract_placeholders(save_path)
    is_default = 1 if not db.query_one("SELECT id FROM templates") else 0
    tid = db.execute("INSERT INTO templates(name, filename, is_default, created_at) VALUES(?,?,?,?)",
                     (name, filename, is_default, now_display()))
    return jsonify(code=0, msg="上传成功", id=tid, placeholders=placeholders)


def _safe_token(token: str) -> bool:
    return bool(token) and len(token) <= 64 and all(c in "0123456789abcdef" for c in token.lower())


@bp.post("/api/report/template/extract-preview")
def template_extract_preview():
    """上传一份成品漏洞报告 docx，解析段落并按规则预猜字段映射（不入库）。"""
    f = request.files.get("file")
    if not f or not (f.filename or "").lower().endswith(".docx"):
        return jsonify(code=1, msg="请选择 .docx 成品报告"), 400
    src_dir = os.path.join(str(TEMPLATE_DIR), "_src")
    os.makedirs(src_dir, exist_ok=True)
    token = uuid.uuid4().hex
    src_path = os.path.join(src_dir, token + ".docx")
    f.save(src_path)
    try:
        parsed = tpl_extract.parse_report_docx(src_path)
    except Exception as e:
        try:
            os.remove(src_path)
        except OSError:
            pass
        return jsonify(code=1, msg=f"解析失败（请确认是有效的 Word 报告）：{e}"), 400
    paras_out = []
    for p in parsed["paragraphs"]:
        text = p["text"] or ("［图片］" if p["has_image"] else "")
        paras_out.append({
            "idx": p["idx"],
            "text": text[:120],
            "heading": bool(p["heading"]),
            "has_image": bool(p["has_image"]),
            "suggest": p["suggest"],
        })
    return jsonify(code=0, data={
        "token": token,
        "paragraphs": paras_out,
        "mapping": {str(k): v for k, v in parsed["mapping"].items()},
        "fields": [{"key": k, "name": cn} for k, cn in tpl_extract.FIELDS],
        "title_key": tpl_extract.TITLE_KEY,
    })


@bp.post("/api/report/template/build-from-doc")
def template_build_from_doc():
    """根据用户确认的段落→字段映射，从成品报告生成可复用模板并入库。"""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    name = (data.get("name") or "").strip()
    mapping = data.get("mapping") or {}
    if not token or not name:
        return jsonify(code=1, msg="缺少模板名称或解析凭据"), 400
    if not _safe_token(token):
        return jsonify(code=1, msg="非法凭据"), 400
    if db.query_one("SELECT id FROM templates WHERE name=?", (name,)):
        return jsonify(code=1, msg="模板名称已存在，请换一个"), 400
    src_path = os.path.join(str(TEMPLATE_DIR), "_src", token + ".docx")
    if not os.path.exists(src_path):
        return jsonify(code=1, msg="源文件已失效，请重新导入"), 400
    clean = {}
    for k, v in mapping.items():
        if v == tpl_extract.TITLE_KEY or v in tpl_extract.FIELD_CN:
            clean[k] = v
    filename = f"{uuid.uuid4().hex}.docx"
    dst_path = os.path.join(str(TEMPLATE_DIR), filename)
    try:
        tpl_extract.build_template_from_doc(src_path, clean, dst_path)
    except Exception as e:
        return jsonify(code=1, msg=f"生成模板失败：{e}"), 500
    finally:
        try:
            os.remove(src_path)
        except OSError:
            pass
    placeholders = extract_placeholders(dst_path)
    is_default = 1 if not db.query_one("SELECT id FROM templates") else 0
    tid = db.execute("INSERT INTO templates(name, filename, is_default, created_at) VALUES(?,?,?,?)",
                     (name, filename, is_default, now_display()))
    return jsonify(code=0, msg="已从成品报告生成模板", id=tid, placeholders=placeholders)


@bp.post("/api/report/template/set-default")
def template_set_default():
    data = request.get_json(silent=True) or {}
    tid = data.get("id")
    db.execute("UPDATE templates SET is_default=0")
    db.execute("UPDATE templates SET is_default=1 WHERE id=?", (tid,))
    return jsonify(code=0, msg="已设为默认模板")


@bp.post("/api/report/template/delete")
def template_delete():
    data = request.get_json(silent=True) or {}
    tid = data.get("id")
    t = db.query_one("SELECT * FROM templates WHERE id=?", (tid,))
    if t:
        db.execute("DELETE FROM templates WHERE id=?", (tid,))
        path = os.path.join(str(TEMPLATE_DIR), t["filename"])
        if os.path.exists(path):
            os.remove(path)
    return jsonify(code=0, msg="删除成功")


@bp.get("/api/report/template/download")
def template_download():
    tid = request.args.get("id")
    t = db.query_one("SELECT * FROM templates WHERE id=?", (tid,))
    if not t:
        return jsonify(code=1, msg="模板不存在")
    path = os.path.join(str(TEMPLATE_DIR), t["filename"])
    if not os.path.exists(path):
        return jsonify(code=1, msg="模板文件缺失")
    return send_file(path, as_attachment=True, download_name=sanitize_filename(t["name"]) + ".docx")


# ---------------- 报告导出 ----------------
@bp.post("/api/report/export")
def report_export():
    data = request.get_json(silent=True) or {}
    report_ids = data.get("report_ids", [])
    template_key = data.get("template_key", "normal")
    template_id = data.get("template_id", "")
    org_footer = data.get("org_footer", "")
    if not report_ids:
        return jsonify(code=1, msg="未选择任何报告"), 400
    records = [dict(r) for r in db.query_all(
        f"SELECT * FROM reports WHERE id IN ({','.join('?' * len(report_ids))})", report_ids)]
    if not records:
        return jsonify(code=1, msg="未找到指定报告"), 404
    if template_key not in ("normal", "gongwen", "summary", "custom"):
        return jsonify(code=1, msg="不支持的导出模板类型"), 400
    # 公文模板为单条隐患通报，仅支持单条导出
    if template_key == "gongwen" and len(records) != 1:
        return jsonify(code=1, msg="公文模板仅支持单条报告导出，请只选择一条"), 400

    custom_path = None
    if template_key == "custom":
        if template_id:
            t = db.query_one("SELECT * FROM templates WHERE id=?", (template_id,))
            if t:
                custom_path = os.path.join(str(TEMPLATE_DIR), t["filename"])
        if not custom_path:
            # 回退默认自定义模板
            t = db.query_one("SELECT * FROM templates WHERE is_default=1")
            if t:
                custom_path = os.path.join(str(TEMPLATE_DIR), t["filename"])
        if not custom_path:
            return jsonify(code=1, msg="未找到可用的自定义模板，请先在模板管理中上传"), 400
        if not os.path.exists(custom_path):
            return jsonify(code=1, msg="自定义模板文件缺失"), 500

    try:
        filename = exporter.export_records_to_docx(records, template_key=template_key,
                                                   custom_template_path=custom_path,
                                                   org_footer=org_footer)
    except Exception as e:
        return jsonify(code=1, msg=f"导出失败：{e}"), 500
    return jsonify(code=0, msg="生成成功", filename=filename,
                   url=f"/api/report/download/{filename}")


@bp.get("/api/report/download/<path:filename>")
def report_download(filename):
    safe = os.path.basename(filename)
    path = os.path.join(str(EXPORT_DIR), safe)
    if not os.path.exists(path):
        return jsonify(code=1, msg="文件不存在"), 404
    return send_file(path, as_attachment=True, download_name=safe)


@bp.get("/api/report/exports")
def export_history():
    files = exporter.list_exported_files()
    return jsonify(code=0, data=files)


# ---------------- PDF 导出 ----------------
@bp.post("/api/report/export-pdf")
def report_export_pdf():
    from core import pdf_export
    data = request.get_json(silent=True) or {}
    report_ids = data.get("report_ids", [])
    template_key = data.get("template_key", "normal")
    org_footer = data.get("org_footer", "")
    if not report_ids:
        return jsonify(code=1, msg="未选择任何报告"), 400
    # 公文模板只支持单条
    if template_key == "gongwen" and len(report_ids) != 1:
        return jsonify(code=1, msg="公文模板仅支持单条报告导出，请只选择一条"), 400
    records = [dict(r) for r in db.query_all(
        f"SELECT * FROM reports WHERE id IN ({','.join('?' * len(report_ids))})", report_ids)]
    if not records:
        return jsonify(code=1, msg="未找到指定报告"), 404
    try:
        filename = pdf_export.export_records_to_pdf(records, template_key=template_key,
                                                    org_footer=org_footer)
    except Exception as e:
        return jsonify(code=1, msg=f"PDF 导出失败：{e}"), 500
    return jsonify(code=0, msg="PDF 生成成功", filename=filename,
                   url=f"/api/report/download/{filename}")


# ---------------- 报告质量体检 ----------------
@bp.get("/api/report/qa")
def report_qa_all():
    from core import qa
    return jsonify(code=0, data=qa.check_all_reports())


@bp.get("/api/report/qa-one")
def report_qa_one():
    from core import qa
    rid = request.args.get("id")
    row = db.query_one("SELECT * FROM reports WHERE id=?", (rid,))
    if not row:
        return jsonify(code=1, msg="报告不存在"), 404
    return jsonify(code=0, data=qa.check_report(dict(row)))
