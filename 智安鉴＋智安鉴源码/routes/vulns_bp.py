# -*- coding: utf-8 -*-
"""漏洞知识库路由"""
from flask import Blueprint, request, jsonify

import database as db
from config import get_cfg
from core.ai_engine import get_ai_engine, mock_translate_segments
from core.helpers import now_display
import re

from core.vuln_translate import to_chinese

_LATIN = re.compile(r"[A-Za-z]")
_CJK = re.compile(r"[\u4e00-\u9fff]")

bp = Blueprint("vulns", __name__)


def _needs_zh(text) -> bool:
    """判断字段是否需要翻译成中文。

    不能只看「有没有中文」：扫描引擎会把 AI 分析/整改建议拼进描述，
    形成「英文正文 + 中文标签」的混合内容，这类也要翻译。
    规则：英文字母不少于 12 个，且英文字母数 ≥ 中文字符数的 2 倍。
    """
    value = (text or "").strip()
    if not value:
        return False
    letters = len(_LATIN.findall(value))
    cjk = len(_CJK.findall(value))
    if letters < 20:
        return False
    if cjk == 0:
        return True
    # 混合内容：扫描引擎会把中文的「AI 分析/整改建议」拼在英文正文后面，
    # 只要第一段仍以英文为主，就值得翻译（AI 会保留已有中文）
    first = re.split(r"\n\s*\n", value)[0]
    first_letters = len(_LATIN.findall(first))
    first_cjk = len(_CJK.findall(first))
    return first_letters >= 20 and first_cjk * 4 < first_letters


_FIELDS = ("description", "harm", "suggestion")


def _split_paragraphs(text) -> list:
    """按空行拆分段落，去掉空段。"""
    return [p.strip() for p in re.split(r"\n\s*\n", text or "") if p.strip()]


def _row_needs_translation(row) -> bool:
    return any(_needs_zh(row[k]) for k in ("description", "harm", "suggestion"))


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
    data = []
    for r in rows:
        d = dict(r)
        d["needs_translation"] = _row_needs_translation(d)
        data.append(d)
    return jsonify(code=0, data=data, count=total)


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
    # 英文名称自动翻译为中文入库，英文原名记在 name_en
    zh = to_chinese(name)
    if db.query_one("SELECT id FROM vulnerabilities WHERE name=? OR name_en=?", (zh, name)):
        return jsonify(code=1, msg=f"漏洞「{zh}」已存在，可直接编辑")
    vid = db.execute(
        """INSERT INTO vulnerabilities(name, name_en, description, harm, suggestion, severity, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (zh, name if zh != name else "", data.get("description", ""), data.get("harm", ""),
         data.get("suggestion", ""), data.get("severity", "unknown"), now_display(), now_display()))
    return jsonify(code=0, msg="新增成功" + (f"（已翻译为「{zh}」）" if zh != name else ""),
                   id=vid, name=zh)


@bp.post("/api/vulnerabilities/translate")
def vuln_translate_all():
    """把漏洞库里仍是英文的名称批量翻译为中文（幂等，已中文的跳过）。"""
    rows = db.query_all(
        "SELECT id, name, IFNULL(name_en,'') AS name_en FROM vulnerabilities ORDER BY id")
    changed, skipped = [], 0
    for r in rows:
        original = (r["name_en"] or "").strip() or (r["name"] or "").strip()
        zh = to_chinese(original)
        if zh and zh != r["name"]:
            db.execute("UPDATE vulnerabilities SET name=?, name_en=?, updated_at=? WHERE id=?",
                       (zh, original, now_display(), r["id"]))
            changed.append({"id": r["id"], "from": r["name"], "to": zh})
        else:
            # 已是中文但缺英文原名时补记一次，便于后续与扫描结果匹配
            if original != r["name"] and not (r["name_en"] or "").strip():
                db.execute("UPDATE vulnerabilities SET name_en=? WHERE id=?", (original, r["id"]))
            skipped += 1
    return jsonify(code=0,
                   msg=f"已翻译 {len(changed)} 条，跳过 {skipped} 条（已是中文或无法识别）",
                   data={"changed": changed, "updated": len(changed), "skipped": skipped})


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
            value = data[f]
            if f == "name":
                value = (value or "").strip()
                if not value:
                    return jsonify(code=1, msg="漏洞名称不能为空")
                zh = to_chinese(value)
                # 英文名同样自动翻译，并把英文原名留在 name_en
                if zh != value:
                    sets.append("name_en=?")
                    params.append(value)
                    value = zh
            sets.append(f"{f}=?")
            params.append(value)
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


@bp.post("/api/vulnerabilities/ai-translate")
def vuln_ai_translate():
    """用 AI 把英文的漏洞描述/危害/整改建议翻译成中文。

    传 id 翻译单条；不传 id 时按「仍含英文」的条件批量处理（最多 20 条/次）。
    按段落翻译：扫描引擎拼进来的中文「AI 分析/整改建议」原样保留，不会被整段重写。
    """
    data = request.get_json(silent=True) or {}
    try:
        limit = max(1, min(int(data.get("limit") or 10), 20))
    except (TypeError, ValueError):
        limit = 10
    vid = data.get("id")

    if vid:
        row = db.query_one("SELECT * FROM vulnerabilities WHERE id=?", (vid,))
        if not row:
            return jsonify(code=1, msg="漏洞记录不存在"), 404
        rows = [row]
    else:
        rows = [r for r in db.query_all("SELECT * FROM vulnerabilities ORDER BY id")
                if _row_needs_translation(r)][:limit]
        if not rows:
            return jsonify(code=0, msg="没有需要翻译的英文内容", data={"updated": [], "failed": []})

    cfg = get_cfg().get("ai", {})
    api_key = (cfg.get("api_key") or "").strip()
    if not api_key:
        return jsonify(code=1, msg="未配置 AI 接口，请先在「系统设置 → AI 接口配置」里填写 API Key"), 400
    base_url = (cfg.get("base_url") or "").strip() or "https://api.stepfun.com/v1"
    model = (cfg.get("model") or "").strip()
    timeout = cfg.get("timeout") or 120
    engine = get_ai_engine(api_key, base_url, model, timeout)

    updated, failed = [], []
    for r in rows:
        parts = {f: _split_paragraphs(r[f]) for f in _FIELDS}
        jobs = [(f, i, p) for f in _FIELDS for i, p in enumerate(parts[f]) if _needs_zh(p)]
        if not jobs:
            continue
        try:
            if api_key == "sk-test-mock":
                translated = mock_translate_segments(len(jobs))
            else:
                translated = engine.translate_segments([j[2] for j in jobs])
            if len(translated) != len(jobs):
                failed.append({"id": r["id"], "msg": "AI 返回的段落数与输入不一致，已跳过"})
                continue
            for (field, idx, _), zh in zip(jobs, translated):
                parts[field][idx] = zh
            sets, params = [], []
            for field in _FIELDS:
                if not parts[field]:
                    continue
                new_value = "\n\n".join(parts[field])
                if new_value != (r[field] or "").strip():
                    sets.append(f"{field}=?")
                    params.append(new_value)
            if not sets:
                failed.append({"id": r["id"], "msg": "AI 未返回可用的中文内容"})
                continue
            params.extend([now_display(), r["id"]])
            db.execute(f"UPDATE vulnerabilities SET {','.join(sets)}, updated_at=? WHERE id=?", tuple(params))
            updated.append(r["id"])
        except Exception as e:
            failed.append({"id": r["id"], "msg": str(e)[:160]})

    msg = f"AI 翻译完成：{len(updated)} 条"
    if failed:
        msg += f"，{len(failed)} 条失败"
    return jsonify(code=0, msg=msg, data={"updated": updated, "failed": failed})
