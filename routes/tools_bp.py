# -*- coding: utf-8 -*-
"""工具管理路由"""
from flask import Blueprint, request, jsonify, render_template

from core import tools as T

bp = Blueprint("tools", __name__)


@bp.get("/tools/password")
def password_page():
    return render_template("tools/password.html")


@bp.get("/tools/dedup")
def dedup_page():
    return render_template("tools/dedup.html")


@bp.get("/tools/urls")
def urls_page():
    return render_template("tools/urls.html")


@bp.get("/tools/compare")
def compare_page():
    return render_template("tools/compare.html")


@bp.get("/tools/classify")
def classify_page():
    return render_template("tools/classify.html")


@bp.get("/tools/cvss")
def cvss_page():
    return render_template("tools/cvss.html")


# ---------------- API ----------------
@bp.post("/api/tools/password")
def api_password():
    data = request.get_json(silent=True) or {}
    try:
        length = max(1, min(128, int(data.get("length", 12))))
        count = max(1, min(100, int(data.get("count", 1))))
        pws = T.generate_batch_passwords(
            count, length=length,
            use_upper=bool(data.get("uppercase", True)),
            use_lower=bool(data.get("lowercase", True)),
            use_numbers=bool(data.get("numbers", True)),
            use_special=bool(data.get("special", True)))
        return jsonify(code=0, data=pws)
    except Exception as e:
        return jsonify(code=1, msg=str(e))


@bp.post("/api/tools/dedup")
def api_dedup():
    data = request.get_json(silent=True) or {}
    lines = T.dedup_lines(data.get("text", ""),
                          keep_order=bool(data.get("keep_order", True)),
                          case_insensitive=bool(data.get("case_insensitive", False)))
    return jsonify(code=0, data="\n".join(lines), count=len(lines))


@bp.post("/api/tools/urls")
def api_urls():
    data = request.get_json(silent=True) or {}
    results = T.process_url_text(data.get("text", ""))
    return jsonify(code=0, data=results)


@bp.post("/api/tools/compare")
def api_compare():
    data = request.get_json(silent=True) or {}
    result = T.align_columns(data.get("a", ""), data.get("b", ""))
    return jsonify(code=0, data=result)


@bp.post("/api/tools/classify")
def api_classify():
    data = request.get_json(silent=True) or {}
    result = T.classify_assets(data.get("text", ""))
    return jsonify(code=0, data=result)


@bp.post("/api/tools/cvss")
def api_cvss():
    from core import cvss as cvss_mod
    data = request.get_json(silent=True) or {}
    vector = data.get("vector", "")
    try:
        result = cvss_mod.calculate(vector)
    except ValueError as e:
        return jsonify(code=1, msg=str(e))
    except Exception as e:
        return jsonify(code=1, msg=f"计算失败：{e}")
    return jsonify(code=0, data=result)
