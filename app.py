# -*- coding: utf-8 -*-
"""
智安鉴 · 智能安全检测与漏洞报告系统 —— 应用入口
================================================
运行方式：
    py -3.10 app.py
    浏览器访问 http://127.0.0.1:8080

功能模块：
    仪表盘 / 单位管理 / 标签管理 / 域名资产 / 漏洞库 / 报告管理 /
    AI 智能生成 / AI 漏洞扫描 / 工具管理 / 系统设置 / 用户管理

访问控制：除登录页与静态资源外，所有页面与接口都需要登录；
「用户管理」仅管理员可见可用（详见 core/auth.py）。
"""
import os
import secrets
import sqlite3
from datetime import timedelta
from urllib.parse import quote

from flask import (Flask, render_template, jsonify, request, session,
                   send_from_directory, abort, redirect)

import database as db
from config import (get_cfg, get_secret_key, DATA_DIR, UPLOAD_DIR, AI_IMAGE_DIR, VERSION)
from core import auth

# 注册蓝图
from routes.units_bp import bp as units_bp
from routes.domains_bp import bp as domains_bp
from routes.vulns_bp import bp as vulns_bp
from routes.reports_bp import bp as reports_bp
from routes.ai_bp import bp as ai_bp
from routes.tools_bp import bp as tools_bp
from routes.settings_bp import bp as settings_bp
from routes.scanner_bp import bp as scanner_bp
from routes.users_bp import bp as users_bp


def create_app():
    app = Flask(__name__)
    # 会话签名密钥持久化在 config.json，重建容器不会让已登录用户掉线
    app.secret_key = get_secret_key()
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB
    app.config["JSON_AS_ASCII"] = False

    db.init_db()

    # 内置标准报告模板（与原工具一致的占位符模板）幂等登记并设为默认
    from core.tpl_bootstrap import ensure_builtin_templates
    ensure_builtin_templates()

    # 首次启动创建内置管理员账号
    admin_info = db.ensure_default_admin()
    if admin_info.get("created"):
        print("=" * 60)
        print("  已创建内置管理员账号：%s / %s" % (admin_info["username"], admin_info["password"]))
        print("  请登录后到「用户管理」或右上角头像处立即修改密码")
        print("=" * 60)

    # ---------------- 蓝图 ----------------
    app.register_blueprint(units_bp)
    app.register_blueprint(domains_bp)
    app.register_blueprint(vulns_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(users_bp)

    # ---------------- 登录校验 ----------------
    # 免登录：登录页本身、登录接口、CSRF 取号接口、静态资源
    PUBLIC_PATHS = {"/login", "/api/auth/login", "/api/csrf", "/favicon.ico"}
    PUBLIC_PREFIXES = ("/static/",)
    # 仅管理员：用户管理页面与接口
    ADMIN_PATHS = ("/users", "/api/users")

    @app.before_request
    def require_login():
        path = request.path
        if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
            return None
        user = auth.current_user()
        if not user:
            if path.startswith("/api/"):
                return jsonify(code=1, msg="登录已失效，请重新登录", need_login=True), 401
            return redirect("/login?next=" + quote(path, safe="/"))
        if path == ADMIN_PATHS[0] or path.startswith(ADMIN_PATHS[1]):
            if user["role"] != "admin":
                if path.startswith("/api/"):
                    return jsonify(code=1, msg="需要管理员权限"), 403
                return render_template("error.html", code=403, msg="需要管理员权限"), 403
        return None

    # ---------------- 轻量 CSRF 防护 ----------------
    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            # 文件上传接口允许（同源本地工具）
            if (request.path.startswith("/api/upload/")
                    or request.path.startswith("/api/settings/background")
                    or request.path == "/api/scanner/parse"):
                return None
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if token and token == session.get("_csrf"):
                return None
            # 首次进入系统后 session 未设置时放行（页面加载会先获取 token）
            if not session.get("_csrf"):
                return None
            return jsonify(code=1, msg="CSRF 校验失败，请刷新页面重试"), 403
        return None

    @app.get("/api/csrf")
    def csrf_token():
        if not session.get("_csrf"):
            session["_csrf"] = secrets.token_hex(16)
        return jsonify(code=0, token=session["_csrf"])

    # ---------------- 仪表盘 ----------------
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/dashboard")
    def dashboard():
        conn = db.get_db()
        cur = conn.cursor()
        stats = {
            "units": cur.execute("SELECT COUNT(*) FROM units").fetchone()[0],
            "domains": cur.execute("SELECT COUNT(*) FROM domains WHERE is_deleted=0").fetchone()[0],
            "vulns": cur.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
            "reports": cur.execute("SELECT COUNT(*) FROM reports WHERE status=0").fetchone()[0],
            "templates": cur.execute("SELECT COUNT(*) FROM templates").fetchone()[0],
        }
        severity_rows = cur.execute(
            "SELECT severity, COUNT(*) c FROM reports WHERE status=0 GROUP BY severity").fetchall()
        severity = {r["severity"]: r["c"] for r in severity_rows}
        recent = [dict(r) for r in cur.execute(
            "SELECT * FROM reports WHERE status=0 ORDER BY id DESC LIMIT 8").fetchall()]
        recent_units = [dict(r) for r in cur.execute(
            "SELECT enterprise_name, city, business_status FROM units ORDER BY id DESC LIMIT 5").fetchall()]
        # 近 6 个月报告趋势
        trend_rows = cur.execute(
            """SELECT strftime('%Y-%m', created_at) m, COUNT(*) c FROM reports
               WHERE status=0 AND created_at >= date('now','-6 month')
               GROUP BY m ORDER BY m""").fetchall()
        monthly_trend = [{"month": r["m"], "count": r["c"]} for r in trend_rows]
        # 报告数 TOP5 单位
        top_rows = cur.execute(
            """SELECT unit_name, COUNT(*) c FROM reports WHERE status=0
               GROUP BY unit_name ORDER BY c DESC LIMIT 5""").fetchall()
        top_units = [{"unit_name": r["unit_name"], "count": r["c"]} for r in top_rows]
        # 漏洞处置全生命周期统计（open/fixing/fixed/verified）
        lc_rows = cur.execute(
            "SELECT lifecycle, COUNT(*) c FROM reports WHERE status=0 GROUP BY lifecycle").fetchall()
        lifecycle = {"open": 0, "fixing": 0, "fixed": 0, "verified": 0}
        for r in lc_rows:
            lifecycle[r["lifecycle"] or "open"] = r["c"]
        total_rep = stats["reports"] or 0
        closed_rate = round(lifecycle["verified"] * 100.0 / total_rep, 1) if total_rep else 0.0
        handling_rate = round(
            (lifecycle["fixing"] + lifecycle["fixed"] + lifecycle["verified"]) * 100.0 / total_rep, 1
        ) if total_rep else 0.0
        cur.close()
        for r in recent:
            from core.helpers import severity_cn
            r["severity_cn"] = severity_cn(r["severity"])
        return jsonify(code=0, data={"stats": stats, "severity": severity,
                                     "recent": recent, "recent_units": recent_units,
                                     "monthly_trend": monthly_trend, "top_units": top_units,
                                     "lifecycle": lifecycle,
                                     "closed_rate": closed_rate,
                                     "handling_rate": handling_rate})

    # ---------------- 静态资源 ----------------
    @app.get("/uploads/<path:filename>")
    def uploaded_file(filename):
        return send_from_directory(str(UPLOAD_DIR), filename)

    @app.get("/media/ai_images/<path:filename>")
    def ai_images(filename):
        return send_from_directory(str(AI_IMAGE_DIR), filename)

    # ---------------- 模板上下文 ----------------
    def _active_nav(path: str) -> str:
        """按请求路径推断侧栏应高亮的项（与 templates/base.html 里的判断一致）"""
        path = path or "/"
        if path == "/":
            return "index"
        if path.startswith("/tools/"):
            return "tools-" + path.rstrip("/").rsplit("/", 1)[-1]
        if path.startswith("/reports/ai"):
            return "report_ai"
        return path.strip("/").split("/")[0]

    @app.context_processor
    def inject_globals():
        cfg = get_cfg()
        return {
            # 侧栏高亮：按当前路径推断（模板里用 active 变量）
            "active": _active_nav(request.path),
            # 当前登录用户（未登录为 None；模板里用 CURRENT_USER 控制入口与头像）
            "CURRENT_USER": auth.current_user(),
            "DEFAULT_PWD": bool(session.get("default_pwd")),
            "APP_NAME": "智安鉴",
            "APP_TITLE": cfg.get("app_title", "智能安全检测与漏洞报告系统"),
            "APP_SUBTITLE": cfg.get("app_subtitle", ""),
            "APP_VERSION": VERSION,
            "THEME_COLOR": cfg.get("theme_color", "#2563eb"),
            "BG_IMAGE": cfg.get("background", ""),
            "BG_OVERLAY": cfg.get("background_overlay", 0.35),
            "BG_BLUR": cfg.get("background_blur", 0),
            "CSRF_TOKEN": session.get("_csrf", ""),
        }

    # ---------------- 错误处理 ----------------
    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, msg="页面不存在"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500, msg="服务器内部错误"), 500

    @app.errorhandler(413)
    def too_large(e):
        return jsonify(code=1, msg="文件过大（限制 50MB）"), 413

    return app


app = create_app()


def _open_browser_when_ready(host="127.0.0.1", port=8080, path="/"):
    """等待本地端口真正监听后再打开默认浏览器，避免抢跑显示无法访问。"""
    import time
    import socket
    import webbrowser
    url = f"http://{host}:{port}{path}"
    for _ in range(40):  # 最多等待约 12 秒
        try:
            with socket.create_connection((host, port), timeout=0.3):
                break
        except OSError:
            time.sleep(0.3)
    webbrowser.open(url)


if __name__ == "__main__":
    _host = os.environ.get("ZS_HOST", "127.0.0.1")
    _port = int(os.environ.get("ZS_PORT", "8080"))
    print("=" * 60)
    print("  智安鉴 · 智能安全检测与漏洞报告系统  v" + VERSION)
    print(f"  浏览器访问:  http://{_host}:{_port}")
    print("  按 Ctrl+C 停止服务")
    print("=" * 60)
    # 启动后自动打开浏览器；设环境变量 ZS_NO_BROWSER=1 可关闭（自动化测试用）
    if not os.environ.get("ZS_NO_BROWSER"):
        import threading
        threading.Thread(target=_open_browser_when_ready,
                         args=(_host, _port, "/"), daemon=True).start()
    app.run(host=_host, port=_port, debug=False, threaded=True)
