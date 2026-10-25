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
from datetime import timedelta
from urllib.parse import quote

from flask import (Flask, jsonify, request, session,
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

    # ---------------- 前端（React SPA） ----------------
    # 构建产物在 static/app/（frontend/ 目录 npm run build 生成）。
    # 所有页面路径统一返回 SPA 外壳，由前端路由渲染；/api、/static、/uploads、/media 仍走 Flask。
    SPA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "app")
    SPA_INDEX = os.path.join(SPA_DIR, "index.html")

    @app.before_request
    def serve_spa():
        if request.method != "GET":
            return None
        path = request.path
        if path.startswith(("/api/", "/static/", "/uploads/", "/media/")) or path == "/favicon.ico":
            return None
        if not os.path.exists(SPA_INDEX):
            return (
                "<!doctype html><meta charset='utf-8'><title>前端未构建</title>"
                "<div style='font:14px/1.8 system-ui;padding:48px;max-width:640px;margin:0 auto'>"
                "<h2>前端资源未构建</h2>"
                "<p>请在 <code>frontend/</code> 目录执行：</p>"
                "<pre style='background:#f6f7f9;padding:12px;border-radius:6px'>npm install\nnpm run build</pre>"
                "<p>构建完成后刷新本页。</p>"
                "</div>",
                503,
                {"Content-Type": "text/html; charset=utf-8"},
            )
        # 页面级访问控制仍由服务端兜底（接口侧另有一层），前端路由再按角色兜一层：
        # 未登录整页跳登录页，管理员专属页面直接回 403（页面内也会渲染无权限提示）
        user = auth.current_user()
        if path == "/login":
            if user:
                return redirect("/")
        elif not user:
            return redirect("/login?next=" + quote(path, safe="/"))
        resp = send_from_directory(SPA_DIR, "index.html")
        if path == "/users" and user and user["role"] != "admin":
            resp.status_code = 403
        return resp

    # ---------------- 登录校验 ----------------
    # 免登录：登录页本身、登录接口、CSRF 取号接口、前端启动配置、静态资源
    PUBLIC_PATHS = {"/login", "/api/auth/login", "/api/csrf", "/api/app/bootstrap", "/favicon.ico"}
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
        if path.startswith(ADMIN_PATHS[1]) and user["role"] != "admin":
            return jsonify(code=1, msg="需要管理员权限"), 403
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

    # ---------------- 前端启动配置 ----------------
    @app.get("/api/app/bootstrap")
    def app_bootstrap():
        """SPA 首屏配置：品牌信息、主题、背景与当前登录用户（未登录时 user=None）。"""
        cfg = get_cfg()
        user = auth.current_user()
        default_pwd = bool(session.get("default_pwd"))
        return jsonify(code=0, data={
            "app_name": "智安鉴",
            "app_title": cfg.get("app_title", "智能安全检测与漏洞报告系统"),
            "app_subtitle": cfg.get("app_subtitle", ""),
            "app_version": VERSION,
            "theme_color": cfg.get("theme_color", "#2563eb"),
            "background": cfg.get("background", ""),
            "background_overlay": cfg.get("background_overlay", 0.35),
            "background_blur": cfg.get("background_blur", 0),
            "default_pwd": default_pwd,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "display_name": user["display_name"],
                "role": user["role"],
                "role_cn": "管理员" if user["role"] == "admin" else "普通用户",
                "last_login_at": user["last_login_at"],
                "default_pwd": default_pwd,
            } if user else None,
        })

    # ---------------- 仪表盘 ----------------
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
            """SELECT SUBSTRING(created_at, 1, 7) AS m, COUNT(*) AS c FROM reports
               WHERE status=0
                 AND created_at >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 6 MONTH), '%Y-%m-%d')
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

    # ---------------- 错误处理 ----------------
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify(code=1, msg="接口不存在"), 404
        return "页面不存在", 404

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith("/api/"):
            return jsonify(code=1, msg="服务器内部错误"), 500
        return "服务器内部错误", 500

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
