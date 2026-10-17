# -*- coding: utf-8 -*-
"""
智安鉴 · 智能安全检测与漏洞报告系统 —— 系统配置
================================================
所有可调配置集中于此。config.json（位于项目根目录）可覆盖以下默认值，
方便用户在不改代码的情况下调整系统。

敏感信息说明：AI API Key 仅保存在本机 config.json 中，不会写入数据库、
不会出现在报告或日志中。
"""
import os
import json
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# ---------------- 基础信息 ----------------
APP_NAME = "智安鉴"
APP_TITLE = "智能安全检测与漏洞报告系统"
APP_SUBTITLE = "AI 赋能 · 资产管理 · 漏洞治理 · 报告一键生成"
VERSION = "1.0.0"

# ---------------- 目录 ----------------
DATA_DIR = BASE_DIR / "data"
EXPORT_DIR = DATA_DIR / "exports"          # 导出的 Word 报告
UPLOAD_DIR = DATA_DIR / "uploads"          # 富文本图片上传
BG_DIR = DATA_DIR / "backgrounds"          # 用户自定义背景图
TEMPLATE_DIR = DATA_DIR / "report_templates"  # 用户上传的报告模板
AI_IMAGE_DIR = DATA_DIR / "ai_images"      # AI 流程产生的图片
BUILTIN_TEMPLATE_DIR = BASE_DIR / "assets" / "builtin_templates"  # 随源码分发的内置标准模板

for _d in (DATA_DIR, EXPORT_DIR, UPLOAD_DIR, BG_DIR, TEMPLATE_DIR, AI_IMAGE_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "zhianjian.db"
CONFIG_FILE = BASE_DIR / "config.json"

# ---------------- 默认配置 ----------------
DEFAULTS = {
    "app_title": APP_TITLE,
    "app_subtitle": APP_SUBTITLE,
    "theme_color": "#2563eb",              # 主题色
    "background": "",                      # 背景图（相对 data/backgrounds 的文件名），空=使用默认渐变
    "background_overlay": 0.35,            # 背景遮罩透明度 0~0.9
    "background_blur": 0,                  # 背景模糊像素
    "report_header": "网络安全测试报告",     # 导出报告页眉标题
    "export_org": "",                      # 报告落款单位（可选）
    # ---- AI 配置（敏感，仅本地 config.json）----
    "ai": {
        "base_url": "https://api.stepfun.com/v1",
        "model": "step-3.5-flash",
        "api_key": "",
        "timeout": 120
    },
    # ---- 内置漏洞扫描引擎（已合入代码，无界面配置项）----
    # 智安鉴内置调用扫描引擎（Shelling 后端 API），下面是内置默认值，开箱即用；
    # 若部署在别处，可在 config.json 里用同名的 shelling 段覆盖（没有界面入口）。
    "shelling": {
        "base_url": "http://host.docker.internal:8000",
        "username": "admin",
        "password": "admin123456",
        "timeout": 600
    },
    # ---- 登录会话签名密钥（首次运行自动生成并写回 config.json，不要手工清空）----
    "secret_key": ""
}

# 需要按子字典合并（而非整体覆盖）的配置段
NESTED_KEYS = ("ai", "shelling")


def load_config() -> dict:
    """加载用户配置（config.json 覆盖默认值）"""
    cfg = json.loads(json.dumps(DEFAULTS))
    if CONFIG_FILE.exists():
        try:
            user_cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            for k, v in user_cfg.items():
                if k in NESTED_KEYS and isinstance(v, dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except Exception:
            pass
    return cfg


def save_config(cfg: dict) -> None:
    """将用户配置写回 config.json（保留 AI 敏感字段）"""
    merged = load_config()
    for k, v in cfg.items():
        if k in NESTED_KEYS and isinstance(v, dict):
            merged.setdefault(k, {}).update(v)
        else:
            merged[k] = v
    # 扫描引擎地址与账号是代码内置默认值，与默认值相同时不落盘，
    # 免得 config.json 里出现一份看着像「必须配置」的副本（用户手工改过则原样保留）
    if merged.get("shelling") == DEFAULTS.get("shelling"):
        merged.pop("shelling", None)
    CONFIG_FILE.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")


def get_cfg() -> dict:
    return load_config()


def get_secret_key() -> str:
    """会话签名密钥：首次运行生成后写入 config.json，重启/重建容器都不会让登录态失效"""
    try:
        key = load_config().get("secret_key") or ""
        if len(key) >= 32:
            return key
        key = secrets.token_hex(32)
        save_config({"secret_key": key})
        return key
    except Exception:
        # 配置文件不可写时退化为进程内随机密钥（重启需重新登录）
        return secrets.token_hex(32)
