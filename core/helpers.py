# -*- coding: utf-8 -*-
"""
智安鉴 · 通用辅助函数
"""
import os
import re
import uuid
from datetime import datetime
from urllib.parse import quote


def sanitize_filename(name: str) -> str:
    """清洗文件名中的非法字符"""
    name = re.sub(r'[\\/:*?"<>|\r\n\t]', '_', name)
    name = re.sub(r'\s+', ' ', name).strip()
    return name[:120]


def now_ts() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def now_display() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def gen_record_id() -> str:
    return uuid.uuid4().hex


def random_filename(ext: str) -> str:
    return f"{uuid.uuid4().hex}{ext}"


def content_disposition(filename: str) -> str:
    """构造支持中文的 Content-Disposition"""
    return f"attachment; filename*=UTF-8''{quote(filename)}"


def severity_cn(severity: str) -> str:
    mapping = {
        "critical": "严重", "high": "高危", "medium": "中危",
        "low": "低危", "info": "信息", "unknown": "未知",
    }
    return mapping.get(severity, "未知")


def severity_level(severity: str) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
    return order.get(severity, 0)


def escape_placeholder(text: str) -> str:
    """转义 docxtpl 占位符，避免用户内容里的 {{ }} 被二次解析"""
    if not text:
        return ""
    return str(text).replace("{{", "&#123;&#123;").replace("}}", "&#125;&#125;")


def is_image_ext(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico")


# ---------------- 漏洞处置全生命周期 ----------------
# open 待整改 -> fixing 整改中 -> fixed 已修复待复测 -> verified 复测通过（闭环）
LIFECYCLE_CN = {
    "open": "待整改",
    "fixing": "整改中",
    "fixed": "已修复待复测",
    "verified": "复测通过",
}

# 允许的状态流转（严格闭环；fixed 可被复测退回 fixing，verified 可由管理操作撤销）
LIFECYCLE_TRANSITIONS = {
    "open": ["fixing"],
    "fixing": ["fixed", "open"],
    "fixed": ["verified", "fixing"],
    "verified": ["fixed"],
}

# 每个流转动作的中文说明（用于操作按钮与时间线）
LIFECYCLE_ACTION = {
    ("open", "fixing"): "开始整改",
    ("fixing", "fixed"): "提交整改完成，申请复测",
    ("fixing", "open"): "退回待整改",
    ("fixed", "verified"): "复测通过，漏洞闭环",
    ("fixed", "fixing"): "复测未通过，退回整改",
    ("verified", "fixed"): "撤销复测结论",
}


def lifecycle_cn(state: str) -> str:
    return LIFECYCLE_CN.get(state or "open", "待整改")


def lifecycle_next(state: str):
    return LIFECYCLE_TRANSITIONS.get(state or "open", [])


def lifecycle_can_move(src: str, dst: str) -> bool:
    return dst in LIFECYCLE_TRANSITIONS.get(src or "open", [])
