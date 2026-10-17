# -*- coding: utf-8 -*-
"""
智安鉴 · 漏洞报告质量体检引擎
==============================
基于本地规则对报告进行完整性、规范性、证据充分性检查，
输出问题清单、扣分明细与 0-100 综合评分；不依赖 AI，离线可用。
AI 点评为可选增强（在路由层按需调用）。
"""
import re
from bs4 import BeautifulSoup

import database as db

# 检查项：(规则键, 权重, 问题级别)
RULES = [
    ("unit_name", 10, "critical"),
    ("vul_name", 10, "critical"),
    ("severity", 8, "high"),
    ("address", 12, "high"),
    ("description", 14, "high"),
    ("harm", 12, "medium"),
    ("detail", 16, "high"),
    ("suggestion", 12, "medium"),
    ("prove", 6, "medium"),
]

URL_RE = re.compile(r"^(https?://|ftp://)?([\w-]+\.)+[a-zA-Z]{2,}(:\d+)?(/\S*)?$|^(\d{1,3}\.){3}\d{1,3}(:\d+)?(/\S*)?$")


def _html_text_len(html: str) -> int:
    if not html:
        return 0
    soup = BeautifulSoup(html, "html.parser")
    return len(soup.get_text(strip=True))


def _html_img_count(html: str) -> int:
    if not html:
        return 0
    return len(BeautifulSoup(html, "html.parser").find_all("img"))


def check_report(r: dict) -> dict:
    """
    对单条报告进行体检
    :return: {score, level, issues:[{rule, level, msg, weight}], passed}
    """
    issues = []
    score = 100
    weights = dict((k, w) for k, w, _ in RULES)

    def fail(rule, msg, level="medium"):
        issues.append({"rule": rule, "level": level, "msg": msg, "weight": weights.get(rule, 5)})

    # 1. 单位名称
    unit = (r.get("unit_name") or "").strip()
    if not unit:
        fail("unit_name", "缺少单位名称", "critical")
    elif len(unit) < 4:
        fail("unit_name", "单位名称过短，建议使用完整工商注册名称", "low")

    # 2. 漏洞名称
    vul = (r.get("vul_name") or "").strip()
    if not vul:
        fail("vul_name", "缺少漏洞名称", "critical")
    elif len(vul) < 4:
        fail("vul_name", "漏洞名称过于简略，建议采用“XX 漏洞”规范命名", "low")

    # 3. 漏洞等级
    sev = (r.get("severity") or "unknown").lower()
    if sev in ("unknown", ""):
        fail("severity", "未设置漏洞等级", "high")

    # 4. 漏洞地址
    addr = (r.get("address") or "").strip()
    if not addr:
        fail("address", "缺少漏洞地址（URL/IP/路径）", "high")
    else:
        lines = [x.strip() for x in addr.splitlines() if x.strip()]
        bad = [x for x in lines if not URL_RE.match(x)]
        if bad and len(bad) == len(lines):
            fail("address", "漏洞地址格式可能不正确，建议填写完整 URL 或 IP:端口", "low")

    # 5. 漏洞描述
    desc = (r.get("description") or "").strip()
    if not desc:
        fail("description", "缺少漏洞描述", "high")
    elif len(desc) < 30:
        fail("description", "漏洞描述过短（建议不少于 30 字），需说明技术原理与触发条件", "medium")

    # 6. 漏洞危害
    harm = (r.get("harm") or "").strip()
    if not harm:
        fail("harm", "缺少漏洞危害分析", "medium")
    elif len(harm) < 15:
        fail("harm", "危害分析过短，建议结合业务影响说明", "low")

    # 7. 检测过程（富文本）
    detail = r.get("detail") or ""
    detail_len = _html_text_len(detail)
    img_count = _html_img_count(detail)
    if detail_len < 20:
        fail("detail", "检测过程内容不足，应包含可复现的操作步骤", "high")
    elif detail_len < 60:
        fail("detail", "检测过程描述偏简单，建议补充复现步骤与响应结果", "medium")
    if img_count == 0:
        fail("detail", "检测过程缺少截图证据，建议至少插入 1 张复现截图", "low")

    # 8. 整改建议
    sug = (r.get("suggestion") or "").strip()
    if not sug:
        fail("suggestion", "缺少整改建议", "medium")
    else:
        sug_text = BeautifulSoup(sug, "html.parser").get_text(" ", strip=True)
        has_steps = bool(re.search(r"(1[.、）)]|①|首先|步骤|[;\n])", sug_text)) or sug_text.count("。") >= 1
        if len(sug_text) < 15:
            fail("suggestion", "整改建议过短，需可落地执行", "low")
        elif not has_steps:
            fail("suggestion", "整改建议建议分条列出，便于责任方落实", "low")

    # 9. 归属证明
    prove = r.get("prove") or ""
    prove_len = _html_text_len(prove)
    if prove_len < 10:
        fail("prove", "归属证明内容不足，需能证明漏洞属于目标系统", "medium")
    if _html_img_count(prove) == 0:
        fail("prove", "归属证明建议附带 ICP 备案/系统页面等截图", "low")

    # 扣分（权重换算：总权重 100）
    for it in issues:
        # low 级别按权重 40% 扣，medium 70%，critical/high 100%
        ratio = {"low": 0.4, "medium": 0.7, "high": 1.0, "critical": 1.0}.get(it["level"], 0.7)
        score -= it["weight"] * ratio
    score = max(0, round(score))

    level = "优秀" if score >= 90 else "良好" if score >= 75 else "合格" if score >= 60 else "待完善"
    return {
        "id": r.get("id"),
        "unit_name": unit,
        "vul_name": vul,
        "score": score,
        "level": level,
        "passed": score >= 60,
        "issues": issues,
        "evidence_images": img_count,
        "detail_length": detail_len,
    }


def check_all_reports():
    """体检全部报告，含重复性检测"""
    rows = db.query_all("SELECT * FROM reports WHERE status=0 ORDER BY id")
    results = [check_report(dict(r)) for r in rows]

    # 重复性检测：同单位 + 同漏洞名
    seen = {}
    for r in results:
        key = (r["unit_name"], r["vul_name"])
        if key in seen:
            r["issues"].append({"rule": "duplicate", "level": "medium",
                                "msg": f"与报告 #{seen[key]} 可能重复（同单位同漏洞名称）", "weight": 0})
        else:
            seen[key] = r["id"]

    avg = round(sum(r["score"] for r in results) / len(results)) if results else 0
    return {
        "results": results,
        "total": len(results),
        "average_score": avg,
        "passed_count": sum(1 for r in results if r["passed"]),
        "issue_count": sum(len(r["issues"]) for r in results),
    }
