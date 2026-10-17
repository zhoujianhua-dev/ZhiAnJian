# -*- coding: utf-8 -*-
"""
智安鉴 · CVSS v3.1 基础评分计算器
=================================
严格依据 FIRST.org CVSS v3.1 规范实现基础指标评分：
向量格式：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
输出：基础分（0-10）、等级、各指标取值与可复现的计算过程。
参考：https://www.first.org/cvss/calculator/3.1
"""
import math
import re

METRICS = {
    "AV": {"label": "攻击向量 Attack Vector", "values": {
        "N": ("网络 Network", 0.85), "A": ("邻接 Adjacent", 0.62),
        "L": ("本地 Local", 0.55), "P": ("物理 Physical", 0.20)}},
    "AC": {"label": "攻击复杂度 Attack Complexity", "values": {
        "L": ("低 Low", 0.77), "H": ("高 High", 0.44)}},
    "PR": {"label": "所需权限 Privileges Required", "values": {
        "N": ("无 None", None), "L": ("低 Low", None), "H": ("高 High", None)}},
    "UI": {"label": "用户交互 User Interaction", "values": {
        "N": ("无需 None", 0.85), "R": ("需要 Required", 0.62)}},
    "S": {"label": "影响范围 Scope", "values": {
        "U": ("不变 Unchanged", None), "C": ("改变 Changed", None)}},
    "C": {"label": "机密性 Confidentiality", "values": {
        "H": ("高 High", 0.56), "L": ("低 Low", 0.22), "N": ("无 None", 0.0)}},
    "I": {"label": "完整性 Integrity", "values": {
        "H": ("高 High", 0.56), "L": ("低 Low", 0.22), "N": ("无 None", 0.0)}},
    "A": {"label": "可用性 Availability", "values": {
        "H": ("高 High", 0.56), "L": ("低 Low", 0.22), "N": ("无 None", 0.0)}},
}

# PR 权重随 Scope 变化
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def roundup(value: float) -> float:
    """CVSS 规范的 roundup：向上取整到 1 位小数"""
    return math.ceil(value * 10 - 0.00001) / 10


def parse_vector(vector: str) -> dict:
    """解析 CVSS v3.1 向量字符串，返回 {指标: 取值}"""
    vector = (vector or "").strip().upper()
    if not vector:
        raise ValueError("向量为空")
    # 兼容带 CVSS:3.1/ 前缀与不带前缀
    vector = re.sub(r"^CVSS:3\.\d/?", "", vector)
    parts = [p for p in re.split(r"[/\s,]+", vector) if p]
    metrics = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        k, v = k.strip(), v.strip()
        if k in METRICS and v in METRICS[k]["values"]:
            metrics[k] = v
    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise ValueError("向量缺少必要指标：" + ",".join(missing))
    return metrics


def calculate(vector: str) -> dict:
    """计算基础分"""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    av = METRICS["AV"]["values"][m["AV"]][1]
    ac = METRICS["AC"]["values"][m["AC"]][1]
    pr = PR_WEIGHTS["C" if scope_changed else "U"][m["PR"]]
    ui = METRICS["UI"]["values"][m["UI"]][1]
    c = METRICS["C"]["values"][m["C"]][1]
    i = METRICS["I"]["values"][m["I"]][1]
    a = METRICS["A"]["values"][m["A"]][1]

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif not scope_changed:
        base = roundup(min(impact + exploitability, 10.0))
    else:
        base = roundup(min(1.08 * (impact + exploitability), 10.0))

    rating = ("None" if base == 0 else "Low" if base < 4 else
              "Medium" if base < 7 else "High" if base < 9 else "Critical")
    rating_cn = {"None": "无", "Low": "低危", "Medium": "中危", "High": "高危", "Critical": "严重"}[rating]

    detail = []
    for k in REQUIRED:
        label = METRICS[k]["label"]
        val_label = METRICS[k]["values"][m[k]][0]
        detail.append({"metric": k, "label": label, "value": m[k], "value_label": val_label})

    canonical = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in REQUIRED)

    return {
        "base_score": base,
        "rating": rating,
        "rating_cn": rating_cn,
        "vector": canonical,
        "scope_changed": scope_changed,
        "impact_subscore": round(impact, 2),
        "exploitability_subscore": round(exploitability, 2),
        "metrics": detail,
    }


def severity_from_score(score: float) -> str:
    if score <= 0:
        return "unknown"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"
