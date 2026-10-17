# -*- coding: utf-8 -*-
"""
智安鉴 · 扫描器结果智能解析器
================================
支持将主流安全工具的输出文件解析为统一的 raw_findings：
  1. Nuclei：JSONL（每行一个 JSON）或 JSON 数组
     字段：info.name / info.severity / host / matched-at / description / extracted-results
  2. Burp Suite：XML 导出（issues/issue）
     字段：name / severity / host / path / location / issueDetail / issueBackground
  3. 通用 JSON：递归嗅探含 name|title 与 severity|url 的对象
  4. 纯文本：非空行作为待分析的原始记录

输出统一结构：
  {"source": "nuclei|burp|json|text", "data": {title, severity, url, evidence, description, raw}}
"""
import json
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

SEVERITY_ALIAS = {
    "critical": "critical", "crit": "critical", "严重": "critical",
    "high": "high", "h": "high", "高危": "high",
    "medium": "medium", "med": "medium", "middle": "medium", "中危": "medium", "警告": "medium",
    "low": "low", "l": "low", "低危": "low",
    "info": "info", "informational": "info", "information": "info", "信息": "info",
    "none": "unknown", "未知": "unknown", "unknown": "unknown",
}


def norm_severity(s) -> str:
    if not s:
        return "unknown"
    return SEVERITY_ALIAS.get(str(s).strip().lower(), "unknown")


def _finding(source, title, severity="unknown", url="", evidence="", description="", raw=None):
    return {
        "source": source,
        "data": {
            "title": str(title or "未知漏洞")[:300],
            "severity": norm_severity(severity),
            "url": str(url or "")[:500],
            "evidence": str(evidence or "")[:2000],
            "description": str(description or "")[:2000],
            "raw": raw if raw is not None else {},
        },
    }


# ---------------- Nuclei ----------------
def _parse_nuclei_obj(obj: dict) -> dict:
    info = obj.get("info", {}) if isinstance(obj.get("info"), dict) else {}
    classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
    evidence_parts = []
    matched = obj.get("matched-at") or obj.get("matched_at") or ""
    if matched:
        evidence_parts.append(f"匹配位置：{matched}")
    # extracted-results
    er = obj.get("extracted-results") or obj.get("extracted_results") or []
    if isinstance(er, list):
        for e in er[:5]:
            evidence_parts.append(f"提取结果：{e}")
    template_id = obj.get("template-id") or obj.get("template_id") or obj.get("templateID") or ""
    if template_id:
        evidence_parts.append(f"模板ID：{template_id}")
    curl = obj.get("curl-command") or obj.get("curl_command") or ""
    if curl:
        evidence_parts.append(f"请求：{curl}")
    return _finding(
        "nuclei",
        info.get("name") or obj.get("name") or template_id or "未知漏洞",
        info.get("severity") or obj.get("severity"),
        obj.get("host") or obj.get("ip") or "",
        "\n".join(evidence_parts),
        info.get("description") or classification.get("description") or "",
        raw=obj,
    )


def _try_nuclei(text: str):
    text = text.strip()
    findings = []
    # JSONL
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    jsonl_ok = len(lines) > 0
    parsed = []
    for ln in lines:
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                parsed.append(obj)
            else:
                jsonl_ok = False
                break
        except json.JSONDecodeError:
            jsonl_ok = False
            break
    if jsonl_ok and parsed:
        for obj in parsed:
            # Nuclei 特征：info dict 或 template-id
            if isinstance(obj, dict) and ("info" in obj or "template-id" in obj or "template-id" in obj
                                          or "templateID" in obj or "matched-at" in obj):
                findings.append(_parse_nuclei_obj(obj))
        if findings:
            return findings
    # JSON 数组/单对象
    try:
        data = json.loads(text)
        objs = data if isinstance(data, list) else [data]
        for obj in objs:
            if isinstance(obj, dict) and ("info" in obj or "template-id" in obj or "matched-at" in obj):
                findings.append(_parse_nuclei_obj(obj))
        if findings:
            return findings
    except json.JSONDecodeError:
        pass
    return None


# ---------------- Burp XML ----------------
def _try_burp(content: bytes):
    head = content[:2000].lower()
    if b"<issues" not in head and b"<?xml" not in head:
        # 可能在更后面出现 issues
        if b"<issue" not in content[:5000]:
            return None
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None
    issues = root.findall(".//issue")
    if not issues:
        return None

    def txt(parent, tag):
        el = parent.find(tag)
        if el is None:
            # 尝试命名空间无关
            for child in parent:
                if child.tag.split("}")[-1] == tag:
                    return (child.text or "").strip()
            return ""
        # 含 CDP / 子节点 html
        return "".join(el.itertext()).strip()

    findings = []
    for it in issues:
        name = txt(it, "name")
        if not name:
            continue
        host = txt(it, "host")
        path = txt(it, "path")
        location = txt(it, "location")
        detail = txt(it, "issueDetail")
        background = txt(it, "issueBackground")
        severity = txt(it, "severity")
        confidence = txt(it, "confidence")
        url = host + path if host and path else (host or location)
        evidence = []
        if location:
            evidence.append(f"位置：{location}")
        if confidence:
            evidence.append(f"置信度：{confidence}")
        # 请求响应
        req = it.find("request")
        if req is not None and (req.text or "").strip():
            evidence.append("请求：" + (req.text or "").strip()[:500])
        findings.append(_finding("burp", name, severity, url, "\n".join(evidence),
                                 detail or background, raw={"name": name, "host": host, "path": path}))
    return findings or None


# ---------------- 通用 JSON 嗅探 ----------------
_VULN_KEYS_TITLE = ("title", "name", "vul_name", "vulname", "plugin", "template", "poc_name")
_VULN_KEYS_SEV = ("severity", "level", "risk", "threat", "grade")
_VULN_KEYS_URL = ("url", "host", "target", "endpoint", "address", "matched")
_VULN_KEYS_EV = ("evidence", "proof", "payload", "request", "response", "detail", "matched_at", "matched-at")
_VULN_KEYS_DESC = ("description", "desc", "summary", "remediation", "solution")


def _looks_like_vuln(obj: dict) -> bool:
    keys = {str(k).lower(): v for k, v in obj.items()}
    has_title = any(k in keys and keys[k] not in (None, "") for k in _VULN_KEYS_TITLE)
    has_sev_or_url = any(k in keys and keys[k] not in (None, "") for k in _VULN_KEYS_SEV + _VULN_KEYS_URL)
    return has_title and has_sev_or_url


def _sniff_json_obj(obj: dict):
    if not isinstance(obj, dict):
        return None
    if _looks_like_vuln(obj):
        keys = {str(k).lower(): v for k, v in obj.items()}
        title = next((str(keys[k]) for k in _VULN_KEYS_TITLE if keys.get(k) not in (None, "")), "未知漏洞")
        sev = next((str(keys[k]) for k in _VULN_KEYS_SEV if keys.get(k) not in (None, "")), "")
        url = next((str(keys[k]) for k in _VULN_KEYS_URL if keys.get(k) not in (None, "")), "")
        ev = next((str(keys[k]) for k in _VULN_KEYS_EV if keys.get(k) not in (None, "")), "")
        desc = next((str(keys[k]) for k in _VULN_KEYS_DESC if keys.get(k) not in (None, "")), "")
        return _finding("json", title, sev, url, ev, desc, raw=obj)
    # 嵌套：data / result / findings / list / issues
    for k in ("data", "result", "findings", "list", "issues", "vulnerabilities", "items"):
        v = obj.get(k)
        if isinstance(v, list):
            out = [_sniff_json_obj(x) for x in v if isinstance(x, dict)]
            out = [x for x in out if x]
            if out:
                return out
        if isinstance(v, dict):
            r = _sniff_json_obj(v)
            if r:
                return r
    return None


def _try_generic_json(text: str):
    try:
        data = json.loads(text.strip())
    except json.JSONDecodeError:
        # 多行中部分是 JSON
        return None
    findings = []
    objs = data if isinstance(data, list) else [data]
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        r = _sniff_json_obj(obj)
        if isinstance(r, list):
            findings.extend(r)
        elif r:
            findings.append(r)
    return findings or None


# ---------------- 纯文本 ----------------
def _parse_text(text: str):
    lines = [ln.strip(" -*•\t") for ln in text.splitlines()]
    lines = [ln for ln in lines if len(ln) >= 4]
    if not lines:
        return []
    # 行过长则整体作为一条
    if len(lines) == 1 and len(lines[0]) > 200:
        return [_finding("text", "待分析漏洞记录", "unknown", "", lines[0][:2000], "")]
    return [_finding("text", ln[:120], "unknown", "", ln, "") for ln in lines[:50]]


def parse_scanner_content(filename: str, content: bytes):
    """
    解析扫描器结果内容
    :return: {"source": str, "findings": [...], "count": int}
    """
    # Burp XML 优先按二进制嗅探
    low_name = (filename or "").lower()
    is_xml = low_name.endswith(".xml") or content.lstrip()[:5].lower().startswith(b"<?xml")
    if is_xml or b"<issues" in content[:3000]:
        r = _try_burp(content)
        if r:
            return {"source": "burp", "findings": r, "count": len(r)}

    # 文本类尝试多编码
    text = None
    for enc in ("utf-8-sig", "utf-8", "gb18030", "latin-1"):
        try:
            text = content.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = content.decode("utf-8", errors="ignore")

    for parser in (_try_nuclei, _try_generic_json):
        r = parser(text)
        if r:
            return {"source": r[0]["source"], "findings": r, "count": len(r)}

    findings = _parse_text(text)
    return {"source": "text", "findings": findings, "count": len(findings)}


def summarize_findings(findings):
    """统计解析结果"""
    stats = {}
    for f in findings:
        sev = f["data"].get("severity", "unknown")
        stats[sev] = stats.get(sev, 0) + 1
    return stats
