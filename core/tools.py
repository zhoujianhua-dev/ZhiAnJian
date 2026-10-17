# -*- coding: utf-8 -*-
"""
智安鉴 · 工具箱
==============
提供与“工具管理”菜单对应的全部功能：
  1. 随机密码生成（弱口令/社工口令）
  2. 文本行去重
  3. 提取域名 / IP（支持 URL、裸 IP+端口、域名）
  4. A/B 文件对比（对齐两列）
  5. 资产分类（URL / 域名 / IP / 邮箱 / 手机号 / 文件路径等）
  6. 资产信息批量归类（资产分类页）
"""
import random
import string
import re
import ipaddress
import tldextract
from urllib.parse import urlparse


# ---------------- 1. 随机密码生成 ----------------
def generate_password(length: int = 12, use_upper=True, use_lower=True,
                      use_numbers=True, use_special=True) -> str:
    groups = []
    if use_upper:
        groups.append(string.ascii_uppercase)
    if use_lower:
        groups.append(string.ascii_lowercase)
    if use_numbers:
        groups.append(string.digits)
    if use_special:
        groups.append(string.punctuation)
    if not groups:
        raise ValueError("请选择至少 1 个字符类型")
    if length < 1:
        raise ValueError("长度必须大于 0")
    all_chars = "".join(groups)
    if length < len(groups):
        # 长度不足以覆盖全部类别时退化为整池随机
        return "".join(random.choice(all_chars) for _ in range(length))
    # 保证每个已勾选字符类至少出现 1 个字符，其余从合并字符池随机，再整体打乱
    pwd = [random.choice(g) for g in groups]
    pwd += [random.choice(all_chars) for _ in range(length - len(groups))]
    random.shuffle(pwd)
    return "".join(pwd)


def generate_batch_passwords(count: int = 10, **kw) -> list:
    return [generate_password(**kw) for _ in range(max(1, count))]


# ---------------- 2. 文本行去重 ----------------
def dedup_lines(text: str, keep_order: bool = True, ignore_blank: bool = True,
                case_insensitive: bool = False) -> list:
    lines = text.splitlines()
    if ignore_blank:
        lines = [ln.strip() for ln in lines if ln.strip()]
    seen = set()
    result = []
    for ln in lines:
        key = ln.strip().lower() if case_insensitive else ln.strip()
        if key and key not in seen:
            seen.add(key)
            result.append(ln.strip() if ignore_blank else ln)
        elif not key and not ignore_blank:
            result.append(ln)
    return result


# ---------------- 3. 提取域名 / IP ----------------
_RE_URL = re.compile(r"https?://[^\s，。；,;、）)】\]》\"'<>\s]+", re.IGNORECASE)
_RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b")
_RE_DOMAIN = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+\b",
    re.IGNORECASE)


def _valid_ipv4(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 4
    except ValueError:
        return False


def extract_root_domain(input_str: str):
    """从 URL / IP+端口 / 域名 中提取主域名或 IP"""
    try:
        if input_str.startswith(("http://", "https://")):
            hostname = urlparse(input_str).hostname
        else:
            hostname = input_str.split(":")[0].strip()
        if not hostname:
            return "无法识别的地址: " + input_str
        ip = ipaddress.ip_address(hostname)
        return str(ip)
    except ValueError:
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return "无法识别的地址: " + input_str


def extract_assets_from_line(line: str) -> list:
    """
    从一段可能含自然语言的文本中抽取候选资产（URL / IPv4[:端口] / 域名），
    按出现顺序去重。URL 命中区间会被屏蔽，避免其中的主机名被重复计为域名。
    """
    candidates, covered, seen = [], [], set()

    def add(token):
        token = token.strip().strip(".,;:!?)】」』")
        low = token.lower()
        if token and low not in seen:
            seen.add(low)
            candidates.append(token)

    def covered_pos(a, b):
        return any(not (b <= s or a >= e) for s, e in covered)

    for m in _RE_URL.finditer(line):
        tok = m.group(0)
        host = urlparse(tok).hostname or ""
        if host:
            covered.append(m.span())
            add(tok)
    # 裸 IP（含端口），跳过已被 URL 覆盖的位置
    for m in _RE_IP.finditer(line):
        if covered_pos(m.start(), m.end()):
            continue
        iponly = m.group(0).split(":")[0]
        if _valid_ipv4(iponly):
            covered.append(m.span())
            add(m.group(0))
    # 域名（用 tldextract 验证存在有效后缀，避免普通单词误判）
    for m in _RE_DOMAIN.finditer(line):
        if covered_pos(m.start(), m.end()):
            continue
        tok = m.group(0)
        ext = tldextract.extract(tok)
        if ext.domain and ext.suffix:
            covered.append(m.span())
            add(tok)
    return candidates


def process_url_text(text: str) -> list:
    """
    逐行处理：
    - 整行本身就是一个纯净地址时，保持与原工具一致的单列结果；
    - 整行无法直接解析（如夹带中文/多个地址的自然语言）时，
      自动从该行抽取所有 URL/IP/域名并逐一解析，多个结果以“、”连接。
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    results = []
    for ln in lines:
        direct = extract_root_domain(ln)
        if not direct.startswith("无法识别"):
            results.append({"input": ln, "result": direct, "targets": [ln], "multi": False})
            continue
        targets = extract_assets_from_line(ln)
        vals = []
        for tok in targets:
            v = extract_root_domain(tok)
            if not v.startswith("无法识别") and v not in vals:
                vals.append(v)
        if vals:
            results.append({"input": ln, "result": "、".join(vals),
                            "targets": targets, "multi": len(vals) > 1})
        else:
            results.append({"input": ln, "result": direct, "targets": [], "multi": False})
    return results


# ---------------- 4. A/B 文件对比 ----------------
def align_columns(a_text: str, b_text: str):
    a_lines = set(filter(None, a_text.splitlines()))
    b_lines = set(filter(None, b_text.splitlines()))
    all_lines = sorted(a_lines.union(b_lines))
    aligned_a, aligned_b = [], []
    only_a, only_b = [], []
    for ln in all_lines:
        in_a = ln in a_lines
        in_b = ln in b_lines
        aligned_a.append(ln if in_a else "")
        aligned_b.append(ln if in_b else "")
        if in_a and not in_b:
            only_a.append(ln)
        if in_b and not in_a:
            only_b.append(ln)
    return {
        "aligned_a": "\n".join(aligned_a),
        "aligned_b": "\n".join(aligned_b),
        "only_a": "\n".join(only_a),
        "only_b": "\n".join(only_b),
        "common_count": len(a_lines & b_lines),
        "a_count": len(a_lines),
        "b_count": len(b_lines),
    }


# ---------------- 5. 资产分类 ----------------
def classify_line(line: str) -> dict:
    """对单行文本进行资产类型识别"""
    line = line.strip()
    if not line:
        return {"input": "", "type": "空", "value": ""}

    # IP:端口
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", line)
    if m:
        return {"input": line, "type": "IP:端口", "value": m.group(1)}
    # IPv4
    try:
        ip = ipaddress.ip_address(line)
        return {"input": line, "type": "IPv6" if ip.version == 6 else "IP", "value": str(ip)}
    except ValueError:
        pass
    # 邮箱
    if re.match(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$", line):
        return {"input": line, "type": "邮箱", "value": line}
    # 手机号
    if re.match(r"^1[3-9]\d{9}$", line):
        return {"input": line, "type": "手机号", "value": line}
    # URL
    if line.startswith(("http://", "https://")):
        hostname = urlparse(line).hostname or ""
        return {"input": line, "type": "URL", "value": hostname}
    # 域名
    ext = tldextract.extract(line)
    if ext.domain and ext.suffix:
        return {"input": line, "type": "域名", "value": f"{ext.domain}.{ext.suffix}"}
    # 文件路径/其他
    return {"input": line, "type": "其他", "value": line}


def classify_assets(text: str) -> dict:
    """
    分类文本中的资产，返回统计与明细。
    每行本身为单一资产时直接分类；若一行为夹带多个资产的自然语言，
    则自动抽取其中的 URL/IP/域名后逐条分类，无法识别的片段归为“其他”。
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    items = []
    for ln in lines:
        item = classify_line(ln)
        if item["type"] != "其他":
            items.append(item)
            continue
        cands = extract_assets_from_line(ln)
        if cands:
            for c in cands:
                sub = classify_line(c)
                # 二次保险：抽取的域名若仍未识别则不重复堆叠
                if sub["type"] != "其他":
                    sub["source"] = ln
                    items.append(sub)
        else:
            items.append(item)
    stats = {}
    for it in items:
        stats[it["type"]] = stats.get(it["type"], 0) + 1
    return {"items": items, "stats": stats, "total": len(items)}
