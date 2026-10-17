# -*- coding: utf-8 -*-
"""
智安鉴 · 资产自动联动
=====================
保存漏洞报告时，自动把“单位 / 域名”联动写入资产库，保持与 em 工具一致：
  1. 单位名称不存在 → 自动新增单位；
  2. 由漏洞地址（任意协议 http/https/mqtt/ftp/…、裸域名、IP[:端口]）解析主机名，
     或使用表单填写的域名 → 域名库不存在则自动新增并归属到该单位；
  3. 回写单位的域名数量（domain_count）。

extract_host() 的前端等价实现为 static/js/app.js 中的 ZhiShield.extractHost，
两者口径保持一致（去协议、去用户信息、去端口、去路径、域名小写）。
"""
import re
import ipaddress

import database as db

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
# 仅保留主机名时截断的分隔符
_STOP_RE = re.compile(r"[\/?#\s]")


def extract_host(address: str) -> str:
    """
    从漏洞地址中提取主机名（域名 / IPv4），不含协议、端口、路径、用户信息。
    无法识别时返回空字符串（不做臆测）。
      http://a.com:8080/x        -> a.com
      https://www.a.cn/login    -> www.a.cn
      mqtt://broker.xxx.cn:1883 -> broker.xxx.cn
      10.0.0.5:3306             -> 10.0.0.5
      user:pass@1.2.3.4         -> 1.2.3.4
    """
    if not address:
        return ""
    s = str(address).strip()
    if not s:
        return ""
    # 仅取第一行，避免整段文本误入
    s = s.splitlines()[0].strip()
    # 去协议
    s = _SCHEME_RE.sub("", s)
    # 去用户信息 user:pass@host
    if "@" in s:
        s = s.split("@", 1)[1]
    # 截断路径/查询/锚点/空白
    m = _STOP_RE.search(s)
    if m:
        s = s[:m.start()]
    if not s:
        return ""
    # IPv6 [::1]:8080
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            return s[1:end]
        return ""
    # 去端口（仅当冒号后纯数字，避免误删 IPv6/其它）
    if ":" in s:
        host, _, port = s.rpartition(":")
        if port.isdigit():
            s = host
    s = s.strip(".").strip().lower()
    if not s:
        return ""
    # IPv4
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    # 域名 / 主机名：标签合法即可，支持无点的内网主机名（如 server01、localhost、broker）
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")
    if all(label_re.match(lbl) for lbl in s.split(".")) and any(c.isalpha() for c in s):
        # 至少含一个字母，排除纯数字（残留端口等）
        return s
    return ""


def _now():
    return db.now_str()


def sync_unit_and_domain(unit_name: str, domain: str = "", address: str = "") -> dict:
    """
    保存报告后联动单位库 / 域名库。返回联动结果：
      {unit_created, domain_created, host}
    任何异常都不应影响报告保存本身，故上层调用需自行决定是否吞掉异常。
    """
    result = {"unit_created": False, "domain_created": False, "host": ""}
    unit_name = (unit_name or "").strip()
    domain = (domain or "").strip()
    host = domain.strip().strip("/").split(":")[0].strip().lower() if domain else ""
    # 表单域名优先；为空时从漏洞地址兜底解析
    if not host:
        host = extract_host(address)
    result["host"] = host

    # 1) 单位 get_or_create
    unit_existing = None
    if unit_name:
        unit_existing = db.query_one("SELECT id FROM units WHERE enterprise_name=?", (unit_name,))
        if not unit_existing:
            db.execute(
                "INSERT INTO units(enterprise_name, filing_status, icp_total, domain_count, "
                "created_at, updated_at) VALUES(?,?,?,?,?,?)",
                (unit_name, "unknown", -1, -1, _now(), _now()))
            result["unit_created"] = True

    # 2) 域名 get_or_create（归属到该单位）
    if host:
        drow = db.query_one("SELECT id, unit_name FROM domains WHERE domain=? AND is_deleted=0", (host,))
        if not drow:
            db.execute(
                "INSERT INTO domains(unit_name, domain, is_deleted, created_at) VALUES(?,?,0,?)",
                (unit_name or "", host, _now()))
            result["domain_created"] = True
        elif unit_name and not (drow["unit_name"] or "").strip():
            db.execute("UPDATE domains SET unit_name=? WHERE id=?", (unit_name, drow["id"]))

    # 3) 回写单位域名数量
    if unit_name:
        cnt_row = db.query_one(
            "SELECT COUNT(*) AS c FROM domains WHERE unit_name=? AND is_deleted=0", (unit_name,))
        cnt = cnt_row["c"] if cnt_row else 0
        db.execute("UPDATE units SET domain_count=?, updated_at=? WHERE enterprise_name=?",
                   (cnt, _now(), unit_name))
    return result


def backfill_from_reports() -> dict:
    """
    一键把【存量漏洞报告】里的单位 / 域名补录到资产库（幂等，可反复执行）。
    用于联动功能上线前已存在的历史报告：保存时没有自动登记，导致单位列表/域名资产
    页面为空。逐条按报告的 unit_name / domain / address 调 sync_unit_and_domain，
    已存在的单位、域名不会重复创建。返回扫描与新增数量。
    """
    rows = db.query_all(
        "SELECT unit_name, domain, address FROM reports "
        "WHERE COALESCE(unit_name,'')<>'' OR COALESCE(domain,'')<>'' OR COALESCE(address,'')<>''")
    units_new = domains_new = scanned = 0
    touched_units = set()
    for r in rows:
        scanned += 1
        res = sync_unit_and_domain(r["unit_name"] or "", r["domain"] or "", r["address"] or "")
        units_new += 1 if res.get("unit_created") else 0
        domains_new += 1 if res.get("domain_created") else 0
        # 域名能从地址解析、但报告本身 domain 为空时，顺手回写
        if res.get("host") and not (r["domain"] or "").strip():
            db.execute("UPDATE reports SET domain=? WHERE COALESCE(domain,'')='' AND unit_name=? AND address=?",
                      (res["host"], r["unit_name"] or "", r["address"] or ""))
        if (r["unit_name"] or "").strip():
            touched_units.add(r["unit_name"].strip())
    return {"scanned": scanned, "units_created": units_new,
            "domains_created": domains_new, "units": len(touched_units)}
