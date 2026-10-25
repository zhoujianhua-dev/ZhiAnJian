# -*- coding: utf-8 -*-
"""
漏洞名称中文化
==============
扫描引擎（Nuclei 模板）产出的漏洞名称是英文，直接进「漏洞库」不利于中文报告引用。
这里用内置安全术语词典做确定性翻译：不依赖网络与 AI Key，离线可用、结果稳定。

规则：
  1. 已经是中文的名称原样返回；
  2. 「产品名 < 版本 - 漏洞描述」结构只翻译描述部分，产品名与版本保持原样；
  3. 术语按长度优先匹配，保留 CVE 编号与括号；
  4. 未命中任何术语时返回原文，避免产生半截不通顺的名称。
"""
import re

# 安全术语词典：英文（小写匹配）→ 中文。按长度倒序匹配，避免短词先吃掉长词。
_TERMS = {
    # 注入类
    "server-side template injection": "服务端模板注入",
    "expression language injection": "表达式注入",
    "blind sql injection": "SQL 盲注",
    "sql injection": "SQL 注入",
    "nosql injection": "NoSQL 注入",
    "ldap injection": "LDAP 注入",
    "xpath injection": "XPath 注入",
    "template injection": "模板注入",
    "crlf injection": "CRLF 注入",
    "header injection": "请求头注入",
    "host header injection": "Host 头注入",
    "log injection": "日志注入",
    "command injection": "命令注入",
    "code injection": "代码注入",
    "xml external entity": "XML 外部实体注入",
    # 执行类
    "remote code execution": "远程代码执行",
    "remote command execution": "远程命令执行",
    "arbitrary code execution": "任意代码执行",
    "use-after-free": "释放后重用",
    "buffer overflow": "缓冲区溢出",
    "heap overflow": "堆溢出",
    "stack overflow": "栈溢出",
    "denial of service": "拒绝服务",
    "race condition": "条件竞争",
    # 认证 / 授权
    "authentication bypass": "认证绕过",
    "authorization bypass": "权限绕过",
    "access control bypass": "访问控制绕过",
    "improper authentication": "认证不当",
    "improper authorization": "授权不当",
    "privilege escalation": "权限提升",
    "local privilege escalation": "本地权限提升",
    "unauthorized access": "未授权访问",
    "unauthenticated access": "未授权访问",
    "default credentials": "默认口令",
    "default password": "默认密码",
    "hardcoded credentials": "硬编码凭据",
    "hardcoded password": "硬编码口令",
    "weak password": "弱口令",
    "weak credentials": "弱口令",
    # 文件 / 路径
    "arbitrary file read": "任意文件读取",
    "arbitrary file write": "任意文件写入",
    "arbitrary file upload": "任意文件上传",
    "arbitrary file delete": "任意文件删除",
    "local file inclusion": "本地文件包含",
    "remote file inclusion": "远程文件包含",
    "file inclusion": "文件包含",
    "file upload": "文件上传",
    "path traversal": "路径穿越",
    "directory traversal": "目录穿越",
    "directory listing": "目录遍历",
    # Web 常见
    "stored cross-site scripting": "存储型跨站脚本",
    "reflected cross-site scripting": "反射型跨站脚本",
    "dom-based cross-site scripting": "DOM 型跨站脚本",
    "cross-site scripting": "跨站脚本攻击",
    "cross-site request forgery": "跨站请求伪造",
    "server-side request forgery": "服务端请求伪造",
    "open redirect": "开放重定向",
    "subdomain takeover": "子域名接管",
    "domain takeover": "域名接管",
    "clickjacking": "点击劫持",
    "security misconfiguration": "安全配置错误",
    "misconfiguration": "配置错误",
    # 信息泄露
    "sensitive information disclosure": "敏感信息泄露",
    "information disclosure": "信息泄露",
    "information leakage": "信息泄露",
    "source code disclosure": "源码泄露",
    "data exposure": "数据泄露",
    "credential exposure": "凭据泄露",
    "exposure": "暴露",
    "exposed": "暴露的",
    # 其他
    "insecure deserialization": "不安全的反序列化",
    "deserialization": "反序列化",
    "open ports": "开放端口",
    "open port": "开放端口",
    "admin panel": "管理后台",
    "login page": "登录页面",
    "debug mode": "调试模式",
    "backup file": "备份文件",
    "git repository": "Git 仓库",
    "api key": "API 密钥",
    "web shell": "WebShell",
    "webshell": "WebShell",
    "backdoor": "后门",
    "vulnerability": "漏洞",
    "authentication": "认证",
    "authorization": "授权",
    "configuration": "配置",
    "improper": "不安全的",
    "insecure": "不安全的",
    "missing": "缺失",
    # 缩写（仅整词匹配）
    "xxe": "XML 外部实体注入",
    "ssrf": "服务端请求伪造",
    "csrf": "跨站请求伪造",
    "xss": "跨站脚本攻击",
    "rce": "远程代码执行",
    "lfi": "本地文件包含",
    "rfi": "远程文件包含",
}

# 长词优先，保证 "remote code execution" 不被 "code injection" 之类抢先
_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in sorted(_TERMS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

_CJK = re.compile(r"[\u4e00-\u9fff]")
# 产品名与漏洞描述的分隔："TeamCity < 2023.11.4 - Authentication Bypass"
_SPLIT = re.compile(r"^(?P<head>.+?)\s+-\s+(?P<desc>.+)$")


def has_chinese(text: str) -> bool:
    return bool(_CJK.search(text or ""))


def _translate(text: str) -> str:
    """把一段英文里的安全术语替换成中文；无命中时原样返回。"""
    if not text:
        return text
    replaced = _PATTERN.sub(lambda m: _TERMS[m.group(1).lower()], text)
    if replaced == text:
        return text
    # 清理替换后产生的中英混排空格
    replaced = re.sub(r"\s{2,}", " ", replaced)
    replaced = re.sub(r"\s+([,，。；;:：、)）])", r"\1", replaced)
    replaced = re.sub(r"([(（])\s+", r"\1", replaced)
    replaced = re.sub(r"\s*-\s*", " - ", replaced) if " - " in replaced else replaced
    return _polish(replaced.strip())


def _polish(text: str) -> str:
    """收尾润色：去重复括号解释、把「X in Y」改成中文语序。"""
    out = text
    # "跨站脚本攻击 (跨站脚本攻击)" → "跨站脚本攻击"
    out = re.sub(r"([^（）()]{2,}?)\s*[（(]\s*\1\s*[)）]", r"\1", out)
    # "敏感信息泄露 in Spring Boot Actuator" → "Spring Boot Actuator 的敏感信息泄露"
    m = re.match(r"^(?P<what>.+?)\s+(?:in|on|at|via|through|within)\s+(?P<where>.+)$", out, re.IGNORECASE)
    if m:
        what, where = m.group("what").strip(), m.group("where").strip()
        if has_chinese(what) and not has_chinese(where):
            out = f"{where} 的{what}"
    # 中文与英文之间补一个空格："的SQL" → "的 SQL"
    out = re.sub(r"([\u4e00-\u9fff])([A-Za-z])", r"\1 \2", out)
    return out


def to_chinese(name: str) -> str:
    """漏洞名称英译中：已经是中文、或无法识别时返回原文。"""
    text = (name or "").strip()
    if not text or has_chinese(text):
        return text

    m = _SPLIT.match(text)
    if m:
        head = _translate(m.group("head"))
        desc = _translate(m.group("desc"))
        if head == m.group("head") and desc == m.group("desc"):
            return text
        return f"{head} - {desc}"

    translated = _translate(text)
    return translated or text
