# -*- coding: utf-8 -*-
"""智安鉴 第二轮新功能 端到端接口测试（真实 HTTP）"""
import json
import os
import urllib.request
import http.cookiejar
import glob

BASE = "http://127.0.0.1:8080"
EXPORT = os.path.join(os.path.dirname(__file__), "data", "exports")

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

passed, failed = [], []

def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {extra}")

def get(path):
    return json.loads(op.open(BASE + path, timeout=20).read().decode())

def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        return json.loads(op.open(req, timeout=60).read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())

def post_raw(path, body, ctype):
    req = urllib.request.Request(BASE + path, data=body, headers={"Content-Type": ctype}, method="POST")
    try:
        return json.loads(op.open(req, timeout=60).read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())

# 拿 CSRF
tok = get("/api/csrf")["token"]
def postc(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json", "X-CSRF-Token": tok},
                                 method="POST")
    try:
        return json.loads(op.open(req, timeout=60).read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())

# 登录（内置管理员账号，见 database.ensure_default_admin；可用环境变量 ZS_USER / ZS_PASS 覆盖）
ZS_USER = os.environ.get("ZS_USER", "admin")
ZS_PASS = os.environ.get("ZS_PASS", "admin123456")
_login = postc("/api/auth/login", {"username": ZS_USER, "password": ZS_PASS})
assert _login.get("code") == 0, f"登录失败：{_login}"
# 登录成功会换发新的 CSRF token，需要重新取一次
tok = get("/api/csrf")["token"]

print("=" * 60, "\n1) 页面渲染")
for p in ["/assistant", "/tools/cvss", "/", "/reports"]:
    code = op.open(BASE + p, timeout=15).getcode()
    check(f"页面 {p} 返回200", code == 200, str(code))

print("=" * 60, "\n2) CVSS v3.1 计算（FIRST.org 标准向量）")
cases = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", 8.5, "High"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", None, "Low"),
]
for vec, expect, rating in cases:
    r = postc("/api/tools/cvss", {"vector": vec})
    ok = r.get("code") == 0
    sc = r.get("data", {}).get("base_score")
    rt = r.get("data", {}).get("rating")
    exact = (expect is None) or abs((sc if sc is not None else -99) - expect) < 0.05
    check(f"CVSS {vec.split('/')[1:]} -> {sc} {rt}", ok and exact and rt == rating,
          f"expect {expect} {rating}")
r = postc("/api/tools/cvss", {"vector": "CVSS:3.1/AV:X/AC:L"})
check("非法 CVSS 向量被拒绝", r.get("code") == 1)

print("=" * 60, "\n3) 扫描器结果文件解析")
nuclei_jsonl = (
    json.dumps({"template-id":"sqli","info":{"name":"SQL Injection","severity":"high"},
                "matched-at":"http://demo-tech.com/news?id=1"}) + "\n" +
    json.dumps({"template-id":"xss","info":{"name":"Reflected XSS","severity":"medium"},
                "matched-at":"http://demo-tech.com/search?q=test"})
).encode()
r = post_raw("/api/scanner/parse",
             b"------b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"nuclei.jsonl\"\r\n"
             b"Content-Type: application/octet-stream\r\n\r\n" + nuclei_jsonl + b"\r\n------b--\r\n",
             "multipart/form-data; boundary=----b")
check("Nuclei JSONL 解析 2 条", r.get("code") == 0 and r["data"]["count"] == 2,
      f"source={r.get('data',{}).get('source')}")
check("Nuclei 等级统计 high=1/medium=1",
      r.get("data", {}).get("severity_stats", {}).get("high") == 1 and
      r["data"]["severity_stats"].get("medium") == 1)

generic_json = json.dumps({"vulnerabilities":[
    {"name":"弱口令","target":"http://a.com/login","risk":"高危"},
    {"name":"信息泄露","url":"http://a.com/.git","level":"low"}]}).encode()
r = post_raw("/api/scanner/parse",
             b"------c\r\nContent-Disposition: form-data; name=\"file\"; filename=\"scan.json\"\r\n\r\n"
             + generic_json + b"\r\n------c--\r\n",
             "multipart/form-data; boundary=----c")
check("通用 JSON 递归嗅探 2 条", r.get("code") == 0 and r["data"]["count"] == 2)

txt = b"Found SQLi at http://target.com/u?id=1 (CRITICAL)\nAnother issue: weak password"
r = post_raw("/api/scanner/parse",
             b"------d\r\nContent-Disposition: form-data; name=\"file\"; filename=\"out.txt\"\r\n\r\n"
             + txt + b"\r\n------d--\r\n", "multipart/form-data; boundary=----d")
check("纯文本解析", r.get("code") == 0 and r["data"]["count"] >= 1, str(r.get("data",{}).get("count")))

print("=" * 60, "\n4) 报告质量体检")
r = get("/api/report/qa")
check("全量体检返回结构", r.get("code") == 0 and "average_score" in r["data"] and "results" in r["data"],
      f"avg={r['data'].get('average_score')} total={r['data'].get('total')}")
rid = r["data"]["results"][0]["id"] if r["data"]["results"] else None
if rid:
    r1 = get(f"/api/report/qa-one?id={rid}")
    check("单条体检含 issues/score", r1.get("code") == 0 and "issues" in r1["data"] and 0 <= r1["data"]["score"] <= 100)

print("=" * 60, "\n5) PDF 导出（三模板 + 回读校验）")
ids = [x["id"] for x in get("/api/report/qa")["data"]["results"]]
if ids:
    for tpl in (["normal", "summary"] if len(ids) > 1 else ["normal"]) + ["gongwen"]:
        before = set(os.listdir(EXPORT))
        rr = postc("/api/report/export-pdf", {"report_ids": ids if tpl != "gongwen" else [ids[0]],
                                              "template_key": tpl})
        if rr.get("code") == 0:
            newf = [f for f in os.listdir(EXPORT) if f.endswith(".pdf") and f not in before]
            ok = False; size = 0
            if newf:
                p = os.path.join(EXPORT, newf[0])
                size = os.path.getsize(p)
                with open(p, "rb") as fh:
                    head = fh.read(5)
                ok = head == b"%PDF-" and size > 5000
            check(f"PDF {tpl} 生成且文件头正确", ok, f"{size}B")
        else:
            check(f"PDF {tpl} 生成", False, rr.get("msg", ""))
    # 公文多选应被拒
    if len(ids) > 1:
        rr = postc("/api/report/export-pdf", {"report_ids": ids, "template_key": "gongwen"})
        check("公文模板多选被正确拒绝", rr.get("code") == 1)

print("=" * 60, "\n6) RAG 本地知识检索")
r = postc("/api/ai/retrieve-knowledge", {"query": "SQL 注入", "top_k": 3})
check("RAG 检索返回列表", r.get("code") == 0 and isinstance(r["data"], list),
      f"hit={len(r.get('data', []))}")

print("=" * 60, "\n7) AI 模拟模式（无需 Key）")
r = postc("/api/ai/chat", {"api_key": "sk-test-mock", "stream": False,
                           "history": [{"role": "user", "content": "SQL注入怎么修复？"}]})
check("AI 对话非流式模拟", r.get("code") == 0 and "reply" in r["data"])
# 流式 SSE
req = urllib.request.Request(BASE + "/api/ai/chat",
      data=json.dumps({"api_key":"sk-test-mock","stream":True,
                       "history":[{"role":"user","content":"你好"}]}).encode(),
      headers={"Content-Type":"application/json","X-CSRF-Token":tok}, method="POST")
sse = op.open(req, timeout=30).read().decode()
check("AI 对话 SSE 流式含 [DONE]", "data: [DONE]" in sse and "data:" in sse)

r = postc("/api/ai/fix-code", {"api_key": "sk-test-mock", "vul_name": "SQL注入",
                                "tech_stack": "Python/Flask"})
check("AI 修复方案模拟返回结构化", r.get("code") == 0 and "fix_plan" in r["data"] and "code_samples" in r["data"])

if rid:
    r = postc("/api/ai/grade", {"id": rid, "api_key": "sk-test-mock"})
    check("AI 评分模拟（规则+AI）", r.get("code") == 0 and r["data"].get("rule") and r["data"].get("ai"))

print("=" * 60, "\n8) 仪表盘增强字段")
r = get("/api/dashboard")
check("dashboard 含 monthly_trend", "monthly_trend" in r["data"])
check("dashboard 含 top_units", "top_units" in r["data"])

print("=" * 60)
print(f"\n结果：{len(passed)} 通过 / {len(failed)} 失败")
if failed:
    print("失败项：", failed)
    raise SystemExit(1)
print("全部通过 ✅")
