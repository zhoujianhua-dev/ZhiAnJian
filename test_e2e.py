# -*- coding: utf-8 -*-
"""智安鉴 端到端功能测试脚本"""
import json
import requests
import os

BASE = "http://127.0.0.1:8080"
s = requests.Session()

def get(path):
    r = s.get(BASE + path, timeout=30)
    return r.status_code, r.json() if "json" in r.headers.get("Content-Type", "") else r.content

def post(path, data=None, files=None):
    r = s.post(BASE + path, json=data, files=files, timeout=60)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text[:300]

# 登录（内置管理员账号，见 database.ensure_default_admin；可用环境变量 ZS_USER / ZS_PASS 覆盖）
ZS_USER = os.environ.get("ZS_USER", "admin")
ZS_PASS = os.environ.get("ZS_PASS", "admin123456")
_, tok = get("/api/csrf")
s.headers["X-CSRF-Token"] = tok["token"]
st, r = post("/api/auth/login", {"username": ZS_USER, "password": ZS_PASS})
assert st == 200 and r.get("code") == 0, f"登录失败（HTTP {st}）：{r}"
# 登录成功会换发新的 CSRF token，需要重新取一次
_, tok = get("/api/csrf")
s.headers["X-CSRF-Token"] = tok["token"]
print("[1] 登录成功（%s）+ CSRF token:" % ZS_USER, tok["token"][:8], "...")

# 2. 批量新增单位
st, r = post("/api/units/add", {"enterprise_name": "测试单位甲\n测试单位乙\n测试单位丙"})
print("[2] 新增单位:", r.get("msg"), r.get("data", {}).get("success_count"))

# 3. 新增标签并关联
st, r = post("/api/tags/add", {"name": "重点测试", "description": "端到端测试", "unit": "测试单位甲\n测试单位乙"})
print("[3] 新增标签:", r.get("msg"))

# 4. 新增域名
st, r = post("/api/domains/edit", {"unit_name": "测试单位甲", "domain": "test-a.com",
                                   "main_licence": "浙ICP备2026000000号-1"})
print("[4] 新增域名:", r.get("msg"))

# 5. 新增漏洞
st, r = post("/api/vulnerability/add", {"name": "SQL 注入漏洞", "severity": "high",
                                        "description": "测试描述", "harm": "测试危害", "suggestion": "1.测试建议"})
print("[5] 新增漏洞:", r.get("msg"))

# 6. 新增报告
st, r = post("/api/report/add", {"unit_name": "测试单位甲", "system_name": "测试系统",
                                 "vul_name": "SQL 注入漏洞", "domain": "test-a.com",
                                 "address": "https://test-a.com/login",
                                 "description": "登录接口存在 SQL 注入。",
                                 "severity": "high",
                                 "detail": "<p>使用载荷 <b>admin' OR 1=1--</b> 复现成功。</p><p>截图见下。</p>",
                                 "suggestion": "1. 参数化查询；2. 输入校验。",
                                 "prove": "<p>目标：https://test-a.com/login</p><p>结果：绕过登录。</p>"})
print("[6] 新增报告:", r.get("msg"), "id:", r.get("id"))

# 7. 报告列表
st, r = get("/api/reports?page=1&limit=10")
print("[7] 报告列表总数:", r.get("count"))

# 8. 导出普通模板
rid = r["data"][0]["id"]
st, r = post("/api/report/export", {"report_ids": [rid], "template_key": "normal", "org_footer": "测试测评中心"})
print("[8] 导出普通模板:", r.get("msg"), r.get("filename"))

# 9. 导出公文模板
st, r = post("/api/report/export", {"report_ids": [rid], "template_key": "gongwen"})
print("[9] 导出公文模板:", r.get("msg"), r.get("filename"))

# 10. 导出汇总模板
st, r = post("/api/report/export", {"report_ids": [rid], "template_key": "summary"})
print("[10] 导出汇总模板:", r.get("msg"), r.get("filename"))

# 11. AI 模拟分析
st, r = post("/api/ai/analyze", {"api_key": "sk-test-mock",
                                 "base_url": "https://api.stepfun.com/v1", "model": "step-3.5-flash",
                                 "asset_info": {"unit_name": "测试单位甲", "system_name": "门户",
                                                "domain": "test-a.com", "address": "https://test-a.com/login"},
                                 "raw_findings": [{"source": "nuclei", "data": {"title": "SQL 注入漏洞", "severity": "high"}}]})
findings = r.get("data", {}).get("findings", []) if st == 200 else []
print("[11] AI 模拟分析:", r.get("msg", "ok"), "findings:", len(findings))

# 12. AI 模拟一键生成
st, r = post("/api/ai/generate", {"api_key": "sk-test-mock",
                                  "base_url": "https://api.stepfun.com/v1", "model": "step-3.5-flash",
                                  "asset_info": {"unit_name": "测试单位乙", "system_name": "后台",
                                                 "domain": "test-b.com", "address": "https://test-b.com/admin"},
                                  "raw_findings": [{"source": "manual", "data": {"title": "未授权访问"}}],
                                  "template_key": "normal"})
print("[12] AI 一键生成:", r.get("msg"), "file:", r.get("filename"))

# 13. 工具-密码
st, r = post("/api/tools/password", {"length": 12, "count": 3})
print("[13] 密码生成:", len(r.get("data", [])))

# 14. 工具-去重
st, r = post("/api/tools/dedup", {"text": "a.com\na.com\nb.com"})
print("[14] 去重:", r.get("count"), "->", r.get("data"))

# 15. 工具-提取域名
st, r = post("/api/tools/urls", {"text": "https://www.example.com/x\n192.168.1.1:8080"})
print("[15] 提取域名:", [(x["input"], x["result"]) for x in r.get("data", [])])

# 16. 工具-AB对比
st, r = post("/api/tools/compare", {"a": "a.com\nb.com\nc.com", "b": "a.com\nd.com"})
print("[16] AB对比: common:", r.get("data", {}).get("common_count"), "onlyA:", r.get("data", {}).get("only_a"))

# 17. 工具-资产分类
st, r = post("/api/tools/classify", {"text": "https://www.example.com\n192.168.1.1\nuser@mail.com"})
print("[17] 资产分类:", r.get("data", {}).get("stats"))

# 18. 演示数据
st, r = post("/api/settings/seed-demo")
print("[18] 演示数据:", r.get("msg"))

# 19. 外观设置保存
st, r = post("/api/settings/appearance", {"app_title": "智安鉴", "app_subtitle": "智能安全检测与漏洞报告系统",
                                          "theme_color": "#2563eb", "background": "", "background_overlay": 0.35,
                                          "background_blur": 0, "report_header": "网络安全测试报告", "export_org": ""})
print("[19] 外观设置:", r.get("msg"))

# 20. 导出历史
st, r = get("/api/report/exports")
print("[20] 导出历史条数:", len(r.get("data", [])))

print("\n全部测试完成 ✔")
