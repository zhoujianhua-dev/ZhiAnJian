# -*- coding: utf-8 -*-
"""智安鉴 登录 / 权限 / 用户管理 回归测试（真实 HTTP）"""
import os

import requests

BASE = os.environ.get("ZS_BASE", "http://127.0.0.1:8080")
ADMIN_USER = os.environ.get("ZS_USER", "admin")
ADMIN_PASS = os.environ.get("ZS_PASS", "admin123456")

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {extra}")


def csrf(s):
    return s.get(BASE + "/api/csrf", timeout=20).json()["token"]


def login(s, user, pwd):
    r = s.post(BASE + "/api/auth/login", json={"username": user, "password": pwd},
               headers={"X-CSRF-Token": csrf(s)}, timeout=20)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {}


def post(s, path, obj):
    r = s.post(BASE + path, json=obj, headers={"X-CSRF-Token": csrf(s)}, timeout=30)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {}


def get(s, path, allow_redirects=True):
    r = s.get(BASE + path, timeout=20, allow_redirects=allow_redirects)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text[:120]


def find_id(s, username):
    st, j = get(s, "/api/users")
    for u in (j.get("data") or []):
        if u["username"] == username:
            return u["id"]
    return None


print("=" * 60, "\n1) 未登录时的访问控制")
anon = requests.Session()
st, _ = get(anon, "/", allow_redirects=False)
check("未登录访问首页跳转登录页", st == 302, str(st))
st, j = get(anon, "/api/dashboard")
check("未登录访问接口返回 401 + need_login", st == 401 and j.get("need_login") is True,
      f"{st} {j.get('msg')}")
st, _ = get(anon, "/login", allow_redirects=False)
check("登录页可匿名访问", st == 200, str(st))
st, _ = get(anon, "/static/js/app.js")
check("静态资源免登录", st == 200, str(st))
st, j = post(anon, "/api/units/add", {"enterprise_name": "未登录注入测试"})
check("未登录不能调用业务写接口", st == 401, str(st))

print("=" * 60, "\n2) 登录校验")
st, j = login(requests.Session(), ADMIN_USER, "definitely-wrong-pwd")
check("错误密码被拒绝", st == 401 and j.get("code") == 1, f"{st} {j.get('msg')}")
st, j = login(requests.Session(), "no_such_user_zzz", "whatever123")
check("不存在的用户名被拒绝", st == 401, f"{st} {j.get('msg')}")
st, j = login(requests.Session(), ADMIN_USER, "")
check("空密码被拒绝", st == 400, str(st))

admin = requests.Session()
st, j = login(admin, ADMIN_USER, ADMIN_PASS)
check("管理员登录成功", st == 200 and j.get("code") == 0, f"{st} {j.get('msg')}")
st, _ = get(admin, "/")
check("登录后可访问首页", st == 200, str(st))
st, j = get(admin, "/api/auth/me")
check("me 返回当前用户且不含密码哈希",
      st == 200 and j["data"]["username"] == ADMIN_USER and "password_hash" not in j["data"],
      j.get("data", {}).get("role_cn"))
st, _ = get(admin, "/login", allow_redirects=False)
check("已登录访问登录页跳回首页", st == 302, str(st))

print("=" * 60, "\n3) 用户管理（管理员）")
st, j = get(admin, "/api/users")
check("管理员可读取用户列表", st == 200 and j.get("count", 0) >= 1, f"count={j.get('count')}")
st, _ = get(admin, "/users")
check("管理员可打开用户管理页", st == 200, str(st))

UNAME = "qa_user_01"
old = find_id(admin, UNAME)
if old:
    post(admin, "/api/users/delete", {"id": old})

st, j = post(admin, "/api/users/add", {"username": UNAME, "password": "qa-pass-123",
                                       "display_name": "测试用户", "role": "user"})
check("新增普通用户", st == 200 and j.get("code") == 0, j.get("msg"))
UID = find_id(admin, UNAME)
check("新用户出现在列表中", UID is not None, f"id={UID}")
st, j = post(admin, "/api/users/add", {"username": UNAME, "password": "qa-pass-123"})
check("重复用户名被拒绝", st == 400 and j.get("code") == 1, j.get("msg"))
st, j = post(admin, "/api/users/add", {"username": "ab", "password": "qa-pass-123"})
check("过短用户名被拒绝", st == 400, j.get("msg"))
st, j = post(admin, "/api/users/add", {"username": "qa_user_02", "password": "123"})
check("过短密码被拒绝", st == 400, j.get("msg"))
st, j = post(admin, "/api/users/add", {"username": "qa_user_02", "password": "qa-pass-123",
                                       "role": "superuser"})
check("非法角色被拒绝", st == 400, j.get("msg"))

print("=" * 60, "\n4) 普通用户权限")
user = requests.Session()
st, j = login(user, UNAME, "qa-pass-123")
check("新用户可登录", st == 200 and j.get("code") == 0, j.get("msg"))
st, j = get(user, "/api/users")
check("普通用户读用户列表被拒 403", st == 403 and j.get("code") == 1, f"{st} {j.get('msg')}")
st, _ = get(user, "/users")
check("普通用户打开用户管理页被拒 403", st == 403, str(st))
st, j = get(user, "/api/dashboard")
check("普通用户可正常使用业务功能", st == 200 and j.get("code") == 0, str(st))
st, j = post(user, "/api/users/add", {"username": "qa_hack_01", "password": "hack-pass-1"})
check("普通用户不能新增账号 403", st == 403, str(st))
st, j = post(user, "/api/users/delete", {"id": UID})
check("普通用户不能删除账号 403", st == 403, str(st))

print("=" * 60, "\n5) 修改自己的密码")
st, j = post(user, "/api/auth/password", {"old_password": "bad-old", "new_password": "qa-new-pass-1"})
check("原密码错误被拒绝", st == 400, j.get("msg"))
st, j = post(user, "/api/auth/password", {"old_password": "qa-pass-123", "new_password": "123"})
check("新密码过短被拒绝", st == 400, j.get("msg"))
st, j = post(user, "/api/auth/password", {"old_password": "qa-pass-123", "new_password": "qa-new-pass-1"})
check("修改密码成功", st == 200 and j.get("code") == 0, j.get("msg"))
st, j = get(user, "/api/auth/me")
check("改密后当前会话仍然有效", st == 200 and j.get("code") == 0, str(st))
st, _ = login(requests.Session(), UNAME, "qa-pass-123")
check("旧密码不再可用", st == 401, str(st))
st, j = login(requests.Session(), UNAME, "qa-new-pass-1")
check("新密码可登录", st == 200 and j.get("code") == 0, j.get("msg"))

print("=" * 60, "\n6) 管理员重置密码 / 停用 / 启用")
live = requests.Session()
login(live, UNAME, "qa-new-pass-1")
st, j = post(admin, "/api/users/update", {"id": UID, "password": "reset-by-admin-1"})
check("管理员重置密码", st == 200 and j.get("code") == 0, j.get("msg"))
st, _ = get(live, "/api/dashboard")
check("重置后该用户原有会话立即失效", st == 401, str(st))
st, j = login(requests.Session(), UNAME, "reset-by-admin-1")
check("重置后的密码可登录", st == 200 and j.get("code") == 0, j.get("msg"))

live2 = requests.Session()
login(live2, UNAME, "reset-by-admin-1")
st, j = post(admin, "/api/users/update", {"id": UID, "is_active": 0})
check("管理员停用账号", st == 200 and j.get("code") == 0, j.get("msg"))
st, j = login(requests.Session(), UNAME, "reset-by-admin-1")
check("停用后无法登录", st == 403, f"{st} {j.get('msg')}")
st, _ = get(live2, "/api/dashboard")
check("停用后原有会话立即失效", st == 401, str(st))
st, j = post(admin, "/api/users/update", {"id": UID, "is_active": 1, "remark": "回归测试账号"})
check("管理员重新启用账号", st == 200 and j.get("code") == 0, j.get("msg"))
st, j = get(admin, "/api/users")
row = [u for u in j["data"] if u["id"] == UID][0]
check("备注与状态已保存", row["remark"] == "回归测试账号" and row["is_active"] == 1, str(row["remark"]))

print("=" * 60, "\n7) 管理员自我保护")
st, j = get(admin, "/api/auth/me")
me_id = j["data"]["id"]
st, j = post(admin, "/api/users/update", {"id": me_id, "is_active": 0})
check("不能停用当前登录账号", st == 400, j.get("msg"))
st, j = post(admin, "/api/users/update", {"id": me_id, "role": "user"})
check("不能把自己降级为普通用户", st == 400, j.get("msg"))
st, j = post(admin, "/api/users/delete", {"id": me_id})
check("不能删除当前登录账号", st == 400, j.get("msg"))

print("=" * 60, "\n8) 删除账号与退出登录")
st, j = post(admin, "/api/users/delete", {"id": UID})
check("管理员删除账号", st == 200 and j.get("code") == 0, j.get("msg"))
st, _ = login(requests.Session(), UNAME, "reset-by-admin-1")
check("已删除账号无法登录", st == 401, str(st))
st, j = post(admin, "/api/users/delete", {"id": 999999})
check("删除不存在的账号返回 404", st == 404, str(st))

st, j = post(admin, "/api/auth/logout", {})
check("退出登录成功", st == 200 and j.get("code") == 0, j.get("msg"))
st, j = get(admin, "/api/dashboard")
check("退出后接口返回 401", st == 401, str(st))
st, _ = get(admin, "/", allow_redirects=False)
check("退出后页面跳登录页", st == 302, str(st))

print("=" * 60)
print(f"\n结果：{len(passed)} 通过 / {len(failed)} 失败")
if failed:
    print("失败项：" + "；".join(failed))
    raise SystemExit(1)
print("全部通过 ✅")
