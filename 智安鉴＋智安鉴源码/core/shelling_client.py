# -*- coding: utf-8 -*-
"""
智安鉴 · 内置漏洞扫描引擎客户端
=================================
对接 Shelling（Hack Scan AI）开放 API，实现「一键发起扫描 → 回收漏洞结果」：

    登录换取 JWT → 创建扫描任务 → 轮询进度 → 拉取漏洞 → 转换为智安鉴统一发现格式

扫描引擎地址与账号已作为内置默认值合入代码（默认 http://host.docker.internal:8000，
即宿主机 8000 端口），界面上无需任何配置；如需指向别处，可在 config.json 的 shelling 段覆盖。
这些信息不写入数据库、不出现在报告与日志中。
"""
import time
import threading
import logging

import requests

from config import get_cfg
from core.scanners import _finding, summarize_findings

logger = logging.getLogger(__name__)

# 令牌提前 60 秒视为过期，避免边界处 401
_TOKEN_SAFETY = 60
_TIMEOUT_CONNECT = 15
# 攻击链分析（可能触发 LLM 重新分析）耗时较长，单独放宽超时
_TIMEOUT_ANALYZE = 180
# 扫描已结束（终态）状态集合
FINISHED = ("COMPLETED", "FAILED", "CANCELLED")

STATUS_CN = {
    "PENDING": "排队中", "RUNNING": "扫描中", "PAUSED": "已暂停",
    "COMPLETED": "已完成", "FAILED": "失败", "CANCELLED": "已取消",
}

# Shelling 侧由智安鉴统一管理的 LLM 配置名（同步时按此名匹配，幂等）
LLM_SYNC_NAME = "智安鉴统一配置"
# 统一配置在 Shelling 侧的默认模型参数（temperature 为其内部表示：实际值 * 100）
LLM_TEMPERATURE = 10      # 0.1，安全分析场景偏确定性
LLM_MAX_TOKENS = 4096
LLM_PRIORITY = 100        # 高于手工创建的其他配置，便于兜底选中


def guess_provider(base_url: str) -> str:
    """按 base_url 推断一个易读的 provider 标识（Shelling 只用它做展示，实际走 OpenAI 兼容协议）"""
    u = (base_url or "").lower()
    if "deepseek" in u:
        return "deepseek"
    if "stepfun" in u:
        return "stepfun"
    if "dashscope" in u or "aliyun" in u:
        return "qwen"
    if "moonshot" in u:
        return "moonshot"
    if "localhost" in u or "127.0.0.1" in u or "host.docker.internal" in u:
        return "local"
    if "openai" in u:
        return "openai"
    return "openai"


def status_cn(status) -> str:
    return STATUS_CN.get(str(status or "").upper(), str(status or "未知"))


class ShellingError(Exception):
    """扫描引擎接口调用异常（msg 为可直接展示给用户的中文信息）"""


def _brief(resp) -> str:
    """从错误响应里提取一句简短说明"""
    try:
        data = resp.json()
    except ValueError:
        return (resp.text or "")[:200]
    if isinstance(data, dict):
        return str(data.get("detail") or data.get("message") or data)[:200]
    return str(data)[:200]


class ShellingClient:
    """扫描引擎 API 客户端（线程安全，内部缓存并自动续期 JWT）"""

    def __init__(self, base_url, username, password, timeout=600):
        self.base_url = (base_url or "").rstrip("/")
        self.username = username or ""
        self.password = password or ""
        self.timeout = int(timeout or 600)
        self._token = None
        self._token_exp = 0.0
        self._lock = threading.Lock()

    # ---------------- 认证 ----------------
    def _login(self):
        if not self.base_url:
            raise ShellingError("未配置扫描引擎服务地址（config.py 内置默认值缺失，可在 config.json 的 shelling 段补充）")
        try:
            r = requests.post(f"{self.base_url}/api/v1/auth/login",
                              json={"username": self.username, "password": self.password},
                              timeout=_TIMEOUT_CONNECT)
        except requests.RequestException as e:
            raise ShellingError(f"无法连接扫描引擎（{self.base_url}）：{e}")
        if r.status_code != 200:
            raise ShellingError(f"扫描引擎登录失败（HTTP {r.status_code}），请核对内置账号密码")
        try:
            tok = r.json()["token"]
            self._token = tok["access_token"]
            self._token_exp = time.time() + float(tok.get("expires_in") or 1800) - _TOKEN_SAFETY
        except (KeyError, TypeError, ValueError) as e:
            raise ShellingError(f"扫描引擎登录响应格式异常：{e}")
        return self._token

    def _get_token(self, force=False):
        with self._lock:
            if force or not self._token or time.time() >= self._token_exp:
                return self._login()
            return self._token

    def _request(self, method, path, json_body=None, retry_on_401=True, timeout=None):
        token = self._get_token()
        try:
            r = requests.request(method, f"{self.base_url}{path}", json=json_body,
                                 headers={"Authorization": f"Bearer {token}"},
                                 timeout=timeout or _TIMEOUT_CONNECT)
        except requests.RequestException as e:
            raise ShellingError(f"请求扫描引擎失败：{e}")
        if r.status_code == 401 and retry_on_401:
            # 令牌过期/被吊销：强制续期后重试一次
            self._get_token(force=True)
            return self._request(method, path, json_body, retry_on_401=False, timeout=timeout)
        if r.status_code >= 400:
            raise ShellingError(f"扫描引擎接口错误（HTTP {r.status_code}）：{_brief(r)}")
        if not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            return {}

    # ---------------- 业务接口 ----------------
    def ping(self):
        """连通性与认证检查，返回可用扫描器信息"""
        data = self._request("GET", "/api/v1/scanners")
        names = data.get("available_scanners") or []
        return {"base_url": self.base_url, "scanner_count": len(names), "scanners": names}

    def create_scan(self, target, scan_type="full", remark="", config=None):
        body = {"target": target, "scan_type": scan_type or "full"}
        if remark:
            body["remark"] = remark
        if config:
            body["config"] = config
        return self._request("POST", "/api/v1/scans", json_body=body)

    def get_scan(self, scan_id):
        return self._request("GET", f"/api/v1/scans/{scan_id}")

    def get_progress(self, scan_id):
        return self._request("GET", f"/api/v1/scans/{scan_id}/progress")

    def get_logs(self, scan_id, since_index=0):
        """拉取扫描过程日志（增量：只取 since_index 之后的新增部分）"""
        return self._request("GET", f"/api/v1/scans/{scan_id}/logs?since_index={int(since_index)}")

    def get_attack_path(self, scan_id, refresh=False):
        """获取攻击链分析结果（阶段 / 攻击链 / 风险评估）；refresh=True 触发 AI 重新分析"""
        flag = "true" if refresh else "false"
        return self._request("GET", f"/api/v1/scans/{scan_id}/attack-path?refresh={flag}",
                             timeout=_TIMEOUT_ANALYZE)

    def get_vulnerabilities(self, scan_id):
        data = self._request("GET", f"/api/v1/scans/{scan_id}/vulnerabilities")
        return data.get("items") or []

    def cancel_scan(self, scan_id):
        return self._request("POST", f"/api/v1/scans/{scan_id}/cancel")

    def delete_scan(self, scan_id):
        """删除扫描任务（引擎会一并清理该任务的漏洞与消息记录）"""
        return self._request("DELETE", f"/api/v1/scans/{scan_id}")

    def update_scan_remark(self, scan_id, remark):
        """修改扫描任务备注"""
        return self._request("PATCH", f"/api/v1/scans/{scan_id}", json_body={"remark": remark})

    def list_scans(self, page=1, page_size=10):
        """列出扫描任务（「AI 漏洞扫描」页的最近扫描列表）"""
        return self._request("GET", f"/api/v1/scans?page={int(page)}&page_size={int(page_size)}")

    # ---------------- LLM 配置（统一 AI 配置用）----------------
    def list_llm_configs(self):
        """列出 Shelling 侧全部 LLM 配置"""
        data = self._request("GET", "/api/v1/settings/llm")
        return data.get("items") or []

    def create_llm_config(self, name, model, api_base_url=None, api_key=None,
                          provider=None, temperature=LLM_TEMPERATURE,
                          max_tokens=LLM_MAX_TOKENS,
                          active_for_main_agent=True, active_for_sub_agent=True,
                          priority=LLM_PRIORITY):
        body = {
            "name": name,
            "provider": provider or guess_provider(api_base_url or ""),
            "api_base_url": api_base_url or None,
            "api_key": api_key or None,
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "active_for_main_agent": bool(active_for_main_agent),
            "active_for_sub_agent": bool(active_for_sub_agent),
            "priority": priority,
        }
        return self._request("POST", "/api/v1/settings/llm", json_body=body)

    def update_llm_config(self, config_id, **fields):
        return self._request("PATCH", f"/api/v1/settings/llm/{config_id}", json_body=fields)

    def test_llm_config(self, config_id):
        """让 Shelling 用它自己的客户端实测一次（返回 success/message/error）"""
        return self._request("POST", f"/api/v1/settings/llm/{config_id}/test")

    def sync_llm_config(self, base_url, api_key, model, name=LLM_SYNC_NAME):
        """
        把智安鉴的 AI 配置同步到 Shelling（幂等）：
          按固定名称查找 → 存在则更新，不存在则新建 → 激活为主 Agent + 子 Agent 共用
        返回 {"action": "created|updated", "config": {...}, "took_over": [...]}
        """
        base_url = (base_url or "").strip()
        model = (model or "").strip()
        if not base_url:
            raise ShellingError("智安鉴未配置 AI Base URL，无法同步到 Shelling")
        if not model:
            raise ShellingError("智安鉴未配置 AI 模型，无法同步到 Shelling")

        fields = {
            "provider": guess_provider(base_url),
            "api_base_url": base_url,
            "api_key": (api_key or "").strip() or None,
            "model": model,
            "temperature": LLM_TEMPERATURE,
            "max_tokens": LLM_MAX_TOKENS,
            "active_for_main_agent": True,
            "active_for_sub_agent": True,
            "is_enabled": True,
            "priority": LLM_PRIORITY,
        }

        configs = self.list_llm_configs()
        existing = next((c for c in configs if (c.get("name") or "").strip() == name), None)
        # 记录本次接管前，Shelling 侧原有的生效配置，便于如实反馈
        took_over = [c.get("name") for c in configs
                     if (c.get("active_for_main_agent") or c.get("active_for_sub_agent"))
                     and (c.get("name") or "").strip() != name]

        if existing:
            cfg = self.update_llm_config(existing["id"], **fields)
            action = "updated"
        else:
            # Shelling 的创建接口不接受 is_enabled（新建默认即为启用），仅在更新时下发
            create_fields = {k: v for k, v in fields.items() if k != "is_enabled"}
            cfg = self.create_llm_config(name=name, **create_fields)
            action = "created"
        return {"action": action, "config": cfg, "took_over": took_over}

    def llm_status(self):
        """汇总 Shelling 侧 LLM 配置状态，供智安鉴设置页展示"""
        try:
            configs = self.list_llm_configs()
        except ShellingError as e:
            return {"reachable": False, "error": str(e), "total": 0, "synced": None,
                    "active_main": None, "active_sub": None}
        synced = next((c for c in configs if (c.get("name") or "").strip() == LLM_SYNC_NAME), None)
        active_main = next((c for c in configs if c.get("active_for_main_agent")), None)
        active_sub = next((c for c in configs if c.get("active_for_sub_agent")), None)

        def brief(c):
            if not c:
                return None
            return {"id": c.get("id"), "name": c.get("name"), "model": c.get("model"),
                    "provider": c.get("provider"), "api_base_url": c.get("api_base_url"),
                    "has_api_key": bool(c.get("has_api_key"))}

        return {"reachable": True, "error": None, "total": len(configs),
                "synced": brief(synced), "active_main": brief(active_main),
                "active_sub": brief(active_sub)}

    def wait_for_scan(self, scan_id, timeout=None, interval=3.0, on_tick=None):
        """阻塞等待扫描结束（供脚本/同步场景使用），返回最终 progress"""
        deadline = time.time() + (timeout or self.timeout)
        while True:
            prog = self.get_progress(scan_id)
            if on_tick:
                on_tick(prog)
            if str(prog.get("status") or "").upper() in FINISHED:
                return prog
            if time.time() >= deadline:
                raise ShellingError(f"扫描超时（超过 {timeout or self.timeout} 秒）")
            time.sleep(interval)


# ---------------- 结果转换 ----------------
def to_findings(items, target=""):
    """
    把 Shelling 的 VulnerabilityResponse 列表转换为智安鉴统一 raw_findings 结构：
        {"source": "shelling", "data": {title, severity, url, evidence, description, raw}}
    """
    findings = []
    for v in items or []:
        if not isinstance(v, dict):
            continue
        location = v.get("location") or target or ""
        evidence = []
        if v.get("evidence"):
            evidence.append(str(v["evidence"]))
        if v.get("category"):
            evidence.append(f"漏洞类别：{v['category']}")
        if v.get("llm_false_positive_score") is not None:
            evidence.append(f"AI 误报评分：{v['llm_false_positive_score']}")
        desc = []
        if v.get("description"):
            desc.append(str(v["description"]))
        if v.get("llm_analysis"):
            desc.append("AI 分析：" + str(v["llm_analysis"]))
        if v.get("llm_remediation"):
            desc.append("整改建议：" + str(v["llm_remediation"]))
        findings.append(_finding(
            "shelling", v.get("name") or "未知漏洞", v.get("severity"),
            location, "\n".join(evidence), "\n".join(desc), raw=v,
        ))
    return findings


def summarize(items, target=""):
    """便捷方法：转换并统计"""
    findings = to_findings(items, target=target)
    return findings, summarize_findings(findings)


# ---------------- 客户端工厂 ----------------
def make_client(base_url=None, username=None, password=None, timeout=None) -> ShellingClient:
    """按传入值（优先）或 config.json 中的 shelling 配置构造客户端"""
    sh = get_cfg().get("shelling") or {}
    return ShellingClient(
        base_url=base_url or sh.get("base_url") or "",
        username=username or sh.get("username") or "",
        password=password or sh.get("password") or "",
        timeout=timeout or sh.get("timeout") or 600,
    )


_default_client = None
_default_lock = threading.Lock()


def get_client() -> ShellingClient:
    """获取进程内复用的默认客户端（缓存 JWT，避免每次请求都登录）"""
    global _default_client
    with _default_lock:
        if _default_client is None:
            _default_client = make_client()
        return _default_client


def reset_client():
    """配置变更后丢弃缓存客户端（连同其 JWT）"""
    global _default_client
    with _default_lock:
        _default_client = None
