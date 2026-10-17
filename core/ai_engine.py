# -*- coding: utf-8 -*-
"""
智安鉴 · AI 智能引擎
=====================
基于 OpenAI 兼容协议（/chat/completions），可对接：
  - DeepSeek        https://api.deepseek.com/v1          deepseek-chat
  - 阶跃星辰 StepFun https://api.stepfun.com/v1          step-3.5-flash
  - 通义千问         https://dashscope.aliyuncs.com/compatible-mode/v1  qwen-turbo
  - OpenAI          https://api.openai.com/v1            gpt-4o-mini
  - 本地 Ollama     http://localhost:11434/v1            qwen2.5:7b

功能：
  1. analyze()         原始漏洞数据 → 结构化报告字段（漏洞名称/等级/描述/危害/检测过程/整改建议/归属证明）
  2. complete_text()   AI 润色/补全漏洞描述、整改建议
  3. classify_assets() AI 辅助资产分类
  4. summarize()       报告摘要 / 结论
模拟模式：api_key 为 sk-test-mock 时返回本地演示数据，便于无 Key 联调。
"""
import json
import re
import time
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class LLMClient:
    """通用 LLM 客户端（OpenAI 兼容协议）"""

    def __init__(self, api_key: str, base_url: str = "https://api.stepfun.com/v1",
                 model: str = "step-3.5-flash", timeout: int = 120, proxy: str = ""):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        # 代理：未显式传入时读取本地配置（应对需要网页认证的网络 / 公司网关 / Clash 等）
        if not proxy:
            try:
                from config import get_cfg
                proxy = (get_cfg().get("ai", {}) or {}).get("proxy", "") or ""
            except Exception:
                proxy = ""
        self.proxy = str(proxy or "").strip()
        self.proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None

    def chat(self, messages: List[Dict[str, Any]], temperature: float = 0.3,
             max_tokens: int = 3000, stream: bool = False):
        import requests as _requests
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": bool(stream),
        }
        url = self.base_url
        if not url.endswith("/chat/completions"):
            url = f"{url}/chat/completions"
        if stream:
            resp = _requests.post(url, headers=headers, json=payload, timeout=self.timeout,
                                  stream=True, proxies=self.proxies)
            if resp.status_code != 200:
                raise RuntimeError(f"AI 请求失败 [{resp.status_code}]: {resp.text[:300]}")
            return resp  # 调用方迭代 SSE

        # 非流式：思考类模型偶发“只生成思考、content 为空”，对空结果自动退避重试
        last_snippet = ""
        for attempt in range(3):
            resp = _requests.post(url, headers=headers, json=payload, timeout=self.timeout,
                                  proxies=self.proxies)
            if resp.status_code != 200:
                raise RuntimeError(f"AI 请求失败 [{resp.status_code}]: {resp.text[:300]}")
            try:
                body = resp.json()
                msg = body["choices"][0]["message"]
                content = (msg.get("content") or msg.get("reasoning_content") or "")
            except Exception:
                raise RuntimeError(f"AI 响应解析失败: {resp.text[:300]}")
            if content.strip():
                return content
            last_snippet = resp.text[:300]
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"AI 连续返回空内容（模型可能仅生成思考过程未输出结论），请重试。原始响应：{last_snippet}")


def _scan_balanced_json(text: str):
    """从第一个 { 或 [ 起按括号配平提取首个完整 JSON 值（忽略字符串内括号与转义）"""
    open_idx = min([i for i in (text.find("{"), text.find("[")) if i != -1], default=-1)
    if open_idx == -1:
        return None
    pair = {"{": "}", "[": "]"}
    stack = []
    in_str = False
    esc = False
    quote = ""
    for i in range(open_idx, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
        elif ch in pair:
            stack.append(pair[ch])
        elif ch in ("}", "]"):
            if stack and stack[-1] == ch:
                stack.pop()
                if not stack:
                    return text[open_idx:i + 1]
    return None


def extract_json(text: str):
    """从 LLM 输出中稳健提取 JSON（容忍代码块围栏、前后说明文字）"""
    if not text:
        return None
    text = text.strip()
    # 去掉 ```json ... ``` 围栏
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # 括号配平提取首个完整 JSON 值（最稳健，能处理前后夹带文字）
    balanced = _scan_balanced_json(text)
    if balanced:
        try:
            return json.loads(balanced)
        except json.JSONDecodeError:
            pass
    # 尝试截取第一个 [ 到最后一个 ]
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return None


# ---------------- 主分析器 ----------------

class AIReportAnalyzer:
    SEVERITY_MAP = ["critical", "high", "medium", "low", "info", "unknown"]

    def __init__(self, llm: LLMClient = None):
        self.llm = llm

    def _is_image_url(self, val: str) -> bool:
        if not isinstance(val, str):
            return False
        val = val.strip()
        if val.startswith("data:image/"):
            return True
        if val.startswith(("http://", "https://")):
            return val.lower().split("?")[0].endswith(
                (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"))
        return False

    def _extract_images(self, raw_findings: List[Dict]) -> List[str]:
        images = []
        fields = ["image", "images", "screenshot", "img", "prove", "evidence",
                  "picture", "photo", "url", "extra_images"]
        def scan(obj):
            if not isinstance(obj, dict):
                return
            for f in fields:
                val = obj.get(f)
                if val is None:
                    continue
                if isinstance(val, list):
                    for v in val:
                        if self._is_image_url(v):
                            images.append(v)
                elif self._is_image_url(val):
                    images.append(val)
            if isinstance(obj.get("data"), dict):
                scan(obj["data"])
        for rf in raw_findings:
            scan(rf)
        seen, unique = set(), []
        for img in images:
            if img not in seen:
                seen.add(img)
                unique.append(img)
        return unique[:10]

    def _build_prompt(self, raw_findings, asset_info, extra_images=None,
                      existing_values=None, raw_text="", mode="report", knowledge=None) -> str:
        if mode == "report":
            return self._build_report_prompt(raw_findings, asset_info, extra_images,
                                             existing_values, raw_text, knowledge or [])
        if mode == "complete":
            return self._build_complete_prompt(asset_info, existing_values or {})
        if mode == "classify":
            return self._build_classify_prompt(raw_text)
        if mode == "summary":
            return self._build_summary_prompt(raw_findings)
        return self._build_report_prompt(raw_findings, asset_info, extra_images, existing_values, raw_text)

    def _build_report_prompt(self, raw_findings, asset_info, extra_images, existing_values, raw_text, knowledge=None):
        prompt = (
            "你是一名专业的网络安全渗透测试报告撰写专家。请分析以下原始漏洞数据，"
            "生成符合专业规范、可直接用于正式报告的结构化内容。\n\n"
            "目标资产：\n"
            f"- 单位名称：{asset_info.get('unit_name', '未知')}\n"
            f"- 系统名称：{asset_info.get('system_name', '未知')}\n"
            f"- 域名：{asset_info.get('domain', '未知')}\n"
            f"- 地址：{asset_info.get('address', '未知')}\n\n"
            f"原始发现数据（{len(raw_findings)} 项）：\n"
        )
        for i, rf in enumerate(raw_findings, 1):
            s = json.dumps(rf, ensure_ascii=False)[:1200]
            prompt += f"{i}. {s}\n"
        if raw_text:
            prompt += f"\n原始文本描述：\n{raw_text[:4000]}\n"
        images = self._extract_images(raw_findings)
        if extra_images:
            for img in extra_images:
                if img not in images:
                    images.append(img)
        if images:
            prompt += (f"\n注意：原始数据中包含 {len(images)} 张图片证据，已同步提供给你。"
                       "请在 detail 和 prove 字段中用 <img src='__AI_IMG_{n}__'> 引用图片，n 从 1 开始。\n")
        if existing_values and any(v for v in existing_values.values()):
            prompt += "\n已有表单内容（请优先保留并完善，不要丢弃）：\n"
            for k, v in existing_values.items():
                if v:
                    prompt += f"- {k}: {str(v)[:500]}\n"
        if knowledge:
            prompt += format_knowledge_for_prompt(knowledge)

        prompt += """
请为每个发现输出一个对象，字段：
- vul_name: 漏洞名称（规范命名，如“SQL 注入漏洞”）
- severity: critical/high/medium/low/info/unknown
- address: 漏洞地址（URL/IP/路径）
- description: 漏洞描述（技术原理 + 触发条件，清晰准确）
- harm: 漏洞危害（业务影响，结合资产重要性）
- detail: 检测过程（复现步骤，含证据截图引用）
- suggestion: 整改建议（分条、可落地）
- prove: 归属证明（如何确认该漏洞属于该系统）

只返回 JSON 数组，不要输出任何其他文字：
[
  {"vul_name": "...", "severity": "...", "address": "...", "description": "...",
   "harm": "...", "detail": "...", "suggestion": "...", "prove": "..."}
]
"""
        return prompt

    def _build_complete_prompt(self, asset_info, existing_values):
        return (
            "你是一名专业的网络安全报告撰写助手。请根据已有信息，补全/润色一份漏洞报告的内容。\n"
            f"单位名称：{asset_info.get('unit_name', '未知')}\n"
            f"系统名称：{asset_info.get('system_name', '未知')}\n"
            f"漏洞名称：{existing_values.get('vul_name', '')}\n"
            f"漏洞等级：{existing_values.get('severity', 'unknown')}\n"
            f"已有漏洞描述：{existing_values.get('description', '')[:1500]}\n"
            f"已有危害分析：{existing_values.get('harm', '')[:1500]}\n"
            f"已有检测过程：{existing_values.get('detail', '')[:1500]}\n"
            f"已有整改建议：{existing_values.get('suggestion', '')[:1500]}\n\n"
            "请输出 JSON 对象，仅包含需要补全/润色的字段（未提供的字段不要输出）：\n"
            '{"description": "...", "harm": "...", "detail": "...", "suggestion": "..."}\n'
        )

    def _build_classify_prompt(self, raw_text):
        return (
            "请将以下资产文本逐行分类，类别从：URL / 域名 / IP / IP:端口 / 邮箱 / 手机号 / 文件路径 / 其他 中选择。\n"
            f"文本内容：\n{raw_text[:4000]}\n\n"
            "输出 JSON 数组：[{\"input\": \"原文\", \"type\": \"类别\"}]\n"
        )

    def _build_summary_prompt(self, findings):
        summary = []
        for f in findings[:30]:
            summary.append({"vul_name": f.get("vul_name"), "severity": f.get("severity"),
                            "address": f.get("address")})
        return (
            "你是一名网络安全专家。请对以下漏洞清单生成一段不超过 300 字的总结（总体风险态势、"
            "高危问题、重点整改方向）：\n"
            + json.dumps(summary, ensure_ascii=False) + "\n直接输出总结文本，不要输出 JSON。\n"
        )

    def analyze(self, raw_findings, asset_info, extra_images=None,
                raw_text="", existing_values=None, use_rag=True) -> List[Dict]:
        # RAG：从原始数据构造检索 query
        knowledge = []
        if use_rag:
            query_parts = [asset_info.get("system_name", ""), raw_text[:200]]
            for rf in (raw_findings or [])[:5]:
                d = rf.get("data", rf) if isinstance(rf, dict) else {}
                query_parts.append(str(d.get("title") or d.get("name") or d.get("vul_name") or ""))
            knowledge = retrieve_similar_vulns(" ".join(p for p in query_parts if p))
        prompt = self._build_prompt(raw_findings, asset_info, extra_images,
                                    existing_values, raw_text, mode="report", knowledge=knowledge)
        content = self.llm.chat([{"role": "user", "content": prompt}], max_tokens=8192)
        data = extract_json(content)
        if not isinstance(data, list):
            raise RuntimeError("AI 未返回有效的 JSON 数组，请重试或更换模型")
        self.last_knowledge = knowledge
        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "unknown")).lower()
            if sev not in self.SEVERITY_MAP:
                sev = "unknown"
            findings.append({
                "vul_name": str(item.get("vul_name", "未知漏洞")).strip()[:200],
                "severity": sev,
                "address": str(item.get("address", "")).strip(),
                "description": str(item.get("description", "")).strip(),
                "harm": str(item.get("harm", "")).strip(),
                "detail": str(item.get("detail", "")).strip(),
                "suggestion": str(item.get("suggestion", "")).strip(),
                "prove": str(item.get("prove", "")).strip(),
            })
        # 图片引用占位符替换为可访问 URL
        images = self._extract_images(raw_findings)
        if extra_images:
            images.extend(extra_images)
        for i, img in enumerate(images, 1):
            for f in findings:
                f["detail"] = f["detail"].replace(f"__AI_IMG_{i}__", img)
                f["prove"] = f["prove"].replace(f"__AI_IMG_{i}__", img)
        return findings

    def complete_text(self, asset_info, existing_values) -> Dict:
        prompt = self._build_prompt([], asset_info, None, existing_values, "", mode="complete")
        content = self.llm.chat([{"role": "user", "content": prompt}], temperature=0.4)
        data = extract_json(content)
        return data if isinstance(data, dict) else {}

    def classify(self, raw_text) -> List[Dict]:
        prompt = self._build_prompt([], {}, None, None, raw_text, mode="classify")
        content = self.llm.chat([{"role": "user", "content": prompt}], temperature=0.1)
        data = extract_json(content)
        return data if isinstance(data, list) else []

    def summarize(self, findings) -> str:
        prompt = self._build_summary_prompt(findings)
        return self.llm.chat([{"role": "user", "content": prompt}], temperature=0.3, max_tokens=600).strip()

    # ---------------- AI 安全专家对话（流式） ----------------
    EXPERT_SYSTEM = (
        "你是「智安鉴」内置的网络安全专家助手，拥有多年渗透测试、代码审计与应急响应经验，"
        "熟悉 OWASP Top 10、CWE、常见中间件与主流漏洞原理。回答要求：\n"
        "1. 专业、准确、可落地，优先给出检测思路、验证方法与修复方案；\n"
        "2. 涉及攻击利用时仅用于授权安全测试与防御目的，不提供破坏性、绕过检测的违法内容；\n"
        "3. 结构清晰，必要时分条说明；代码注明语言与适用场景；\n"
        "4. 若信息不足，主动说明需要补充的信息。"
    )

    def _expert_system_prompt(self, history):
        # 组装安全助手 system 提示词：人设 + 当前系统时间 + 本地知识库 RAG + 作答范围
        from datetime import datetime
        brk = chr(10)
        parts = [self.EXPERT_SYSTEM]
        try:
            now = datetime.now()
            week = "一二三四五六日"[now.weekday()]
            parts.append(
                "【运行环境信息】" + brk +
                "当前系统本地时间：" + now.strftime("%Y年%m月%d日 %H:%M:%S") + "，星期" + week + "。" + brk +
                "当用户询问当前时间、日期、星期、今天几号等，直接依据该时间准确回答，不要再说无法获取实时时间。"
            )
        except Exception:
            pass
        try:
            last_user = ""
            for h in reversed(history or []):
                if h.get("role") == "user":
                    last_user = h.get("content", "") or ""
                    break
            if last_user.strip():
                ks = retrieve_similar_vulns(last_user, top_k=3)
                ktext = format_knowledge_for_prompt(ks)
                if ktext:
                    parts.append(ktext + "若用户问题与上述本地知识库条目相关，优先参考其定级、危害与整改口径；不相关则按专业知识正常回答。")
        except Exception:
            pass
        parts.append("【作答范围】对网络安全之外的通用问题（如时间日期、常识、写作、办公等）也应正常友好回答；只有对必须实时联网而系统未提供的数据（如实时天气、实时股价、最新新闻）才简要说明无法实时获取，不要泛化拒绝其它问题。")
        return (brk + brk).join(parts)

    def _expert_messages(self, history):
        messages = [{"role": "system", "content": self._expert_system_prompt(history)}]
        for h in history[-12:]:
            role = h.get("role", "user")
            if role not in ("user", "assistant", "system"):
                role = "user"
            messages.append({"role": role, "content": h.get("content", "")})
        return messages

    def chat_stream(self, history):
        # 多轮对话流式输出，history: [{role, content}]，返回 requests 流响应
        return self.llm.chat(self._expert_messages(history), temperature=0.4, max_tokens=4096, stream=True)

    def chat(self, history):
        # 多轮对话非流式
        return self.llm.chat(self._expert_messages(history), temperature=0.4, max_tokens=4096)

    # ---------------- AI 修复方案生成 ----------------
    def fix_code(self, vul_name, tech_stack="", description="", address=""):
        knowledge = retrieve_similar_vulns(f"{vul_name} {description}")
        prompt = (
            "你是资深应用安全工程师。请针对以下漏洞给出可直接落地的修复方案与示例代码。\n"
            f"漏洞名称：{vul_name}\n技术栈/语言：{tech_stack or '未知（请给出通用方案并补充常见语言示例）'}\n"
            f"漏洞地址：{address or '未知'}\n漏洞描述：{description[:800]}\n"
        )
        if knowledge:
            prompt += format_knowledge_for_prompt(knowledge)
        prompt += (
            "\n请按以下 JSON 结构输出（不要输出多余文字、不要输出思考过程）：\n"
            '{"root_cause": "根因分析（简明）", "fix_plan": ["修复步骤1","修复步骤2","修复步骤3"], '
            '"code_samples": [{"language":"语言","title":"标题","code":"修复后的关键代码"}], '
            '"verify": "修复验证方法", "defense_in_depth": ["加固建议"]}\n'
            "要求：code_samples 只给 1~2 段最关键的修复后代码，每段不超过 30 行、聚焦核心写法，"
            "不要罗列错误示例与大段铺垫；fix_plan 控制在 3~5 条。\n"
        )
        content = self.llm.chat([{"role": "user", "content": prompt}], temperature=0.3, max_tokens=8192)
        data = extract_json(content)
        return data if isinstance(data, dict) else {"root_cause": content}

    # ---------------- AI 报告评分点评 ----------------
    def grade_report(self, report: dict, rule_issues: list):
        prompt = (
            "你是网络安全报告评审专家。请从专业性、规范性、可复现性、证据充分性角度，"
            "对下面的漏洞报告进行点评。\n"
            f"单位：{report.get('unit_name','')}；系统：{report.get('system_name','')}；"
            f"漏洞：{report.get('vul_name','')}；等级：{report.get('severity','')}\n"
            f"地址：{report.get('address','')}\n描述：{str(report.get('description',''))[:600]}\n"
            f"危害：{str(report.get('harm',''))[:400]}\n"
            f"检测过程：{str(report.get('detail',''))[:800]}\n"
            f"整改建议：{str(report.get('suggestion',''))[:600]}\n"
            f"本地规则引擎检出问题：{json.dumps(rule_issues, ensure_ascii=False)[:600]}\n\n"
            "请输出 JSON：{\"score\": 0到100的整数, \"highlights\": \"亮点\", "
            "\"problems\": [\"问题\"], \"suggestions\": [\"改进建议\"]}，只输出 JSON。"
        )
        content = self.llm.chat([{"role": "user", "content": prompt}], temperature=0.2, max_tokens=8192)
        data = extract_json(content)
        return data if isinstance(data, dict) else {"score": None, "highlights": content}


# ---------------- RAG 本地漏洞知识库检索 ----------------

def _ngrams(text: str, n: int = 2):
    """简易中文 bigram 分词，用于本地相似度检索（无需向量模型）"""
    text = re.sub(r"[\s\W_0-9]+", "", (text or "").lower())
    if not text:
        return set()
    grams = {text[i:i + n] for i in range(len(text) - n + 1)}
    # 英文/数字 token
    grams.update(t for t in re.findall(r"[a-zA-Z][a-zA-Z0-9_.+-]{2,}|\d+", (text or "").lower()))
    return grams


def retrieve_similar_vulns(query: str, top_k: int = 3):
    """从本地漏洞库检索最相似的知识条目（RAG），返回 list[dict]"""
    import database as db
    rows = db.query_all("SELECT name, severity, description, harm, suggestion FROM vulnerabilities")
    if not rows:
        return []
    q_grams = _ngrams(query)
    if not q_grams:
        return []
    scored = []
    for row in rows:
        name = row["name"] or ""
        n_grams = _ngrams(name)
        body_grams = _ngrams(" ".join([row["description"] or "", row["suggestion"] or ""]))
        # 名称权重高
        inter_name = len(q_grams & n_grams)
        inter_body = len(q_grams & body_grams)
        score = inter_name * 3 + inter_body * 0.5
        # 名称直接包含
        if query and query.strip() and query.strip() in name:
            score += 10
        if score > 0:
            scored.append((score, dict(row)))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [item for _, item in scored[:top_k]]


def format_knowledge_for_prompt(knowledge: list) -> str:
    if not knowledge:
        return ""
    lines = ["\n【本地漏洞知识库检索结果（RAG，供参考并保持口径一致，如与实际不符以实测为准）】"]
    for i, k in enumerate(knowledge, 1):
        lines.append(f"知识{i}：《{k.get('name','')}》 等级={k.get('severity','')}")
        if k.get("description"):
            lines.append(f"  描述：{k['description'][:300]}")
        if k.get("harm"):
            lines.append(f"  危害：{k['harm'][:300]}")
        if k.get("suggestion"):
            lines.append(f"  整改建议：{k['suggestion'][:400]}")
    return "\n".join(lines) + "\n"


# ---------------- 模拟模式（无 Key 联调） ----------------

def mock_findings(asset_info, raw_findings, raw_text=""):
    name = "SQL 注入漏洞"
    if raw_findings and isinstance(raw_findings[0], dict):
        d = raw_findings[0].get("data", raw_findings[0])
        name = d.get("title") or d.get("vul_name") or d.get("name") or name
    return [{
        "vul_name": name,
        "severity": "high",
        "address": asset_info.get("address", "https://example.com/login"),
        "description": "应用程序登录接口未对用户输入进行参数化处理，存在 SQL 注入漏洞。攻击者可通过构造恶意 SQL 语句绕过认证并读取数据库敏感数据，实测使用万能密码载荷可成功绕过登录校验。",
        "harm": "攻击者可利用该漏洞获取数据库中的账号、口令、业务数据等敏感信息，造成数据泄露；在特定配置下还可进一步写入文件、控制服务器，危害等级高。",
        "detail": "<p>在登录页面使用如下载荷进行测试：<br><code>admin' OR 1=1--</code><br>系统返回登录成功，证明 SQL 语句拼接存在注入点。</p><p>（演示数据：请在系统设置中配置真实 AI Key 后重新生成）</p>",
        "suggestion": "1. 使用参数化查询或预编译语句，杜绝 SQL 拼接；<br>2. 对输入做严格白名单校验；<br>3. 数据库账户遵循最小权限原则；<br>4. 部署 WAF 并开启 SQL 注入防护规则。",
        "prove": "<p>目标：{address}</p><p>载荷：admin' OR 1=1--</p><p>结果：成功登录系统后台</p>".format(address=asset_info.get("address", "")),
    }]


def mock_summary(findings):
    return ("经检测共发现漏洞 {n} 个，其中高危及以上问题需优先整改。整体风险态势为中等偏上，"
            "建议重点修复注入类与未授权访问类漏洞，并加强访问控制与输入校验，"
            "同步开展安全加固复测。（演示数据）").format(n=len(findings))


def get_ai_engine(api_key, base_url, model, timeout=120):
    """工厂：根据 api_key 返回真实引擎或模拟引擎"""
    if api_key == "sk-test-mock":
        return None  # 由调用方走 mock 分支
    llm = LLMClient(api_key=api_key, base_url=base_url, model=model, timeout=timeout)
    return AIReportAnalyzer(llm=llm)
