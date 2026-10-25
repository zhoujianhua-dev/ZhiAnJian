import json
import re
from typing import Optional, Callable, Awaitable
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from loguru import logger

from app.core.config import get_settings
from app.core.database import AsyncSessionLocal
from llm.tools import get_tool, get_tools_schema, ToolResult
from llm.skill_loader import load_skills_from_db, execute_skill, get_skills_schema, SkillInfo
from llm.web_search import WebSearchTool, WEB_SEARCH_SCHEMA

settings = get_settings()


# ask_user 工具的 schema
ASK_USER_SCHEMA = {
    "name": "ask_user",
    "description": "向用户提问并等待回复。当你遇到问题需要用户决策、需要更多信息、或者需要用户确认时使用此工具。",
    "parameters": {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": "要问用户的问题"
            },
            "context": {
                "type": "string",
                "description": "问题的背景说明，帮助用户理解情况"
            },
            "options": {
                "type": "array",
                "items": {"type": "string"},
                "description": "可选的选项列表，如果问题有明确的选择"
            }
        },
        "required": ["question"]
    }
}


class AgentPauseException(Exception):
    """Agent 暂停异常，用于中断执行流程"""
    def __init__(self, question: str, context: str = None, options: list[str] = None, agent_state: dict = None):
        self.question = question
        self.context = context
        self.options = options
        self.agent_state = agent_state
        super().__init__(f"Agent paused: {question}")


class AgentThought(BaseModel):
    """Agent 思考过程"""
    analysis: str = Field(description="对当前情况的分析")
    plan: str = Field(description="下一步计划")
    tool_name: Optional[str] = Field(description="要调用的工具名称", default=None)
    tool_args: Optional[dict] = Field(description="工具参数", default=None)
    is_complete: bool = Field(description="是否完成测试", default=False)
    final_summary: Optional[str] = Field(description="最终总结", default=None)
    
    class Config:
        # 允许额外字段
        extra = "allow"


def _stringify_content(content) -> str:
    """将不同 LLM content 格式统一转换为字符串"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content") or item.get("message")
                if text is not None:
                    parts.append(_stringify_content(text))
                else:
                    parts.append(json.dumps(item, ensure_ascii=False))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part)
    if isinstance(content, dict):
        text = content.get("text") or content.get("content")
        if text is not None:
            return _stringify_content(text)
        message = content.get("message")
        if isinstance(message, dict):
            return _stringify_content(message.get("content"))
        return json.dumps(content, ensure_ascii=False)
    return str(content)


class SecurityAgent:
    """AI 驱动的安全测试代理"""
    
    def __init__(
        self, 
        target: str,
        scan_context: dict,
        log_callback: Callable[[str, str, Optional[str], Optional[str]], Awaitable[None]] = None,
        max_iterations: int = 0,
        custom_prompt: str = None,
        llm_config: dict = None,
        search_config: dict = None,
        restored_state: dict = None,  # 从暂停状态恢复时传入
        session_factory = None  # 数据库会话工厂 (Celery 任务中必须传入)
    ):
        """
        Args:
            target: 扫描目标
            scan_context: 初始扫描结果上下文
            log_callback: 日志回调函数 (type, message, details, tool)
            max_iterations: 最大迭代次数，0 表示无限制
            custom_prompt: 用户自定义提示词
            llm_config: LLM 配置 (可选，否则使用数据库配置)
            search_config: 搜索配置 (可选，否则使用数据库配置)
            restored_state: 从暂停恢复时的 agent 状态
            session_factory: 数据库会话工厂 (用于 Celery 任务，避免事件循环冲突)
        """
        self.target = target
        self.scan_context = scan_context
        self.log_callback = log_callback
        self.max_iterations = max_iterations if max_iterations > 0 else 999999  # 无限制
        self.custom_prompt = custom_prompt
        self.llm_config = llm_config
        self.search_config = search_config
        self.restored_state = restored_state
        self.session_factory = session_factory or AsyncSessionLocal
        
        # LLM 在 run() 中初始化，以便加载数据库配置
        self.llm = None
        self.web_search = None
        
        self.messages = []
        self.findings = []
        self.tools_used = []
        self.skills: list[SkillInfo] = []  # 用户自定义 skill
        self.current_iteration = 0  # 当前迭代次数
    
    async def _log(self, log_type: str, message: str, details: str = None, tool: str = None):
        """记录日志"""
        if self.log_callback:
            await self.log_callback(log_type, message, details, tool)
    
    async def _init_llm(self):
        """初始化 LLM（从数据库加载配置）"""
        if self.llm_config:
            # 使用传入的配置
            config = self.llm_config
        else:
            # 从数据库加载配置
            from app.api.settings import get_active_llm_config
            async with self.session_factory() as db:
                db_config = await get_active_llm_config(db, role="main")
                if db_config:
                    config = {
                        'model': db_config.model,
                        'temperature': db_config.temperature / 100,
                        'api_key': db_config.api_key,
                        'base_url': db_config.api_base_url,
                        'max_tokens': db_config.max_tokens,
                    }
                    await self._log("info", f"🤖 主 Agent 使用 LLM 配置: {db_config.name}", 
                                  f"模型: {db_config.model}")
                else:
                    # 无配置时抛出异常
                    await self._log("error", "❌ LLM 配置未设置", "请在 Web 界面中配置 LLM")
                    raise RuntimeError("LLM 配置未设置，请在 Web 界面的设置页面中添加 LLM 配置")
        
        self.llm = ChatOpenAI(
            model=config.get('model', 'gpt-4o'),
            temperature=config.get('temperature', 0.2),
            api_key=config.get('api_key') or None,
            base_url=config.get('base_url') or None,
            max_tokens=config.get('max_tokens', 4096),
        )
    
    async def _init_search(self):
        """初始化联网搜索工具"""
        if self.search_config:
            config = self.search_config
        else:
            # 从数据库加载配置
            from app.api.settings import get_search_settings_from_db
            async with self.session_factory() as db:
                search_settings = await get_search_settings_from_db(db)
                config = {
                    'enabled': search_settings.enabled,
                    'provider': search_settings.provider,
                    'api_key': search_settings.api_key,
                    'max_results': search_settings.max_results,
                }
        
        if config.get('enabled', True) and config.get('provider', 'none') != 'none':
            self.web_search = WebSearchTool(
                provider=config.get('provider', 'duckduckgo'),
                api_key=config.get('api_key'),
                max_results=config.get('max_results', 5)
            )
            await self._log("info", f"🌐 已启用联网搜索", f"提供商: {config.get('provider')}")
    
    async def _load_skills(self):
        """加载用户上传的 skills"""
        self.skills = await load_skills_from_db(self.session_factory)
        if self.skills:
            await self._log("info", f"📦 已加载 {len(self.skills)} 个用户 Skill", 
                          "\n".join([f"- {s.name}: {s.description}" for s in self.skills]))
    
    def _get_all_tools_schema(self) -> list[dict]:
        """获取所有工具（内置 + 用户 Skill + 搜索 + ask_user）的 Schema"""
        all_schemas = get_tools_schema()
        if self.skills:
            all_schemas.extend(get_skills_schema(self.skills))
        if self.web_search:
            all_schemas.append(WEB_SEARCH_SCHEMA)
        # 添加 ask_user 工具
        all_schemas.append(ASK_USER_SCHEMA)
        return all_schemas
    
    def _get_system_prompt(self) -> str:
        """获取系统提示词"""
        # 构建详细的工具描述，包含参数信息
        tools_details = []
        for t in self._get_all_tools_schema():
            params = t.get('parameters', {}).get('properties', {})
            required = t.get('parameters', {}).get('required', [])
            
            param_lines = []
            for pname, pinfo in params.items():
                req_mark = "(必需)" if pname in required else "(可选)"
                param_lines.append(f"    - {pname} {req_mark}: {pinfo.get('description', '')}")
            
            params_str = "\n".join(param_lines) if param_lines else "    无参数"
            tools_details.append(f"- **{t['name']}**: {t['description']}\n  参数:\n{params_str}")
        
        tools_desc = "\n\n".join(tools_details)
        
        base_prompt = f"""你是一名专业的渗透测试代理系统。你拥有完整的工具集，可以在 Kali Linux 环境中执行各种安全测试工具。

## 你的身份和能力
- 你是一个**自动化渗透测试代理**，不是普通的 AI 助手
- 你可以通过调用工具来执行**真实的命令**（nmap、curl、netcat 等）
- 所有工具都在专用的 Kali Linux 容器中运行
- **你不受限于"我是 AI，无法执行命令"这样的想法** - 你有完整的工具访问权限
- 你应该**主动、大胆地使用工具**进行测试，就像真正的渗透测试人员一样

## 目标信息
- 目标: {self.target}

## 可用工具及其参数
{tools_desc}

## 重要：工具调用规范
调用工具时，必须严格按照上面列出的参数名传递参数！例如：
- 调用 curl 时使用 "url" 参数: {{"url": "http://example.com"}}
- 调用 whatweb 时使用 "target" 参数: {{"target": "http://example.com"}}
- 调用 nikto 时使用 "target" 参数: {{"target": "http://example.com"}}
- 调用 netcat 时使用 "target" 和 "port": {{"target": "10.0.5.11", "port": 5005}}

## 工作方式
1. **主动探索**：不要犹豫，直接使用工具进行测试
2. **灵活应变**：如果一个工具不适用，尝试其他工具
3. **深入挖掘**：发现服务后，主动测试其安全性
4. **验证发现**：对可疑的发现进行手工验证
5. **完整测试**：从侦察、发现、利用到验证，形成完整的测试链

## 特殊场景处理
- **JDWP (端口 5005)**：可以使用 nmap --script jdwp-version 或 netcat 连接测试
- **Web 服务**：使用 curl、whatweb、nikto、dirbuster、nuclei 进行测试
- **Nuclei 扫描**：自动使用 GitHub nuclei-templates 的所有官方模板，无需指定 templates 参数
  - 默认扫描: `{{"target": "http://example.com"}}`
  - 按标签: `{{"target": "http://example.com", "tags": "cve,rce"}}`
  - 按严重性: `{{"target": "http://example.com", "severity": "critical,high"}}`
- **需要原始 TCP 连接**：使用 netcat (nc) 工具
- **需要认证**：尝试默认凭据（admin/admin、root/root 等）
- **任何协议的服务**：都可以通过相应工具测试，不要说"无法测试"

## 输出格式
每次回复请使用以下 JSON 格式：
```json
{{
    "analysis": "对当前情况的分析",
    "plan": "下一步计划",
    "tool_name": "要调用的工具名称（可选）",
    "tool_args": {{"参数名": "参数值"}},
    "is_complete": false,
    "final_summary": null
}}
```

当你认为测试已经足够全面，设置 is_complete: true 并提供结构化的 final_summary。

**重要**: final_summary 必须是包含以下结构的 JSON 对象：
```json
{{
    "target": "目标地址",
    "scope": "测试范围说明",
    "confirmed_findings": [
        {{
            "title": "漏洞标题",
            "cve": "CVE编号（如有）",
            "severity": "critical/high/medium/low",
            "evidence": ["证据1", "证据2"],
            "impact": ["影响1", "影响2"],
            "affected_version": "受影响版本（如有）"
        }}
    ],
    "unconfirmed_findings": [
        {{
            "title": "待确认的发现",
            "severity": "级别",
            "note": "说明"
        }}
    ],
    "risk_assessment": "风险评估总结",
    "recommended_actions": ["建议1", "建议2"]
}}
```

## 自定义工具和文件 (Skills)
- 你可以调用用户上传的自定义工具（以 skill_ 开头）
- **二进制工具**: 使用 args 参数传递命令行参数，例如: {{"args": "-v --output=/tmp/result.txt"}}
- **数据文件**: 可以读取内容、获取路径、用作其他工具的输入
  - 查看文件信息: {{"operation": "info"}}
  - 读取内容: {{"operation": "read", "max_bytes": 1000}}
  - 获取路径: {{"operation": "path"}}
- **Python/Shell 脚本**: 根据参数定义传递参数
- **你可以自由调用任何上传的工具**，包括扫描工具、利用工具、分析脚本等

## 漏洞验证和复现
- **发现潜在漏洞时，必须尝试手工验证和复现**
- 不要仅依赖工具的报告，要用 curl/netcat 等手动测试
- 对于已知 CVE，使用以下方法查找 POC：
  1. 使用 searchsploit 搜索本地 Exploit-DB: `searchsploit <CVE编号或软件名>`
  2. 使用 curl 访问 GitHub: `curl -L https://api.github.com/search/repositories?q=<CVE编号>+POC`
  3. 使用 curl 搜索公开POC仓库
  4. 如果找到 POC，使用 curl 下载并尝试执行复现
- **关键：只有成功复现的漏洞才是确认的漏洞**
- 复现步骤示例：
  ```
  1. 发现 CVE-2024-XXXXX
  2. searchsploit CVE-2024-XXXXX
  3. 如果有结果：curl <POC-URL> -o /tmp/poc.py && python3 /tmp/poc.py <target>
  4. 如果无结果：根据漏洞描述手工构造请求测试
  5. 记录复现步骤和结果作为证据
  ```

## 注意事项
- **你有完整的工具执行权限**，不要说"我是 AI 无法执行命令"
- **你可以执行任何上传的二进制文件、脚本和数据文件**
- **工具安装失败不影响测试**，继续使用其他工具
- 如果目标是 HTTP/HTTPS URL，优先使用 Web 测试工具（curl、whatweb、nikto、dirbuster 等）
- 从侦察开始，逐步深入，但要**主动、快速**
- 根据发现调整测试策略
- 记录所有重要发现，特别是**可利用的漏洞**
- 不要执行破坏性操作（删除文件、修改数据等）
- 保持测试的合法性和道德性
- 如果遇到 401/403 需要认证，尝试常见凭据（admin/admin、root/root、guest/guest）
- 当遇到需要用户决策或敏感操作确认时，使用 ask_user 工具
- **遇到任何服务都应该测试**，包括 JDWP、SSH、HTTP、数据库等
- **发现漏洞后必须验证和复现，不能仅凭工具报告**

## 扫描策略
- **端口扫描**: 默认扫描所有端口 (1-65535)，使用 nmap 时必须指定 `-p 1-65535` 或 `-p-`
- **禁止 SSH 爆破**: 不要对 SSH (22端口) 进行密码爆破攻击
- **禁止行为**:
  - 不要使用 hydra 对 SSH 进行爆破
  - 不要尝试大量 SSH 登录尝试
  - 不要对生产系统进行拒绝服务攻击
- **允许行为**:
  - 可以尝试少量已知的默认凭据（如 admin/admin）
  - 可以对 Web 登录页面进行有限的凭据测试
  - 可以使用其他服务的爆破工具
"""
        
        # 添加用户自定义提示词
        if self.custom_prompt:
            base_prompt += f"""
## 用户额外要求
{self.custom_prompt}
"""
        
        return base_prompt

    def _parse_response(self, content: str) -> AgentThought:
        """解析 LLM 响应"""
        logger.debug(f"Parsing LLM response (length={len(content)}): {content[:1000]}")
        
        # 尝试提取 JSON 代码块
        json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                logger.debug(f"Parsed JSON from code block: {list(data.keys())}")
                return AgentThought(**data)
            except Exception as e:
                logger.warning(f"Failed to parse JSON block: {e}")
        
        # 尝试查找 JSON 对象（从第一个 { 到最后一个 }）
        try:
            start = content.find('{')
            end = content.rfind('}')
            if start != -1 and end > start:
                json_str = content[start:end+1]
                data = json.loads(json_str)
                logger.debug(f"Parsed JSON object: {list(data.keys())}")
                return AgentThought(**data)
        except Exception as e:
            logger.warning(f"Failed to parse JSON object: {e}")
        
        # 如果内容包含 is_complete: true 或类似模式，尝试提取
        if '"is_complete": true' in content or '"is_complete":true' in content:
            # 尝试提取 final_summary
            summary_match = re.search(r'"final_summary"\s*:\s*"([^"]*)"', content)
            summary = summary_match.group(1) if summary_match else content
            return AgentThought(
                analysis="测试完成",
                plan="",
                is_complete=True,
                final_summary=summary
            )
        
        # 尝试从自然语言响应中提取有用信息
        # 如果 LLM 直接返回文本分析而不是 JSON
        if content and len(content) > 50:
            # 检查是否包含工具调用意图
            tool_patterns = [
                (r'使用\s*(curl|nmap|whatweb|nikto|dirbuster|nuclei|searchsploit)\s*', r'\1'),
                (r'调用\s*(curl|nmap|whatweb|nikto|dirbuster|nuclei|searchsploit)\s*', r'\1'),
                (r'执行\s*(curl|nmap|whatweb|nikto|dirbuster|nuclei|searchsploit)\s*', r'\1'),
            ]
            for pattern, _ in tool_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    tool_name = match.group(1).lower()
                    logger.info(f"Extracted tool intent from text: {tool_name}")
                    # 返回一个提示，让 LLM 使用正确的 JSON 格式
                    return AgentThought(
                        analysis=content[:500],
                        plan=f"需要使用 {tool_name} 工具，请使用正确的 JSON 格式",
                        is_complete=False,
                        tool_name=None,  # 不自动执行，让 LLM 重新格式化
                        tool_args=None,
                        final_summary=None
                    )
            
            # 如果内容看起来像是分析/总结，标记为解析错误但保留内容
            logger.warning(f"Could not parse response as JSON, content preview: {content[:200]}")
        
        # 解析失败，增加 parse_error 标记
        return AgentThought(
            analysis="响应格式异常，尝试重新解析",
            plan="请重新格式化响应",
            is_complete=False,
            tool_name=None,
            tool_args=None,
            final_summary=None,
            _parse_error=True  # 标记解析错误
        )
    
    def _get_state(self) -> dict:
        """获取当前 agent 状态（用于暂停时保存）"""
        return {
            "messages": [
                {"type": m.__class__.__name__, "content": _stringify_content(m.content)}
                for m in self.messages
            ],
            "findings": self.findings,
            "tools_used": self.tools_used,
            "current_iteration": self.current_iteration,
            "target": self.target,
            "scan_context": self.scan_context,
            "custom_prompt": self.custom_prompt,
        }
    
    def _restore_state(self, state: dict):
        """从保存的状态恢复"""
        # 恢复消息
        self.messages = []
        for msg in state.get("messages", []):
            msg_type = msg["type"]
            content = _stringify_content(msg["content"])
            if msg_type == "SystemMessage":
                self.messages.append(SystemMessage(content=content))
            elif msg_type == "HumanMessage":
                self.messages.append(HumanMessage(content=content))
            elif msg_type == "AIMessage":
                self.messages.append(AIMessage(content=content))
        
        # 恢复其他状态
        self.findings = state.get("findings", [])
        self.tools_used = state.get("tools_used", [])
        self.current_iteration = state.get("current_iteration", 0)

    async def run(self, user_reply: str = None) -> dict:
        """运行 Agent
        
        Args:
            user_reply: 用户回复（从暂停恢复时传入）
        
        Returns:
            执行结果，如果暂停会包含 paused=True 和 agent_state
        """
        await self._log("llm", "🤖 AI Agent 启动", f"目标: {self.target}")
        
        # 初始化 LLM 和搜索工具
        await self._init_llm()
        await self._init_search()
        
        # 加载用户自定义 skills
        await self._load_skills()
        
        # 检查是否从暂停状态恢复
        if self.restored_state:
            await self._log("info", "📥 从暂停状态恢复", f"继续执行第 {self.restored_state.get('current_iteration', 0)} 次迭代")
            self._restore_state(self.restored_state)
            
            # 添加用户回复
            if user_reply:
                self.messages.append(HumanMessage(content=f"""用户回复:
{user_reply}

请根据用户的回复继续执行测试。"""))
        else:
            # 初始化消息
            self.messages = [
                SystemMessage(content=self._get_system_prompt()),
                HumanMessage(content=f"""初始扫描结果:
{json.dumps(self.scan_context, ensure_ascii=False, indent=2)}

请分析以上信息，制定测试计划并开始执行。""")
            ]
        
        # 解析错误计数器
        parse_error_count = 0
        max_parse_errors = 3  # 最大连续解析错误次数
        
        while self.current_iteration < self.max_iterations:
            self.current_iteration += 1
            await self._log("llm", f"🔄 迭代 {self.current_iteration}/{self.max_iterations}", "AI 正在思考...")
            
            try:
                # 调用 LLM
                response = await self.llm.ainvoke(self.messages)
                
                # 尝试获取响应内容 - 兼容不同的响应格式
                content = None
                if hasattr(response, 'content'):
                    content = response.content
                elif hasattr(response, 'text'):
                    content = response.text
                elif isinstance(response, str):
                    content = response
                elif isinstance(response, dict):
                    content = response.get('content') or response.get('text') or response.get('message', {}).get('content')
                content = _stringify_content(content)
                
                # 记录 AI 原始响应
                if content:
                    logger.debug(f"Agent response (len={len(content)}): {content[:500]}...")
                else:
                    logger.warning(f"Empty response from LLM. Response type: {type(response)}, Response: {str(response)[:500]}")
                
                # 如果响应为空，当作解析错误处理
                if not content or not content.strip():
                    parse_error_count += 1
                    logger.warning(f"Empty response, parse error count: {parse_error_count}/{max_parse_errors}")
                    if parse_error_count >= max_parse_errors:
                        await self._log("error", "❌ LLM 返回空响应次数过多", "终止测试")
                        return {
                            "success": False,
                            "paused": False,
                            "findings": self.findings,
                            "tools_used": self.tools_used,
                            "iterations": self.current_iteration,
                            "summary": "LLM 返回空响应，无法继续测试"
                        }
                    self.messages.append(HumanMessage(content="你的响应为空，请重新回复。"))
                    continue
                
                # 解析响应
                thought = self._parse_response(content)
                
                # 检查是否是解析错误
                is_parse_error = getattr(thought, '_parse_error', False) or thought.analysis == "响应格式异常，尝试重新解析"
                
                if is_parse_error:
                    parse_error_count += 1
                    logger.warning(f"Parse error count: {parse_error_count}/{max_parse_errors}")
                    
                    if parse_error_count >= max_parse_errors:
                        await self._log("error", "❌ 连续解析错误次数过多", f"已连续 {parse_error_count} 次无法解析 AI 响应，终止测试")
                        return {
                            "success": False,
                            "paused": False,
                            "findings": self.findings,
                            "tools_used": self.tools_used,
                            "iterations": self.current_iteration,
                            "summary": f"AI 响应格式异常，无法继续测试。最后响应内容: {content[:500]}"
                        }
                    
                    # 添加更明确的提示
                    self.messages.append(AIMessage(content=content))
                    self.messages.append(HumanMessage(content="""你的响应格式不正确。请严格按照以下 JSON 格式响应:

```json
{
    "analysis": "你对当前情况的分析",
    "plan": "你的下一步计划",
    "tool_name": "要调用的工具名称（如 curl, whatweb, nmap 等，可以为 null）",
    "tool_args": {"参数名": "参数值"},
    "is_complete": false,
    "final_summary": null
}
```

请重新格式化你的响应。"""))
                    continue
                
                # 解析成功，重置错误计数
                parse_error_count = 0
                
                # 记录思考过程
                await self._log(
                    "llm", 
                    f"💭 分析: {thought.analysis[:100]}...",
                    f"计划: {thought.plan}\n\n分析:\n{thought.analysis}"
                )
                
                # 检查是否完成
                if thought.is_complete:
                    await self._log("llm", "✅ AI 测试完成", thought.final_summary)
                    return {
                        "success": True,
                        "paused": False,
                        "findings": self.findings,
                        "tools_used": self.tools_used,
                        "iterations": self.current_iteration,
                        "summary": thought.final_summary
                    }
                
                # 执行工具
                if thought.tool_name and thought.tool_args:
                    try:
                        tool_result = await self._execute_tool(thought.tool_name, thought.tool_args)
                        
                        # 添加到消息历史
                        self.messages.append(AIMessage(content=content))
                        self.messages.append(HumanMessage(content=f"""工具 {thought.tool_name} 执行结果:
成功: {tool_result.success}
输出:
```
{tool_result.output[:3000]}
```
{f'错误: {tool_result.error}' if tool_result.error else ''}

请分析结果并决定下一步。"""))
                    except AgentPauseException as e:
                        # Agent 请求暂停
                        self.messages.append(AIMessage(content=content))
                        await self._log("info", "⏸️ AI Agent 暂停", f"等待用户回复: {e.question}")
                        return {
                            "success": True,
                            "paused": True,
                            "question": e.question,
                            "context": e.context,
                            "options": e.options,
                            "findings": self.findings,
                            "tools_used": self.tools_used,
                            "iterations": self.current_iteration,
                            "agent_state": self._get_state(),
                            "summary": None
                        }
                else:
                    # 没有工具调用，增加无操作计数
                    parse_error_count += 1
                    logger.warning(f"No tool call in response, count: {parse_error_count}/{max_parse_errors}")
                    
                    if parse_error_count >= max_parse_errors:
                        # 如果连续多次没有工具调用，可能是任务完成或卡住
                        await self._log("warning", "⚠️ 连续多次无工具调用", "尝试总结当前测试结果")
                        # 强制让 agent 总结
                        self.messages.append(AIMessage(content=content))
                        self.messages.append(HumanMessage(content="""你已经连续多次没有调用任何工具。请选择:
1. 如果测试已经完成，请设置 is_complete: true 并提供 final_summary
2. 如果需要继续测试，请明确指定要调用的工具和参数

请使用正确的 JSON 格式响应。"""))
                    else:
                        # 正常提示继续
                        self.messages.append(AIMessage(content=content))
                        self.messages.append(HumanMessage(content="请继续执行测试计划，调用合适的工具。如果测试已完成，请设置 is_complete: true。"))
                    
            except AgentPauseException as e:
                # Agent 请求暂停（在 tool execution 之外）
                await self._log("info", "⏸️ AI Agent 暂停", f"等待用户回复: {e.question}")
                return {
                    "success": True,
                    "paused": True,
                    "question": e.question,
                    "context": e.context,
                    "options": e.options,
                    "findings": self.findings,
                    "tools_used": self.tools_used,
                    "iterations": self.current_iteration,
                    "agent_state": self._get_state(),
                    "summary": None
                }
            except Exception as e:
                logger.error(f"Agent iteration error: {e}")
                await self._log("error", f"❌ 迭代出错: {str(e)}")
                self.messages.append(HumanMessage(content=f"发生错误: {str(e)}，请继续。"))
        
        await self._log("llm", "⚠️ 达到最大迭代次数", f"已执行 {self.max_iterations} 次迭代")
        return {
            "success": True,
            "paused": False,
            "findings": self.findings,
            "tools_used": self.tools_used,
            "iterations": self.current_iteration,
            "summary": "达到最大迭代次数，测试终止"
        }

    def _parse_target_port(self, value: str) -> tuple[str, int]:
        """从字符串中智能解析 target 和 port
        
        支持格式:
        - "127.0.0.1:80" 或 "127.0.0.1 80"
        - "http://127.0.0.1:80"
        - "domain.com:443"
        - "127.0.0.1" (无端口则返回 None)
        
        Returns:
            (target, port) - port 可能为 None
        """
        if not value:
            return None, None
            
        value = _stringify_content(value).strip()
        
        # 处理 URL 格式
        url_match = re.match(r'^(https?://)?([^:/\s]+)(?::(\d+))?', value)
        if url_match:
            scheme, host, port = url_match.groups()
            if port:
                return host, int(port)
            # 根据 scheme 推断默认端口
            if scheme == 'https://':
                return host, 443
            elif scheme == 'http://':
                return host, 80
            return host, None
        
        # 处理 host:port 格式
        if ':' in value:
            parts = value.rsplit(':', 1)
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0], int(parts[1])
        
        # 处理 host port 格式（空格分隔）
        parts = value.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            return ' '.join(parts[:-1]), int(parts[-1])
        
        # 纯 host，无端口
        return value, None

    def _normalize_tool_args(self, tool_name: str, tool_args: dict) -> dict:
        """标准化工具参数，自动修正常见的参数名混淆和格式问题"""
        args = {
            key: _stringify_content(value) if isinstance(value, (list, dict)) else value
            for key, value in (tool_args or {}).copy().items()
        }
        
        # 定义每个工具需要的主要参数名
        # 格式: {tool_name: (expected_param, [alternative_names])}
        param_mappings = {
            "whatweb": ("target", ["url", "host", "domain"]),
            "nikto": ("target", ["url", "host"]),
            "nuclei": ("target", ["url", "host"]),
            "nmap": ("target", ["host", "ip", "domain"]),
            "sslscan": ("target", ["host", "url"]),
            "whois": ("target", ["domain", "ip", "host"]),
            "netcat": ("target", ["host", "ip"]),
            "hydra": ("target", ["host", "ip"]),
            "curl": ("url", ["target", "host"]),
            "dirbuster": ("url", ["target", "host"]),
            "sqlmap": ("url", ["target"]),
            "dig": ("domain", ["target", "host"]),
        }
        
        if tool_name in param_mappings:
            expected_param, alternatives = param_mappings[tool_name]
            # 如果期望的参数不存在，尝试从替代参数中获取
            if expected_param not in args or not args.get(expected_param):
                for alt in alternatives:
                    if alt in args and args.get(alt):
                        args[expected_param] = args.pop(alt)
                        logger.debug(f"Auto-mapped {alt} -> {expected_param} for {tool_name}")
                        break
        
        # ========== 特殊工具的智能参数解析 ==========
        
        # netcat: 智能解析 target 和 port
        if tool_name == "netcat":
            args = self._normalize_netcat_args(args)
        
        # nmap: 处理 target 中可能包含的端口信息
        elif tool_name == "nmap":
            args = self._normalize_nmap_args(args)
        
        # curl: 确保 URL 格式正确
        elif tool_name == "curl":
            args = self._normalize_curl_args(args)
        
        return args
    
    def _normalize_netcat_args(self, args: dict) -> dict:
        """智能解析 netcat 参数"""
        # 如果有 args 字符串，尝试从中提取 target 和 port
        if args.get("args") and not args.get("target"):
            args_str = args["args"]
            # 尝试解析 args 字符串
            target, port = self._parse_target_port(args_str)
            if target:
                args["target"] = target
                if port and not args.get("port"):
                    args["port"] = port
                # 如果成功解析出 target 和 port，清除 args 以使用结构化参数
                if args.get("target") and args.get("port"):
                    args.pop("args", None)
                    logger.debug(f"Auto-parsed netcat args: target={target}, port={port}")
        
        # 从 target 中提取 port（如 "127.0.0.1:80"）
        if args.get("target") and not args.get("port"):
            target, port = self._parse_target_port(args["target"])
            if target and port:
                args["target"] = target
                args["port"] = port
                logger.debug(f"Auto-extracted port from target: {target}:{port}")
        
        # 从 destination 参数提取（LLM 有时用 destination）
        if not args.get("target") and args.get("destination"):
            dest = args.pop("destination")
            target, port = self._parse_target_port(dest)
            args["target"] = target
            if port and not args.get("port"):
                args["port"] = port
            logger.debug(f"Auto-mapped destination -> target for netcat")
        
        return args
    
    def _normalize_nmap_args(self, args: dict) -> dict:
        """智能解析 nmap 参数"""
        # 处理 target 中可能包含端口的情况（如 "127.0.0.1:80"）
        if args.get("target") and ':' in str(args["target"]):
            target_str = args["target"]
            # 检查是否是 IP:port 格式
            if re.match(r'^[\d\.]+:\d+$', target_str):
                host, port = target_str.split(':')
                args["target"] = host
                # 如果没有指定 ports 参数，添加端口
                if not args.get("ports"):
                    args["ports"] = port
                logger.debug(f"Auto-extracted port from nmap target: {host}, ports={port}")
        return args
    
    def _normalize_curl_args(self, args: dict) -> dict:
        """智能解析 curl 参数"""
        # 确保 URL 有协议前缀
        if args.get("url"):
            url = _stringify_content(args["url"]).strip()
            if not url.startswith(('http://', 'https://')):
                args["url"] = f"http://{url}"
            else:
                args["url"] = url
                logger.debug(f"Auto-added http:// prefix to curl url")
        return args

    async def _execute_tool(self, tool_name: str, tool_args: dict) -> ToolResult:
        """执行工具（包括用户 Skill 和搜索），支持自动修复重试"""
        # 标准化参数
        normalized_args = self._normalize_tool_args(tool_name, tool_args)
        
        await self._log("tool", f"🔧 调用工具: {tool_name}", json.dumps(normalized_args, ensure_ascii=False, indent=2), tool_name)
        
        # 检查是否是 ask_user 工具
        if tool_name == "ask_user":
            return await self._execute_ask_user(normalized_args)
        
        # 检查是否是用户 Skill (以 skill_ 前缀开头)
        if tool_name.startswith("skill_"):
            return await self._execute_skill(tool_name, normalized_args)
        
        # 检查是否是联网搜索
        if tool_name == "web_search":
            return await self._execute_web_search(normalized_args)
        
        tool = get_tool(tool_name)
        if not tool:
            result = ToolResult(success=False, output="", error=f"未知工具: {tool_name}")
            await self._log("error", f"❌ 工具不存在: {tool_name}", None, tool_name)
            return result
        
        # 尝试确保工具已安装（不阻塞执行）
        try:
            is_installed = await tool.ensure_installed(self.log_callback)
            if not is_installed:
                await self._log("warning", f"⚠️  工具 {tool_name} 可能未安装，尝试执行", None, tool_name)
        except Exception as e:
            await self._log("warning", f"⚠️  工具安装检查失败: {str(e)[:100]}，继续执行", None, tool_name)
        
        self.tools_used.append({"name": tool_name, "args": normalized_args})
        
        # 执行工具，支持自动修复重试
        result = await self._execute_tool_with_auto_repair(tool, tool_name, normalized_args)
        
        if result.success:
            await self._log(
                "output", 
                f"📤 {tool_name} 输出 ({len(result.output)} 字符)",
                result.output[:2000] if result.output else "无输出",
                tool_name
            )
        else:
            await self._log(
                "error",
                f"❌ {tool_name} 执行失败",
                result.error,
                tool_name
            )
        
        # 分析输出中的发现
        await self._analyze_output(tool_name, result)
        
        return result
    
    async def _execute_tool_with_auto_repair(self, tool, tool_name: str, args: dict, max_retries: int = 1) -> ToolResult:
        """执行工具并在失败时尝试自动修复参数
        
        Args:
            tool: 工具实例
            tool_name: 工具名称
            args: 参数字典
            max_retries: 最大重试次数
            
        Returns:
            ToolResult
        """
        try:
            result = await tool.execute(**args)
            
            # 如果成功或已达到重试上限，直接返回
            if result.success or max_retries <= 0:
                return result
            
            # 尝试根据错误信息自动修复参数
            repaired_args = self._try_auto_repair_args(tool_name, args, result.error)
            
            if repaired_args and repaired_args != args:
                await self._log(
                    "info", 
                    f"🔄 尝试自动修复参数并重试 {tool_name}",
                    f"修复后参数: {json.dumps(repaired_args, ensure_ascii=False)}"
                )
                # 递归重试（减少重试次数）
                return await self._execute_tool_with_auto_repair(tool, tool_name, repaired_args, max_retries - 1)
            
            return result
            
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return ToolResult(success=False, output="", error=str(e))
    
    def _try_auto_repair_args(self, tool_name: str, args: dict, error: str) -> dict:
        """根据错误信息尝试自动修复参数
        
        Args:
            tool_name: 工具名称
            args: 原参数
            error: 错误信息
            
        Returns:
            修复后的参数，如果无法修复则返回 None
        """
        if not error:
            return None
        
        repaired = args.copy()
        error_lower = error.lower()
        
        # 通用修复：缺少必需参数
        if "缺少必需参数" in error or "missing" in error_lower or "required" in error_lower:
            # 尝试从 scan context 获取目标
            if hasattr(self, 'target') and self.target:
                if tool_name in ["nmap", "netcat", "whatweb", "nikto", "nuclei", "sslscan"]:
                    if not repaired.get("target"):
                        # 解析目标（可能是 URL 或 IP）
                        target = self.target
                        if target.startswith(('http://', 'https://')):
                            # 从 URL 提取 host
                            match = re.match(r'https?://([^:/]+)', target)
                            if match:
                                target = match.group(1)
                        repaired["target"] = target
                        logger.debug(f"Auto-repair: added target={target} from scan context")
                
                if tool_name == "curl" and not repaired.get("url"):
                    repaired["url"] = self.target
                    logger.debug(f"Auto-repair: added url={self.target} from scan context")
        
        # netcat 特定修复
        if tool_name == "netcat":
            # 如果缺少端口且错误提到端口
            if "port" in error_lower and not repaired.get("port"):
                # 尝试常见端口
                if repaired.get("target"):
                    # 检查 target 是否暗示了协议
                    target = repaired["target"]
                    if "https" in str(args).lower() or "443" in str(args):
                        repaired["port"] = 443
                    elif "http" in str(args).lower() or "80" in str(args):
                        repaired["port"] = 80
                    else:
                        # 默认尝试 80
                        repaired["port"] = 80
                    logger.debug(f"Auto-repair: guessed port={repaired['port']} for netcat")
        
        # nmap 特定修复
        if tool_name == "nmap":
            # 如果没有目标且有 scan context
            if "target" in error_lower and not repaired.get("target"):
                if hasattr(self, 'target') and self.target:
                    repaired["target"] = self.target
        
        # curl 特定修复
        if tool_name == "curl":
            # URL 格式问题
            if repaired.get("url"):
                url = _stringify_content(repaired["url"])
                # 移除多余的空格
                url = url.strip()
                # 确保有协议
                if not url.startswith(('http://', 'https://')):
                    repaired["url"] = f"http://{url}"
                    logger.debug(f"Auto-repair: fixed curl URL format")
        
        # 如果没有任何修改，返回 None
        if repaired == args:
            return None
        
        return repaired
    
    async def _execute_skill(self, tool_name: str, tool_args: dict) -> ToolResult:
        """执行用户自定义 Skill"""
        # 提取 skill 名称 (去掉 skill_ 前缀)
        skill_name = tool_name[6:]  # 移除 "skill_" 前缀
        
        # 查找对应的 skill
        skill = next((s for s in self.skills if s.name == skill_name), None)
        if not skill:
            result = ToolResult(success=False, output="", error=f"未找到 Skill: {skill_name}")
            await self._log("error", f"❌ Skill 不存在: {skill_name}", None, tool_name)
            return result
        
        self.tools_used.append({"name": tool_name, "args": tool_args, "type": "skill"})
        
        try:
            await self._log("info", f"🧩 执行 Skill: {skill_name}", None, tool_name)
            skill_result = await execute_skill(skill, tool_args, log_callback=self.log_callback)
            
            # 转换为 ToolResult
            result = ToolResult(
                success=skill_result.success,
                output=skill_result.output,
                error=skill_result.error
            )
            
            if result.success:
                await self._log(
                    "output",
                    f"📤 Skill {skill_name} 输出 ({len(result.output)} 字符)",
                    result.output[:2000] if result.output else "无输出",
                    tool_name
                )
            else:
                await self._log(
                    "error",
                    f"❌ Skill {skill_name} 执行失败",
                    result.error,
                    tool_name
                )
            
            # 分析输出
            await self._analyze_output(tool_name, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Skill execution error: {e}")
            result = ToolResult(success=False, output="", error=str(e))
            await self._log("error", f"❌ Skill {skill_name} 异常", str(e), tool_name)
            return result
    
    async def _execute_web_search(self, tool_args: dict) -> ToolResult:
        """执行联网搜索"""
        if not self.web_search:
            return ToolResult(success=False, output="", error="联网搜索未启用")
        
        query = tool_args.get('query', '')
        if not query:
            return ToolResult(success=False, output="", error="搜索关键词不能为空")
        
        self.tools_used.append({"name": "web_search", "args": tool_args, "type": "search"})
        
        try:
            await self._log("info", f"🔍 搜索: {query}", None, "web_search")
            results = await self.web_search.search(query)
            
            if not results:
                return ToolResult(success=True, output="未找到相关结果")
            
            # 格式化搜索结果
            output_lines = [f"找到 {len(results)} 条结果:\n"]
            for i, r in enumerate(results, 1):
                output_lines.append(f"{i}. {r.title}")
                output_lines.append(f"   URL: {r.url}")
                output_lines.append(f"   {r.snippet}\n")
            
            output = "\n".join(output_lines)
            
            await self._log(
                "output",
                f"📤 搜索结果 ({len(results)} 条)",
                output[:2000],
                "web_search"
            )
            
            return ToolResult(success=True, output=output)
            
        except Exception as e:
            logger.error(f"Web search error: {e}")
            return ToolResult(success=False, output="", error=str(e))
    
    async def _execute_ask_user(self, tool_args: dict) -> ToolResult:
        """执行 ask_user 工具，暂停等待用户回复"""
        question = tool_args.get('question', '')
        context = tool_args.get('context', '')
        options = tool_args.get('options', [])
        
        if not question:
            return ToolResult(success=False, output="", error="问题不能为空")
        
        self.tools_used.append({"name": "ask_user", "args": tool_args, "type": "interaction"})
        
        # 构造问题显示
        question_display = question
        if context:
            question_display = f"{context}\n\n{question}"
        if options:
            question_display += "\n\n可选项:\n" + "\n".join([f"  • {opt}" for opt in options])
        
        await self._log("info", "❓ AI 向用户提问", question_display, "ask_user")
        
        # 抛出暂停异常，让 run() 方法处理
        raise AgentPauseException(
            question=question,
            context=context,
            options=options,
            agent_state=self._get_state()
        )

    async def _analyze_output(self, tool_name: str, result: ToolResult):
        """分析工具输出，提取发现"""
        if not result.success or not result.output:
            return
        
        output = result.output.lower()
        
        # 简单的关键词检测
        findings_keywords = {
            "critical": ["rce", "remote code execution", "command injection", "sql injection"],
            "high": ["xss", "cross-site scripting", "authentication bypass", "sensitive data"],
            "medium": ["information disclosure", "directory listing", "version disclosure"],
            "low": ["missing header", "cookie without", "http only"],
        }
        
        for severity, keywords in findings_keywords.items():
            for keyword in keywords:
                if keyword in output:
                    finding = {
                        "tool": tool_name,
                        "severity": severity,
                        "keyword": keyword,
                        "snippet": output[:500]
                    }
                    self.findings.append(finding)
                    await self._log(
                        "success" if severity in ["critical", "high"] else "info",
                        f"🎯 发现: {keyword} ({severity})",
                        f"工具: {tool_name}",
                        tool_name
                    )
                    break


async def run_security_agent(
    target: str,
    scan_context: dict,
    log_callback: Callable = None,
    max_iterations: int = 0,
    custom_prompt: str = None,
    restored_state: dict = None,
    user_reply: str = None,
    session_factory = None,
    llm_config: dict = None,
    search_config: dict = None
) -> dict:
    """运行安全测试 Agent
    
    Args:
        target: 目标
        scan_context: 初始扫描上下文
        log_callback: 日志回调
        max_iterations: 最大迭代次数，0 表示无限制
        custom_prompt: 用户自定义提示词
        restored_state: 从暂停恢复时的 agent 状态
        user_reply: 用户回复（从暂停恢复时传入）
        session_factory: 数据库会话工厂 (Celery 任务中必须传入以避免事件循环冲突)
        llm_config: LLM 配置 (预加载，避免 Agent 内部访问数据库)
        search_config: 搜索配置 (预加载，避免 Agent 内部访问数据库)
        
    Returns:
        Agent 执行结果，如果暂停会包含 paused=True 和 agent_state
    """
    agent = SecurityAgent(
        target=target,
        scan_context=scan_context,
        log_callback=log_callback,
        max_iterations=max_iterations,
        custom_prompt=custom_prompt,
        restored_state=restored_state,
        session_factory=session_factory,
        llm_config=llm_config,
        search_config=search_config
    )
    return await agent.run(user_reply=user_reply)
