"""Pydantic schemas for API requests/responses"""
from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
from app.models.database import ScanStatus, SeverityLevel


# ============ Scan Task Schemas ============

class ScanConfig(BaseModel):
    """扫描配置"""
    # 智能工具选择
    auto_select_tools: bool = Field(
        default=True,
        description="使用 LLM 自动选择扫描工具（推荐）。关闭后使用手动配置。"
    )
    
    # ======== 扫描类别开关 ========
    enable_category_network: bool = Field(default=True, description="网络扫描与资产识别")
    enable_category_vuln: bool = Field(default=True, description="漏洞扫描与组件分析")
    enable_category_web: bool = Field(default=True, description="Web/API 测试")
    enable_category_cred: bool = Field(default=False, description="凭证与身份验证（危险）")
    enable_category_post_exploit: bool = Field(default=False, description="后渗透与取证辅助")
    
    # ======== 网络扫描与资产识别 ========
    enable_nmap: bool = True
    enable_masscan: bool = True
    enable_naabu: bool = True
    enable_rustscan: bool = True
    enable_httpx: bool = True
    enable_whatweb: bool = True
    enable_katana: bool = True
    
    # ======== 漏洞扫描与组件分析 ========
    enable_nuclei: bool = True
    enable_nikto: bool = True
    enable_wapiti: bool = True
    enable_trivy: bool = True
    enable_grype: bool = True
    enable_lynis: bool = True
    enable_searchsploit: bool = True
    enable_yara: bool = True
    
    # ======== Web/API 测试 ========
    enable_sqlmap: bool = True
    enable_ffuf: bool = True
    enable_dirsearch: bool = True
    enable_gobuster: bool = True
    enable_feroxbuster: bool = True
    enable_wfuzz: bool = True
    enable_dalfox: bool = True
    enable_xsstrike: bool = True
    enable_commix: bool = True
    enable_jwt_tool: bool = True
    enable_newman: bool = True
    enable_sslscan: bool = True
    
    # ======== 凭证与身份验证（默认禁用）========
    enable_hydra: bool = False
    enable_medusa: bool = False
    enable_netexec: bool = False
    enable_cewl: bool = False
    enable_kerbrute: bool = False
    enable_enum4linux: bool = False
    
    # ======== 后渗透与取证辅助（默认禁用）========
    enable_gitleaks: bool = False
    enable_trufflehog: bool = False
    enable_pspy: bool = False
    enable_linpeas: bool = False
    enable_linenum: bool = False
    enable_linux_exploit_suggester: bool = False
    
    # ======== AI Agent 配置 ========
    enable_ai_agent: bool = True
    enable_sub_agents: bool = Field(default=True, description="启用子智能体任务编排")
    ai_max_iterations: int = Field(default=0, ge=0, description="AI Agent 最大迭代次数，0 表示无限制")
    ai_custom_prompt: str | None = Field(default=None, description="AI Agent 自定义提示词")
    ai_persona_id: str | None = Field(default=None, description="AI 人格 ID，为空则使用默认人格")
    
    # ======== 扫描参数 ========
    custom_ports: list[int] = []
    scan_depth: int = Field(default=3, ge=1, le=10)
    rate_limit: int = Field(default=10, ge=1, le=100)  # req/s


class ScanTaskCreate(BaseModel):
    """创建扫描任务请求"""
    target: str = Field(..., description="目标 URL 或 IP 地址")
    scan_type: str = Field(default="quick", pattern="^(full|quick|custom)$")
    config: ScanConfig = Field(default_factory=ScanConfig)
    remark: str | None = Field(default=None, description="扫描备注")


class SubAgentTaskResponse(BaseModel):
    """SubAgent 编排状态"""
    id: str
    name: str
    role: str
    objective: str
    status: str
    phase: str | None = None
    progress: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: str | None = None
    findings_count: int = 0
    error: str | None = None


class ScanTaskResponse(BaseModel):
    """扫描任务响应"""
    id: str
    target: str
    scan_type: str
    status: ScanStatus
    config: dict
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    llm_summary: str | None
    llm_risk_score: int | None
    vulnerability_count: int = 0
    remark: str | None = None
    sub_agents: list[SubAgentTaskResponse] = []
    
    class Config:
        from_attributes = True


class ScanTaskList(BaseModel):
    """扫描任务列表"""
    total: int
    items: list[ScanTaskResponse]


class ScanProgressResponse(BaseModel):
    """扫描进度响应"""
    scan_id: str
    status: ScanStatus
    phase: str | None = None
    message: str | None = None
    sub_agents: list[SubAgentTaskResponse] = []


class ScanLogEntry(BaseModel):
    """单条扫描日志"""
    timestamp: str
    type: str  # info, tool, output, llm, error, success
    message: str
    details: str | None = None
    tool: str | None = None
    agent: str | None = None


class ScanLogsResponse(BaseModel):
    """扫描日志响应"""
    scan_id: str
    logs: list[ScanLogEntry]
    next_index: int


# ============ Vulnerability Schemas ============

class VulnerabilityResponse(BaseModel):
    """漏洞响应"""
    id: str
    name: str
    severity: SeverityLevel
    category: str | None
    description: str | None
    evidence: str | None
    location: str | None
    llm_analysis: str | None
    llm_remediation: str | None
    llm_false_positive_score: int | None
    created_at: datetime
    
    class Config:
        from_attributes = True


class VulnerabilityList(BaseModel):
    """漏洞列表"""
    total: int
    items: list[VulnerabilityResponse]


# ============ LLM Analysis Schemas ============

class LLMAnalysisRequest(BaseModel):
    """手动触发 LLM 分析"""
    scan_task_id: str
    focus_areas: list[str] = []  # 重点分析的领域


class LLMAnalysisResponse(BaseModel):
    """LLM 分析结果"""
    summary: str
    risk_score: int
    key_findings: list[str]
    recommendations: list[str]


# ============ Security Tool Schemas ============

class SecurityToolCreate(BaseModel):
    """创建安全工具"""
    name: str = Field(..., max_length=200)
    description: str | None = None
    tool_type: str = Field(..., pattern="^(script|nuclei|wordlist|config|skill|scanner)$")
    category: str | None = None
    tags: list[str] = []
    usage_instructions: str | None = None
    author: str | None = None
    version: str | None = None


class SecurityToolUpdate(BaseModel):
    """更新安全工具"""
    name: str | None = None
    description: str | None = None
    category: str | None = None
    tags: list[str] | None = None
    usage_instructions: str | None = None
    is_enabled: bool | None = None
    author: str | None = None
    version: str | None = None


class SecurityToolResponse(BaseModel):
    """安全工具响应"""
    id: str
    name: str
    description: str | None
    tool_type: str
    filename: str
    file_size: int | None
    category: str | None
    tags: list[str]
    usage_instructions: str | None
    is_enabled: bool
    is_verified: bool
    author: str | None
    version: str | None
    created_at: datetime
    updated_at: datetime | None
    
    class Config:
        from_attributes = True


class SecurityToolList(BaseModel):
    """安全工具列表"""
    total: int
    items: list[SecurityToolResponse]


# ============ LLM Config Schemas ============

class LLMConfigCreate(BaseModel):
    """创建 LLM 配置"""
    name: str = Field(..., max_length=100)
    provider: str = Field(default="openai", max_length=50)
    api_base_url: str | None = None
    api_key: str | None = None
    model: str = Field(..., max_length=100)
    temperature: int = Field(default=10, ge=0, le=200)  # 实际值 * 100
    max_tokens: int = Field(default=4096, ge=1, le=128000)
    active_for_main_agent: bool = False
    active_for_sub_agent: bool = False
    priority: int = Field(default=0, ge=0)


class LLMConfigUpdate(BaseModel):
    """更新 LLM 配置"""
    name: str | None = None
    provider: str | None = None
    api_base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
    temperature: int | None = None
    max_tokens: int | None = None
    active_for_main_agent: bool | None = None
    active_for_sub_agent: bool | None = None
    is_enabled: bool | None = None
    priority: int | None = None


class LLMConfigResponse(BaseModel):
    """LLM 配置响应"""
    id: str
    name: str
    provider: str
    api_base_url: str | None
    has_api_key: bool  # 不返回实际的 key，只返回是否有配置
    model: str
    temperature: int
    max_tokens: int
    active_for_main_agent: bool
    active_for_sub_agent: bool
    is_enabled: bool
    priority: int
    total_requests: int
    failed_requests: int
    last_used_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime | None
    
    class Config:
        from_attributes = True


class LLMConfigList(BaseModel):
    """LLM 配置列表"""
    total: int
    items: list[LLMConfigResponse]


# ============ System Settings Schemas ============

class SearchSettings(BaseModel):
    """联网搜索设置"""
    enabled: bool = True
    provider: str = "duckduckgo"  # none, tavily, serper, bing, duckduckgo
    api_key: str | None = None  # 某些搜索需要 API key
    max_results: int = Field(default=5, ge=1, le=20)


class ScanSettings(BaseModel):
    """扫描配置设置"""
    max_concurrent_scans: int = Field(default=5, ge=1, le=20, description="最大并发扫描数")
    scan_timeout: int = Field(default=3600, ge=60, le=86400, description="扫描超时时间（秒）")
    rate_limit_per_target: int = Field(default=10, ge=1, le=100, description="每个目标的请求速率限制（req/s）")
    scan_temp_dir: str = Field(default="/tmp/shelling_scans", description="扫描临时文件目录")


class SystemSettings(BaseModel):
    """系统设置"""
    search: SearchSettings = Field(default_factory=SearchSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    
    class Config:
        from_attributes = True


# ============ AI Persona Schemas ============

class AIPersonaCreate(BaseModel):
    """创建 AI 人格"""
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    system_prompt: str = Field(..., min_length=1, max_length=50000)
    is_default: bool = False


class AIPersonaUpdate(BaseModel):
    """更新 AI 人格"""
    name: str | None = Field(default=None, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    system_prompt: str | None = Field(default=None, max_length=50000)
    is_default: bool | None = None
    is_enabled: bool | None = None


class AIPersonaResponse(BaseModel):
    """AI 人格响应"""
    id: str
    name: str
    description: str | None
    system_prompt: str
    is_default: bool
    is_enabled: bool
    created_at: datetime
    updated_at: datetime | None
    
    class Config:
        from_attributes = True


class AIPersonaList(BaseModel):
    """AI 人格列表"""
    total: int
    items: list[AIPersonaResponse]


class AIPersonaBrief(BaseModel):
    """AI 人格简要信息（用于下拉选择）"""
    id: str
    name: str
    description: str | None
    is_default: bool


# ============ Scan Message Schemas ============

class ScanMessageCreate(BaseModel):
    """创建对话消息（用户回复）"""
    content: str = Field(..., min_length=1, max_length=10000)


class ScanMessageResponse(BaseModel):
    """对话消息响应"""
    id: str
    scan_task_id: str
    role: str  # agent, user
    content: str
    is_processed: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanMessageList(BaseModel):
    """对话消息列表"""
    scan_id: str
    messages: list[ScanMessageResponse]
    is_paused: bool  # 扫描是否处于暂停状态
    pending_question: str | None  # Agent 等待回答的问题


# ============ Chat Analysis Schemas ============

class ChatRequest(BaseModel):
    """扫描完成后的对话请求"""
    message: str = Field(..., min_length=1, max_length=10000, description="用户问题")


class ChatResponse(BaseModel):
    """对话响应"""
    id: str
    scan_id: str
    role: str  # user, assistant
    content: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class ChatHistory(BaseModel):
    """对话历史"""
    scan_id: str
    messages: list[ChatResponse]
    can_chat: bool  # 是否可以继续对话
