"""Database models for vulnerability scanner"""
from datetime import datetime
from enum import Enum
from typing import Optional
from sqlalchemy import Column, String, Text, DateTime, JSON, Integer, ForeignKey, Enum as SQLEnum, Boolean
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"  # Agent 暂停等待用户输入
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class UserRole(str, Enum):
    """用户角色"""
    USER = "user"           # 普通用户
    ADMIN = "admin"         # 管理员


class ToolType(str, Enum):
    SCRIPT = "script"           # Python/Bash 脚本
    NUCLEI_TEMPLATE = "nuclei"  # Nuclei 模板
    WORDLIST = "wordlist"       # 字典文件
    CONFIG = "config"           # 配置文件
    SKILL = "skill"             # AI 可调用的 Skill（Python 脚本）
    SCANNER = "scanner"         # 自定义扫描器


class User(Base):
    """用户表"""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # 关系
    scan_tasks = relationship("ScanTask", back_populates="user")
    llm_configs = relationship("LLMConfig", back_populates="user")
    ai_personas = relationship("AIPersona", back_populates="user")
    security_tools = relationship("SecurityTool", back_populates="user")


class ScanTask(Base):
    """扫描任务表"""
    __tablename__ = "scan_tasks"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    target = Column(String(500), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False)  # full, quick, custom
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    config = Column(JSON, default=dict)  # 扫描配置
    
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # LLM 分析结果
    llm_summary = Column(Text)  # AI 生成的漏洞总结
    llm_risk_score = Column(Integer)  # AI 评估的风险分数 0-100
    attack_path_analysis = Column(JSON)  # AI 生成的攻击路径分析
    sub_agents = Column(JSON, default=list)  # SubAgent 编排状态
    
    # 用户备注
    remark = Column(Text)  # 用户对扫描的备注
    
    user = relationship("User", back_populates="scan_tasks")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_task")


class Vulnerability(Base):
    """漏洞记录表"""
    __tablename__ = "vulnerabilities"
    
    id = Column(String(36), primary_key=True)
    scan_task_id = Column(String(36), ForeignKey("scan_tasks.id"), nullable=False)
    
    name = Column(String(200), nullable=False)
    severity = Column(SQLEnum(SeverityLevel), nullable=False)
    category = Column(String(100))  # XSS, SQLi, RCE, etc.
    
    description = Column(Text)
    evidence = Column(Text)  # 原始证据/payload
    location = Column(String(500))  # URL/文件路径
    
    # LLM 增强字段
    llm_analysis = Column(Text)  # AI 对漏洞的深度分析
    llm_remediation = Column(Text)  # AI 建议的修复方案
    llm_false_positive_score = Column(Integer)  # 误报可能性 0-100
    
    raw_data_ref = Column(String(100))  # MongoDB 原始数据引用
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scan_task = relationship("ScanTask", back_populates="vulnerabilities")


class SecurityTool(Base):
    """安全工具/知识库"""
    __tablename__ = "security_tools"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)  # NULL=系统级
    name = Column(String(200), nullable=False)
    description = Column(Text)
    tool_type = Column(SQLEnum(ToolType), nullable=False)
    
    # 文件信息
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)  # 存储路径
    file_size = Column(Integer)  # 字节
    
    # 使用配置
    category = Column(String(100))  # reconnaissance, vulnerability, exploitation, etc.
    tags = Column(JSON, default=list)  # 标签
    usage_instructions = Column(Text)  # 使用说明
    
    # 状态
    is_enabled = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)  # 是否已验证安全
    
    # 元数据
    author = Column(String(100))
    version = Column(String(50))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    user = relationship("User", back_populates="security_tools")


class SearchProvider(str, Enum):
    """联网搜索提供商"""
    NONE = "none"               # 不使用
    TAVILY = "tavily"           # Tavily API
    SERPER = "serper"           # Serper API (Google)
    BING = "bing"               # Bing Search API
    DUCKDUCKGO = "duckduckgo"   # DuckDuckGo (免费)


class LLMConfig(Base):
    """LLM 配置表"""
    __tablename__ = "llm_configs"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)  # NULL=系统级
    name = Column(String(100), nullable=False)  # 配置名称
    provider = Column(String(50), nullable=False)  # openai, azure, anthropic, ollama, etc.
    
    # API 配置
    api_base_url = Column(String(500))  # API 基础 URL
    api_key = Column(String(500))  # API Key (加密存储)
    model = Column(String(100), nullable=False)  # 模型名称
    
    # 模型参数
    temperature = Column(Integer, default=10)  # 温度 * 100 (0-200)
    max_tokens = Column(Integer, default=4096)
    
    # 状态
    is_active = Column(Boolean, default=False)  # 是否为当前使用的配置
    active_for_main_agent = Column(Boolean, default=False)  # 是否供主 Agent 使用
    active_for_sub_agent = Column(Boolean, default=False)  # 是否供子 Agent/分析器使用
    is_enabled = Column(Boolean, default=True)  # 是否启用
    priority = Column(Integer, default=0)  # 优先级，用于自动选择
    
    # 使用统计
    total_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)
    last_used_at = Column(DateTime(timezone=True))
    last_error = Column(Text)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    user = relationship("User", back_populates="llm_configs")


class SystemConfig(Base):
    """系统配置表（键值对）"""
    __tablename__ = "system_configs"
    
    key = Column(String(100), primary_key=True)
    value = Column(Text)
    description = Column(Text)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AIPersona(Base):
    """AI 人格/角色配置表"""
    __tablename__ = "ai_personas"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)  # NULL=系统级
    name = Column(String(100), nullable=False)  # 人格名称
    description = Column(Text)  # 人格描述
    system_prompt = Column(Text, nullable=False)  # System Prompt
    
    is_default = Column(Boolean, default=False)  # 是否为默认人格
    is_enabled = Column(Boolean, default=True)  # 是否启用
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    user = relationship("User", back_populates="ai_personas")


class MessageRole(str, Enum):
    """对话角色"""
    AGENT = "agent"   # AI Agent 的消息
    USER = "user"     # 用户的回复


class ScanMessage(Base):
    """扫描过程中的对话消息"""
    __tablename__ = "scan_messages"
    
    id = Column(String(36), primary_key=True)
    scan_task_id = Column(String(36), ForeignKey("scan_tasks.id"), nullable=False, index=True)
    role = Column(SQLEnum(MessageRole), nullable=False)
    content = Column(Text, nullable=False)
    
    # Agent 暂停时的上下文（JSON 序列化的 agent state）
    agent_state = Column(JSON, nullable=True)
    
    # 是否已处理（用户消息是否已被 agent 读取）
    is_processed = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ChatRole(str, Enum):
    """对话角色（扫描完成后的对话）"""
    USER = "user"           # 用户提问
    ASSISTANT = "assistant" # AI 回答


class ScanChatMessage(Base):
    """扫描完成后的对话消息（用于进一步分析）"""
    __tablename__ = "scan_chat_messages"
    
    id = Column(String(36), primary_key=True)
    scan_task_id = Column(String(36), ForeignKey("scan_tasks.id"), nullable=False, index=True)
    role = Column(SQLEnum(ChatRole), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
