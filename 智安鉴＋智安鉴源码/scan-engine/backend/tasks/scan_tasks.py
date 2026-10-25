"""Celery scan tasks"""
import asyncio
import uuid
import json
from datetime import datetime
from loguru import logger
from sqlalchemy import select

from tasks.celery_app import celery_app
from scanners import get_scanner, get_available_scanners
from scanners.base import ScannerType, ScanFinding
from llm.analyzer import get_analyzer
from llm.agent import run_security_agent
from app.core.database import create_celery_session
from app.core.scan_logger import get_scan_logger, ScanLogger
from app.models.database import ScanTask, Vulnerability, ScanStatus, SeverityLevel, ScanMessage, MessageRole
from app.core.config import get_settings
from app.core.vulnerability_fingerprint import severity_rank, vulnerability_fingerprint

celery_settings = get_settings()


def run_async(coro):
    """Helper to run async code in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _normalize_unconfirmed_severity(severity: str | None) -> str:
    """未确认的发现不应标记为严重/高危"""
    if not severity:
        return "medium"
    normalized = severity.lower()
    if normalized in {"critical", "high"}:
        return "medium"
    if normalized in {"medium", "low", "info"}:
        return normalized
    return "medium"


def _condense_agent_summary(agent_summary: str | dict | None) -> str:
    """将 AI Agent 总结精简为可读的一句话"""
    if not agent_summary:
        return ""
    summary_data = agent_summary
    if isinstance(agent_summary, str):
        try:
            summary_data = json.loads(agent_summary)
        except json.JSONDecodeError:
            return agent_summary.strip()[:200]
    
    if not isinstance(summary_data, dict):
        return str(summary_data)[:200]
    
    final_summary = summary_data.get("final_summary") or summary_data.get("finalsummary") or summary_data
    confirmed_list = (
        final_summary.get("confirmed_findings")
        or final_summary.get("confirmedfindings")
        or []
    )
    unconfirmed_list = (
        final_summary.get("unconfirmed_findings")
        or final_summary.get("unconfirmedfindings")
        or []
    )
    confirmed_titles = [
        item.get("title") for item in confirmed_list
        if isinstance(item, dict) and item.get("title")
    ]
    unconfirmed_titles = [
        item.get("title") for item in unconfirmed_list
        if isinstance(item, dict) and item.get("title")
    ]
    
    parts = []
    if confirmed_list:
        parts.append(f"已确认 {len(confirmed_list)} 个问题")
    if unconfirmed_list:
        parts.append(f"待确认 {len(unconfirmed_list)} 个问题")
    if confirmed_titles:
        parts.append(f"重点关注：{', '.join(confirmed_titles[:2])}")
    elif unconfirmed_titles:
        parts.append(f"待确认重点：{', '.join(unconfirmed_titles[:2])}")
    
    if not parts:
        return ""
    
    return "AI Agent 结果：" + "；".join(parts) + "。"


async def _fetch_agent_configs(session_factory) -> tuple[dict | None, dict | None]:
    """预加载 Agent 所需的 LLM 和搜索配置，避免 Agent 内部访问数据库时的并发问题"""
    from app.api.settings import get_active_llm_config, get_search_settings_from_db
    
    llm_config = None
    search_config = None
    
    async with session_factory() as db:
        # 加载 LLM 配置
        db_config = await get_active_llm_config(db, role="main")
        if db_config:
            llm_config = {
                'model': db_config.model,
                'temperature': db_config.temperature / 100,
                'api_key': db_config.api_key,
                'base_url': db_config.api_base_url,
                'max_tokens': db_config.max_tokens,
            }
        else:
            # 无配置时返回 None，让调用方决定如何处理
            llm_config = None
        
        # 加载搜索配置
        search_settings = await get_search_settings_from_db(db)
        search_config = {
            'enabled': search_settings.enabled,
            'provider': search_settings.provider,
            'api_key': search_settings.api_key,
            'max_results': search_settings.max_results,
        }
    
    return llm_config, search_config


async def _update_scan_status(
    session_factory,
    scan_task_id: str,
    status: ScanStatus,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    llm_summary: str | None = None,
    risk_score: int | None = None,
):
    """更新扫描任务状态与汇总字段"""
    async with session_factory() as session:
        result = await session.execute(
            select(ScanTask).where(ScanTask.id == scan_task_id)
        )
        task = result.scalar_one_or_none()
        if not task:
            logger.error(f"Scan task not found for status update: {scan_task_id}")
            return

        task.status = status
        if started_at is not None:
            task.started_at = started_at
        if completed_at is not None:
            task.completed_at = completed_at
        if llm_summary is not None:
            task.llm_summary = llm_summary
        if risk_score is not None:
            task.llm_risk_score = risk_score

        await session.commit()


def _is_better_finding(candidate: ScanFinding, existing: ScanFinding) -> bool:
    """选择更具代表性的发现（严重性更高、证据更充分）"""
    candidate_rank = severity_rank(candidate.severity)
    existing_rank = severity_rank(existing.severity)
    if candidate_rank != existing_rank:
        return candidate_rank > existing_rank
    candidate_evidence = len(candidate.evidence or "")
    existing_evidence = len(existing.evidence or "")
    if candidate_evidence != existing_evidence:
        return candidate_evidence > existing_evidence
    return len(candidate.description or "") > len(existing.description or "")


def _dedupe_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    if not findings:
        return []
    deduped: dict[str, ScanFinding] = {}
    for finding in findings:
        key = vulnerability_fingerprint(finding.name, finding.category, finding.location)
        if not key:
            key = str(uuid.uuid4())
        existing = deduped.get(key)
        if not existing or _is_better_finding(finding, existing):
            deduped[key] = finding
    return list(deduped.values())


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _sub_agent_task(
    agent_id: str,
    name: str,
    role: str,
    objective: str,
    status: str = "queued",
    phase: str | None = None,
) -> dict:
    return {
        "id": agent_id,
        "name": name,
        "role": role,
        "objective": objective,
        "status": status,
        "phase": phase,
        "progress": 0,
        "started_at": None,
        "completed_at": None,
        "summary": None,
        "findings_count": 0,
        "error": None,
    }


def _scanner_sub_agent_id(scanner_type: ScannerType) -> str:
    if scanner_type == ScannerType.NMAP:
        return "recon-subagent"
    if scanner_type == ScannerType.NUCLEI:
        return "vulnerability-subagent"
    return f"{scanner_type.value}-subagent"


def _build_sub_agent_plan(config: dict, scanners_to_run: list[ScannerType]) -> list[dict]:
    plan = []
    if ScannerType.NMAP in scanners_to_run:
        plan.append(_sub_agent_task(
            "recon-subagent",
            "Recon SubAgent",
            "资产探测与端口识别",
            "识别目标暴露面、开放端口与基础服务指纹。",
        ))
    if ScannerType.NUCLEI in scanners_to_run:
        plan.append(_sub_agent_task(
            "vulnerability-subagent",
            "Vulnerability SubAgent",
            "模板化漏洞验证",
            "调用漏洞扫描器验证常见 Web 与服务漏洞。",
        ))
    if config.get("enable_ai_agent", True):
        plan.append(_sub_agent_task(
            "ai-validation-subagent",
            "AI Validation SubAgent",
            "自主安全测试与发现验证",
            "基于主 Agent 上下文执行补充测试、验证发现并提出下一步判断。",
        ))
    plan.append(_sub_agent_task(
        "reporting-subagent",
        "Reporting SubAgent",
        "风险归纳与报告生成",
        "汇总各 SubAgent 输出，生成风险评分、修复建议与攻击路径。",
    ))
    return plan


async def _set_sub_agents(session_factory, scan_task_id: str, sub_agents: list[dict]):
    async with session_factory() as session:
        result = await session.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
        task = result.scalar_one_or_none()
        if not task:
            return
        task.sub_agents = sub_agents
        await session.commit()


async def _update_sub_agent(
    session_factory,
    scan_task_id: str,
    agent_id: str,
    *,
    status: str | None = None,
    phase: str | None = None,
    progress: int | None = None,
    summary: str | None = None,
    findings_count: int | None = None,
    error: str | None = None,
):
    async with session_factory() as session:
        result = await session.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
        task = result.scalar_one_or_none()
        if not task:
            return

        updated_sub_agents = []
        for original_sub_agent in task.sub_agents or []:
            sub_agent = dict(original_sub_agent)
            if sub_agent.get("id") != agent_id:
                updated_sub_agents.append(sub_agent)
                continue
            if status is not None:
                previous_status = sub_agent.get("status")
                sub_agent["status"] = status
                if status == "running" and previous_status != "running":
                    sub_agent["started_at"] = sub_agent.get("started_at") or _utc_now_iso()
                if status in {"completed", "failed", "skipped"}:
                    sub_agent["completed_at"] = _utc_now_iso()
            if phase is not None:
                sub_agent["phase"] = phase
            if progress is not None:
                sub_agent["progress"] = max(0, min(100, progress))
            if summary is not None:
                sub_agent["summary"] = summary
            if findings_count is not None:
                sub_agent["findings_count"] = findings_count
            if error is not None:
                sub_agent["error"] = error
            updated_sub_agents.append(sub_agent)

        task.sub_agents = updated_sub_agents
        await session.commit()


async def _save_findings(session_factory, scan_task_id: str, findings: list[ScanFinding]):
    """将扫描发现写入漏洞表"""
    if not findings:
        return

    severity_map = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
    }

    deduped_findings = _dedupe_findings(findings)
    if not deduped_findings:
        return

    async with session_factory() as session:
        existing_result = await session.execute(
            select(Vulnerability.name, Vulnerability.category, Vulnerability.location)
            .where(Vulnerability.scan_task_id == scan_task_id)
        )
        existing_keys = {
            vulnerability_fingerprint(name, category, location)
            for name, category, location in existing_result.all()
        }

        for finding in deduped_findings:
            key = vulnerability_fingerprint(finding.name, finding.category, finding.location)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            vuln = Vulnerability(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                name=finding.name,
                severity=severity_map.get(finding.severity.lower(), SeverityLevel.INFO),
                category=finding.category,
                description=finding.description,
                evidence=(finding.evidence[:4000] if finding.evidence else None),
                location=finding.location,
            )
            session.add(vuln)

        await session.commit()


async def _analyze_vulnerabilities(session_factory, scan_task_id: str, scan_logger):
    """对关键漏洞进行 LLM 分析，生成修复建议"""
    from llm.analyzer import get_analyzer
    
    async with session_factory() as session:
        # 获取所有非端口扫描的漏洞
        result = await session.execute(
            select(Vulnerability)
            .where(Vulnerability.scan_task_id == scan_task_id)
            .where(~Vulnerability.name.startswith("Open port:"))
        )
        vulnerabilities = result.scalars().all()
        
        if not vulnerabilities:
            return
        
        # 优先分析高危和严重漏洞，限制数量避免超时
        priority_vulns = [
            v for v in vulnerabilities 
            if v.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ][:10]  # 最多分析10个高危漏洞
        
        if not priority_vulns:
            # 如果没有高危漏洞，分析前5个中危漏洞
            priority_vulns = [
                v for v in vulnerabilities 
                if v.severity == SeverityLevel.MEDIUM
            ][:5]
        
        if not priority_vulns:
            return
        
        analyzer = get_analyzer()
        analyzed_count = 0
        
        for vuln in priority_vulns:
            try:
                # 调用 LLM 分析单个漏洞
                analysis = await analyzer.analyze_vulnerability(
                    vuln_name=vuln.name,
                    vuln_type=vuln.category or "unknown",
                    evidence=vuln.evidence or "",
                    context=f"位置: {vuln.location}\n描述: {vuln.description}"
                )
                
                # 更新漏洞记录
                vuln.llm_analysis = analysis.summary
                vuln.llm_remediation = "\n".join(analysis.remediation_steps)
                vuln.llm_false_positive_score = analysis.false_positive_likelihood
                
                analyzed_count += 1
                
                scan_logger.llm(
                    f"✅ 分析完成: {vuln.name[:50]}",
                    f"修复建议: {len(analysis.remediation_steps)} 项"
                )
                
            except Exception as e:
                logger.error(f"Failed to analyze vulnerability {vuln.id}: {e}")
                scan_logger.error(f"❌ 漏洞分析失败: {vuln.name[:50]}", str(e))
        
        if analyzed_count > 0:
            await session.commit()
            scan_logger.success(
                f"🎯 漏洞分析完成",
                f"已为 {analyzed_count} 个关键漏洞生成修复建议"
            )


async def _analyze_attack_path(session_factory, scan_task_id: str, target: str, findings: list, scan_logger):
    """生成攻击路径分析并写入扫描任务"""
    if not findings:
        return
    
    open_ports = []
    vulnerabilities = []
    for f in findings:
        vuln_dict = {
            "id": str(uuid.uuid4()),
            "name": f.name,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "location": f.location,
            "evidence": f.evidence,
        }
        if f.name.startswith("Open port:"):
            open_ports.append(vuln_dict)
        else:
            vulnerabilities.append(vuln_dict)
    
    if not open_ports and not vulnerabilities:
        return
    
    scan_logger.llm(
        "🧭 开始生成攻击路径分析",
        f"漏洞: {len(vulnerabilities)}，开放端口: {len(open_ports)}"
    )
    
    try:
        analyzer = get_analyzer()
        analysis_result = await analyzer.analyze_attack_path(
            target=target,
            vulnerabilities=vulnerabilities,
            open_ports=open_ports
        )
        result_dict = analysis_result.model_dump()
    except Exception as e:
        logger.error(f"Attack path analysis failed: {e}")
        scan_logger.error("❌ 攻击路径分析失败", str(e))
        return
    
    async with session_factory() as session:
        result = await session.execute(
            select(ScanTask).where(ScanTask.id == scan_task_id)
        )
        task = result.scalar_one_or_none()
        if not task:
            return
        task.attack_path_analysis = result_dict
        await session.commit()
    
    scan_logger.success("✅ 攻击路径分析完成", f"攻击链: {len(result_dict.get('attack_chains', []))}")


async def _save_agent_pause(
    session_factory,
    scan_task_id: str,
    question: str,
    context: str = None,
    options: list = None,
    agent_state: dict = None,
    scan_context: dict = None,
    findings: list = None,
):
    """保存 Agent 暂停状态"""
    async with session_factory() as session:
        # 构造完整的消息内容
        content_parts = [question]
        if context:
            content_parts.insert(0, f"**背景:** {context}\n")
        if options:
            content_parts.append("\n**可选项:**\n" + "\n".join([f"  • {opt}" for opt in options]))
        
        message = ScanMessage(
            id=str(uuid.uuid4()),
            scan_task_id=scan_task_id,
            role=MessageRole.AGENT,
            content="\n".join(content_parts),
            agent_state={
                "agent_state": agent_state,
                "scan_context": scan_context,
                "findings": [
                    {
                        "name": f.name,
                        "severity": f.severity,
                        "category": f.category,
                        "location": f.location,
                        "description": f.description,
                        "evidence": f.evidence[:1000] if f.evidence else None,
                    }
                    for f in (findings or [])
                ],
                "options": options,
            },
            is_processed=False,
        )
        session.add(message)
        await session.commit()


async def _get_pending_user_reply(session_factory, scan_task_id: str) -> tuple:
    """获取待处理的用户回复和 agent 状态"""
    async with session_factory() as session:
        # 获取最新的未处理用户消息
        result = await session.execute(
            select(ScanMessage)
            .where(ScanMessage.scan_task_id == scan_task_id)
            .where(ScanMessage.role == MessageRole.USER)
            .where(ScanMessage.is_processed == False)
            .order_by(ScanMessage.created_at.desc())
            .limit(1)
        )
        user_msg = result.scalar_one_or_none()
        
        if not user_msg:
            return None, None, None, None
        
        # 获取最新的 agent 消息（包含 agent_state）
        result = await session.execute(
            select(ScanMessage)
            .where(ScanMessage.scan_task_id == scan_task_id)
            .where(ScanMessage.role == MessageRole.AGENT)
            .where(ScanMessage.agent_state.isnot(None))
            .order_by(ScanMessage.created_at.desc())
            .limit(1)
        )
        agent_msg = result.scalar_one_or_none()
        
        if not agent_msg or not agent_msg.agent_state:
            return None, None, None, None
        
        # 标记用户消息为已处理
        user_msg.is_processed = True
        await session.commit()
        
        state_data = agent_msg.agent_state
        return (
            user_msg.content,
            state_data.get("agent_state"),
            state_data.get("scan_context"),
            state_data.get("findings", [])
        )


@celery_app.task(bind=True, name="tasks.execute_scan")
def execute_scan(self, scan_task_id: str, target: str, scan_type: str, config: dict):
    """执行完整扫描流程"""
    logger.info(f"Starting scan task {scan_task_id} for target: {target}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Create session factory for this event loop
    engine, session_factory = create_celery_session()
    
    # Initialize scan logger
    scan_logger = get_scan_logger(scan_task_id)
    scan_logger.info("🚀 主 Agent 启动扫描任务", f"目标: {target}, 类型: {scan_type}", agent="主 Agent")

    loop.run_until_complete(_update_scan_status(
        session_factory=session_factory,
        scan_task_id=scan_task_id,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow(),
    ))
    
    self.update_state(state="RUNNING", meta={"phase": "initializing"})
    scan_logger.info("⚙️ 主 Agent 初始化扫描环境", agent="主 Agent")
    
    findings = []
    errors = []
    
    async def run_scanners():
        nonlocal findings, errors
        
        # 确定要运行的扫描器
        available, uploaded_scanners = await get_available_scanners()
        scan_logger.info(
            "🔍 主 Agent 检测可用扫描器",
            f"可用: {[s.value for s in available] + uploaded_scanners}"
            , agent="主 Agent"
        )
        
        scanners_to_run = []
        if config.get("enable_port_scan", True) and ScannerType.NMAP in available:
            scanners_to_run.append(ScannerType.NMAP)
        if config.get("enable_nuclei", True) and ScannerType.NUCLEI in available:
            scanners_to_run.append(ScannerType.NUCLEI)
        
        if not scanners_to_run:
            scan_logger.error("❌ 主 Agent 未找到可用扫描器", agent="主 Agent")
            errors.append("No scanners available")
            return
        
        if config.get("enable_sub_agents", True):
            sub_agent_plan = _build_sub_agent_plan(config, scanners_to_run)
            await _set_sub_agents(session_factory, scan_task_id, sub_agent_plan)
            scan_logger.info(
                "🧠 主 Agent 已编排 SubAgent 任务",
                "\n".join(f"• {agent['name']}: {agent['objective']}" for agent in sub_agent_plan)
                , agent="主 Agent"
            )

        scan_logger.info(
            "📋 主 Agent 下发并行扫描计划",
            f"将并行运行: {[s.value for s in scanners_to_run]}",
            agent="主 Agent"
        )
        
        async def run_scanner_sub_agent(scanner_type: ScannerType):
            tool_name = scanner_type.value.upper()
            sub_agent_id = _scanner_sub_agent_id(scanner_type)
            sub_agent_name = {
                "recon-subagent": "Recon SubAgent",
                "vulnerability-subagent": "Vulnerability SubAgent",
            }.get(sub_agent_id, f"{tool_name} SubAgent")
            self.update_state(
                state="RUNNING",
                meta={"phase": "parallel_sub_agents", "active_sub_agents": [s.value for s in scanners_to_run]}
            )
            scan_logger.tool(tool_name, f"🔧 {sub_agent_name} 启动 {tool_name} 扫描器", agent=sub_agent_name)
            if config.get("enable_sub_agents", True):
                await _update_sub_agent(
                    session_factory,
                    scan_task_id,
                    sub_agent_id,
                    status="running",
                    phase=f"running_{scanner_type.value}",
                    progress=20,
                    summary=f"{sub_agent_name} 已接收主 Agent 委派，正在执行 {tool_name}。",
                )
            
            try:
                scanner = get_scanner(scanner_type)
                finding_count = 0
                async for finding in scanner.scan(target, config):
                    findings.append(finding)
                    finding_count += 1
                    if config.get("enable_sub_agents", True) and finding_count % 5 == 0:
                        await _update_sub_agent(
                            session_factory,
                            scan_task_id,
                            sub_agent_id,
                            progress=min(85, 20 + finding_count * 5),
                            findings_count=finding_count,
                            summary=f"已上报 {finding_count} 个候选发现。",
                        )
                    # 记录每个发现
                    scan_logger.tool(
                        tool_name, 
                        f"📍 {sub_agent_name} 发现: {finding.name}",
                        f"严重性: {finding.severity}\n位置: {finding.location or 'N/A'}\n{finding.description or ''}",
                        agent=sub_agent_name,
                    )
                    logger.debug(f"Found: {finding.name} ({finding.severity})")
                
                scan_logger.success(f"✅ {sub_agent_name} 完成 {tool_name} 扫描", f"发现 {finding_count} 个结果", agent=sub_agent_name)
                if config.get("enable_sub_agents", True):
                    await _update_sub_agent(
                        session_factory,
                        scan_task_id,
                        sub_agent_id,
                        status="completed",
                        progress=100,
                        findings_count=finding_count,
                        summary=f"{sub_agent_name} 完成 {tool_name} 子任务，发现 {finding_count} 个结果。",
                    )
                
            except Exception as e:
                logger.error(f"Scanner {scanner_type} error: {e}")
                scan_logger.error(f"❌ {sub_agent_name} 执行 {tool_name} 出错", str(e), agent=sub_agent_name)
                errors.append(f"{scanner_type}: {str(e)}")
                if config.get("enable_sub_agents", True):
                    await _update_sub_agent(
                        session_factory,
                        scan_task_id,
                        sub_agent_id,
                        status="failed",
                        progress=100,
                        error=str(e),
                        summary=f"{sub_agent_name} 执行 {tool_name} 子任务失败。",
                    )

        await asyncio.gather(*(run_scanner_sub_agent(scanner_type) for scanner_type in scanners_to_run))
        scan_logger.info("🧠 主 Agent 已汇总并行 SubAgent 初扫结果", f"累计发现: {len(findings)}", agent="主 Agent")
    
    llm_summary = None
    risk_score = None

    try:
        # 执行扫描
        loop.run_until_complete(run_scanners())

        # LLM 分析
        self.update_state(state="RUNNING", meta={"phase": "llm_analysis"})
        
        # 构建初始扫描上下文
        scan_context = {
            "target": target,
            "scan_type": scan_type,
            "findings_count": len(findings),
            "findings": [
                {
                    "name": f.name,
                    "severity": f.severity,
                    "location": f.location,
                    "category": f.category,
                    "description": f.description,
                }
                for f in findings[:50]  # 限制数量避免 token 过多
            ],
            "errors": errors,
        }
        
        # AI Agent 自主安全测试阶段
        if config.get("enable_ai_agent", True):
            self.update_state(state="RUNNING", meta={"phase": "ai_agent"})
            if config.get("enable_sub_agents", True):
                loop.run_until_complete(_update_sub_agent(
                    session_factory,
                    scan_task_id,
                    "ai-validation-subagent",
                    status="running",
                    phase="ai_agent",
                    progress=15,
                    summary="主 Agent 正在委派 AI Validation SubAgent 执行自主验证。",
                ))
            
            # 获取自定义提示词
            custom_prompt = config.get("ai_custom_prompt")
            max_iterations = config.get("ai_max_iterations", 0)  # 0 表示无限制
            
            if custom_prompt:
                scan_logger.llm("🤖 启动 AI 安全测试代理", f"AI 将按照用户指示执行测试...\n\n用户提示: {custom_prompt}")
            else:
                scan_logger.llm("🤖 启动 AI 安全测试代理", "AI 将自主决定并执行额外的安全测试...")
            
            try:
                # 创建日志回调
                async def agent_log_callback(log_type: str, message: str, details: str = None, tool: str = None):
                    if log_type == "llm":
                        scan_logger.llm(message, details, agent="AI Validation SubAgent")
                    elif log_type == "tool":
                        scan_logger.tool(tool or "agent", message, details, agent="AI Validation SubAgent")
                    elif log_type == "output":
                        scan_logger.output(tool or "agent", message, details, agent="AI Validation SubAgent")
                    elif log_type == "error":
                        scan_logger.error(message, details, agent="AI Validation SubAgent")
                    elif log_type == "success":
                        scan_logger.success(message, details, agent="AI Validation SubAgent")
                    else:
                        scan_logger.info(message, details, agent="AI Validation SubAgent")
                
                # 预加载 Agent 所需的配置，避免 Agent 内部并发访问数据库
                llm_config, search_config = loop.run_until_complete(
                    _fetch_agent_configs(session_factory)
                )
                
                # 检查 LLM 配置是否存在
                if llm_config is None:
                    scan_logger.error("❌ LLM 配置未设置", "请在 Web 界面的设置页面中添加 LLM 配置")
                    errors.append("LLM 配置未设置，AI 代理无法运行")
                    if config.get("enable_sub_agents", True):
                        loop.run_until_complete(_update_sub_agent(
                            session_factory,
                            scan_task_id,
                            "ai-validation-subagent",
                            status="skipped",
                            progress=100,
                            summary="未配置 LLM，AI Validation SubAgent 已跳过。",
                        ))
                    # 跳过 AI Agent 阶段，继续保存扫描结果
                    loop.run_until_complete(_save_findings(session_factory, scan_task_id, findings))
                    loop.run_until_complete(_update_scan_status(
                        session_factory=session_factory,
                        scan_task_id=scan_task_id,
                        status=ScanStatus.COMPLETED,
                        completed_at=datetime.utcnow(),
                    ))
                    return {"status": "completed_without_ai", "message": "扫描完成，但 AI 分析被跳过（未配置 LLM）"}
                
                # 运行 AI Agent
                agent_result = loop.run_until_complete(run_security_agent(
                    target=target,
                    scan_context=scan_context,
                    log_callback=agent_log_callback,
                    max_iterations=max_iterations,
                    custom_prompt=custom_prompt,
                    session_factory=session_factory,
                    llm_config=llm_config,
                    search_config=search_config
                ))
                
                # 检查 Agent 是否暂停等待用户输入
                if agent_result.get("paused"):
                    scan_logger.info("⏸️ AI Agent 暂停", f"等待用户回复: {agent_result.get('question')}")
                    if config.get("enable_sub_agents", True):
                        loop.run_until_complete(_update_sub_agent(
                            session_factory,
                            scan_task_id,
                            "ai-validation-subagent",
                            status="waiting_input",
                            progress=60,
                            summary=f"需要用户确认：{agent_result.get('question')}",
                        ))
                    
                    # 保存暂停状态到数据库
                    loop.run_until_complete(_save_agent_pause(
                        session_factory=session_factory,
                        scan_task_id=scan_task_id,
                        question=agent_result.get("question"),
                        context=agent_result.get("context"),
                        options=agent_result.get("options"),
                        agent_state=agent_result.get("agent_state"),
                        scan_context=scan_context,
                        findings=findings
                    ))
                    
                    # 更新扫描状态为 paused
                    loop.run_until_complete(_update_scan_status(
                        session_factory=session_factory,
                        scan_task_id=scan_task_id,
                        status=ScanStatus.PAUSED,
                    ))
                    
                    scan_logger.close()
                    loop.run_until_complete(engine.dispose())
                    asyncio.set_event_loop(None)
                    loop.close()
                    
                    return {
                        "scan_task_id": scan_task_id,
                        "status": "paused",
                        "question": agent_result.get("question"),
                        "context": agent_result.get("context"),
                        "options": agent_result.get("options"),
                    }
                
                # 添加 Agent 发现到 findings
                if agent_result.get("findings"):
                    agent_findings = agent_result["findings"]
                    scan_logger.success(
                        f"🎯 AI Agent 发现 {len(agent_findings)} 个问题",
                        json.dumps(agent_findings, ensure_ascii=False, indent=2)
                    )
                    
                    # 将 Agent 发现转换为 ScanFinding 对象
                    for af in agent_findings:
                        keyword = af.get('keyword', 'security issue')
                        tool_used = af.get('tool', 'unknown')
                        raw_severity = af.get('severity')
                        severity = _normalize_unconfirmed_severity(raw_severity)
                        if raw_severity and raw_severity.lower() != severity:
                            severity_display = f"{raw_severity} -> {severity}"
                        elif raw_severity is None:
                            severity_display = f"unknown -> {severity}"
                        else:
                            severity_display = severity
                        finding = ScanFinding(
                            scanner=ScannerType.CUSTOM,
                            name=f"{keyword.upper()} 检测到潜在安全风险",
                            severity=severity,
                            category=f"ai_{keyword.replace(' ', '_')}",
                            description=f"AI Agent 在使用 {tool_used} 工具测试时检测到潜在的 {keyword} 安全问题。建议进一步人工验证。",
                            location=target,
                            evidence=af.get('snippet', '')[:4000],
                            raw_data=af,
                            metadata={
                                "detected_by": "ai_agent",
                                "tool": tool_used,
                                "keyword": keyword,
                                "raw_severity": raw_severity,
                            }
                        )
                        findings.append(finding)
                        scan_logger.info(
                            f"➕ 添加 AI 发现",
                            f"类型: {keyword}, 严重性: {severity_display}"
                        )
                    if config.get("enable_sub_agents", True):
                        loop.run_until_complete(_update_sub_agent(
                            session_factory,
                            scan_task_id,
                            "ai-validation-subagent",
                            progress=80,
                            findings_count=len(agent_findings),
                            summary=f"AI Validation SubAgent 已提交 {len(agent_findings)} 个候选发现。",
                        ))
                
                # 解析 final_summary 中的结构化漏洞信息
                if agent_result.get("summary"):
                    summary = agent_result["summary"]
                    
                    # 尝试解析 JSON 格式的 summary
                    if isinstance(summary, str):
                        try:
                            summary_data = json.loads(summary)
                            
                            # 检查是否有 final_summary.confirmed_findings
                            if isinstance(summary_data, dict):
                                # 可能直接在 summary_data 中，或在 final_summary 中
                                confirmed_list = None
                                if "confirmed_findings" in summary_data:
                                    confirmed_list = summary_data["confirmed_findings"]
                                elif "final_summary" in summary_data and isinstance(summary_data["final_summary"], dict):
                                    confirmed_list = summary_data["final_summary"].get("confirmed_findings")
                                
                                if confirmed_list and isinstance(confirmed_list, list):
                                    for confirmed in confirmed_list:
                                        cve = confirmed.get("cve", "N/A")
                                        title = confirmed.get("title", "Unknown vulnerability")
                                        severity = confirmed.get("severity", "high")
                                        evidence_list = confirmed.get("evidence", [])
                                        impact_list = confirmed.get("impact", [])
                                        
                                        evidence_text = "\n".join([f"• {e}" for e in evidence_list])
                                        impact_text = "\n".join([f"• {i}" for i in impact_list])
                                        
                                        finding = ScanFinding(
                                            scanner=ScannerType.CUSTOM,
                                            name=f"{cve}: {title}",
                                            severity=severity,
                                            category="ai_confirmed_vulnerability",
                                            description=f"AI Agent 通过人工验证确认的漏洞。\n\n影响:\n{impact_text}",
                                            location=target,
                                            evidence=evidence_text[:4000],
                                            raw_data=confirmed,
                                            metadata={"cve": cve, "ai_confirmed": True}
                                        )
                                        findings.append(finding)
                                        scan_logger.success(
                                            f"🔍 AI 确认漏洞: {cve}",
                                            f"严重性: {severity}, 标题: {title}"
                                        )
                                
                                # 使用格式化的 summary
                                scan_context["agent_summary"] = json.dumps(summary_data, ensure_ascii=False, indent=2)
                            else:
                                # 不是预期的结构，直接使用字符串
                                scan_context["agent_summary"] = summary
                        except (json.JSONDecodeError, TypeError, KeyError) as e:
                            # 如果不是 JSON，继续使用字符串 summary
                            logger.debug(f"Summary is not JSON: {e}")
                            scan_context["agent_summary"] = summary
                    elif isinstance(summary, dict):
                        # 已经是字典对象
                        confirmed_list = None
                        if "confirmed_findings" in summary:
                            confirmed_list = summary["confirmed_findings"]
                        elif "final_summary" in summary and isinstance(summary["final_summary"], dict):
                            confirmed_list = summary["final_summary"].get("confirmed_findings")
                        
                        if confirmed_list and isinstance(confirmed_list, list):
                            for confirmed in confirmed_list:
                                cve = confirmed.get("cve", "N/A")
                                title = confirmed.get("title", "Unknown vulnerability")
                                severity = confirmed.get("severity", "high")
                                evidence_list = confirmed.get("evidence", [])
                                impact_list = confirmed.get("impact", [])
                                
                                evidence_text = "\n".join([f"• {e}" for e in evidence_list])
                                impact_text = "\n".join([f"• {i}" for i in impact_list])
                                
                                finding = ScanFinding(
                                    scanner=ScannerType.CUSTOM,
                                    name=f"{cve}: {title}",
                                    severity=severity,
                                    category="ai_confirmed_vulnerability",
                                    description=f"AI Agent 通过人工验证确认的漏洞。\n\n影响:\n{impact_text}",
                                    location=target,
                                    evidence=evidence_text[:4000],
                                    raw_data=confirmed,
                                    metadata={"cve": cve, "ai_confirmed": True}
                                )
                                findings.append(finding)
                                scan_logger.success(
                                    f"🔍 AI 确认漏洞: {cve}",
                                    f"严重性: {severity}, 标题: {title}"
                                )
                        
                        scan_context["agent_summary"] = json.dumps(summary, ensure_ascii=False, indent=2)
                    else:
                        scan_context["agent_summary"] = str(summary)
                    
                    scan_context["agent_tools_used"] = agent_result.get("tools_used", [])
                    scan_context["agent_iterations"] = agent_result.get("iterations", 0)
                if config.get("enable_sub_agents", True):
                    loop.run_until_complete(_update_sub_agent(
                        session_factory,
                        scan_task_id,
                        "ai-validation-subagent",
                        status="completed",
                        progress=100,
                        findings_count=len(agent_result.get("findings", []) or []),
                        summary=f"自主验证完成，迭代 {agent_result.get('iterations', 0)} 次。",
                    ))
                
            except Exception as e:
                logger.error(f"AI Agent failed: {e}")
                scan_logger.error("❌ AI Agent 执行失败", str(e))
                errors.append(f"AI Agent: {str(e)}")
                if config.get("enable_sub_agents", True):
                    loop.run_until_complete(_update_sub_agent(
                        session_factory,
                        scan_task_id,
                        "ai-validation-subagent",
                        status="failed",
                        progress=100,
                        error=str(e),
                        summary="AI Validation SubAgent 执行失败。",
                    ))
        elif config.get("enable_sub_agents", True):
            loop.run_until_complete(_update_sub_agent(
                session_factory,
                scan_task_id,
                "ai-validation-subagent",
                status="skipped",
                progress=100,
                summary="未启用 AI Agent，AI Validation SubAgent 已跳过。",
            ))
        
        # 去重扫描发现，避免重复漏洞影响摘要与保存
        findings = _dedupe_findings(findings)

        # LLM 总结分析
        if config.get("enable_sub_agents", True):
            loop.run_until_complete(_update_sub_agent(
                session_factory,
                scan_task_id,
                "reporting-subagent",
                status="running",
                phase="llm_analysis",
                progress=20,
                findings_count=len(findings),
                summary="Reporting SubAgent 正在汇总扫描、验证与漏洞上下文。",
            ))
        if findings or scan_context.get("agent_summary"):
            scan_logger.llm("🤖 Reporting SubAgent 开始生成扫描报告", f"综合 {len(findings)} 个发现和 AI Agent 测试结果", agent="Reporting SubAgent")
            
            try:
                analyzer = get_analyzer()
                vuln_dicts = [
                    {
                        "name": f.name,
                        "severity": f.severity,
                        "location": f.location,
                        "category": f.category,
                    }
                    for f in findings
                ]
                
                # 添加 Agent 测试信息到扫描信息
                scan_info = {
                    "scan_type": scan_type,
                    "duration": "N/A",
                }
                if scan_context.get("agent_summary"):
                    scan_info["ai_agent_summary"] = scan_context["agent_summary"]
                    scan_info["ai_agent_tools"] = scan_context.get("agent_tools_used", [])
                
                scan_logger.llm("📤 Reporting SubAgent 发送数据到 AI 模型", f"分析 {len(vuln_dicts)} 个漏洞发现...", agent="Reporting SubAgent")

                result = loop.run_until_complete(analyzer.summarize_scan(
                    target=target,
                    vulnerabilities=vuln_dicts,
                    scan_info=scan_info
                ))

                llm_summary = result.executive_summary
                risk_score = result.risk_score
                
                scan_logger.llm(
                    "📥 Reporting SubAgent 分析完成", 
                    f"风险评分: {risk_score}/100\n\n{llm_summary}",
                    agent="Reporting SubAgent"
                )
                if config.get("enable_sub_agents", True):
                    loop.run_until_complete(_update_sub_agent(
                        session_factory,
                        scan_task_id,
                        "reporting-subagent",
                        progress=65,
                        summary=f"已生成风险摘要，风险评分 {risk_score}/100。",
                    ))
                
                if result.critical_findings:
                    scan_logger.llm("⚠️ 关键发现", "\n".join(f"• {f}" for f in result.critical_findings))
                
                if result.priority_recommendations:
                    scan_logger.llm("💡 修复建议", "\n".join(f"• {r}" for r in result.priority_recommendations))

            except Exception as e:
                logger.error(f"LLM analysis failed: {e}")
                scan_logger.error("❌ AI 分析失败", str(e))
                errors.append(f"LLM analysis: {str(e)}")
                
                # 如果 LLM 分析失败但有 Agent 总结，使用 Agent 总结
                if scan_context.get("agent_summary"):
                    llm_summary = _condense_agent_summary(scan_context.get("agent_summary")) or "AI Agent 已完成测试，但未生成可读摘要。"
        else:
            scan_logger.info("ℹ️ 未发现漏洞，跳过 AI 分析")
            if config.get("enable_sub_agents", True):
                loop.run_until_complete(_update_sub_agent(
                    session_factory,
                    scan_task_id,
                    "reporting-subagent",
                    progress=65,
                    summary="未发现可报告漏洞，跳过 LLM 摘要生成。",
                ))

        # 保存扫描发现
        loop.run_until_complete(_save_findings(
            session_factory=session_factory,
            scan_task_id=scan_task_id,
            findings=findings
        ))
        
        # 对关键漏洞进行详细分析（生成修复建议）
        if findings:
            scan_logger.llm("🔍 开始分析关键漏洞", "为高危漏洞生成修复建议...")
            loop.run_until_complete(_analyze_vulnerabilities(
                session_factory=session_factory,
                scan_task_id=scan_task_id,
                scan_logger=scan_logger
            ))
            loop.run_until_complete(_analyze_attack_path(
                session_factory=session_factory,
                scan_task_id=scan_task_id,
                target=target,
                findings=findings,
                scan_logger=scan_logger
            ))
        if config.get("enable_sub_agents", True):
            loop.run_until_complete(_update_sub_agent(
                session_factory,
                scan_task_id,
                "reporting-subagent",
                status="completed",
                progress=100,
                findings_count=len(findings),
                summary=f"报告整理完成，共纳入 {len(findings)} 个去重发现。",
            ))
        
        loop.run_until_complete(_update_scan_status(
            session_factory=session_factory,
            scan_task_id=scan_task_id,
            status=ScanStatus.COMPLETED,
            completed_at=datetime.utcnow(),
            llm_summary=llm_summary,
            risk_score=risk_score,
        ))
        
        scan_logger.success(
            "🎉 扫描任务完成", 
            f"共发现 {len(findings)} 个结果" + (f"，风险评分 {risk_score}/100" if risk_score else "")
        )
        
    except Exception as e:
        logger.exception(f"Scan task failed for {scan_task_id}: {e}")
        scan_logger.error("💥 扫描任务失败", str(e))
        try:
            loop.run_until_complete(_update_scan_status(
                session_factory=session_factory,
                scan_task_id=scan_task_id,
                status=ScanStatus.FAILED,
                completed_at=datetime.utcnow(),
            ))
        except Exception as status_error:
            logger.error(f"Failed to mark task {scan_task_id} as failed: {status_error}")
        raise
    finally:
        scan_logger.close()
        loop.run_until_complete(engine.dispose())
        asyncio.set_event_loop(None)
        loop.close()

    # 返回结果
    return {
        "scan_task_id": scan_task_id,
        "findings_count": len(findings),
        "findings": [
            {
                "id": str(uuid.uuid4()),
                "name": f.name,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "location": f.location,
                "evidence": f.evidence[:1000] if f.evidence else None,
                "raw_data": f.raw_data,
            }
            for f in findings
        ],
        "llm_summary": llm_summary,
        "risk_score": risk_score,
        "errors": errors,
    }


@celery_app.task(name="tasks.analyze_vulnerability")
def analyze_vulnerability(vuln_id: str, name: str, category: str, evidence: str, context: str = ""):
    """单独分析一个漏洞"""
    async def analyze():
        analyzer = get_analyzer()
        return await analyzer.analyze_vulnerability(
            vuln_name=name,
            vuln_type=category,
            evidence=evidence,
            context=context
        )
    
    try:
        result = run_async(analyze())
        return {
            "vuln_id": vuln_id,
            "summary": result.summary,
            "severity_assessment": result.severity_assessment,
            "exploitation_difficulty": result.exploitation_difficulty,
            "business_impact": result.business_impact,
            "remediation_steps": result.remediation_steps,
            "false_positive_likelihood": result.false_positive_likelihood,
        }
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {e}")
        return {"vuln_id": vuln_id, "error": str(e)}


@celery_app.task(bind=True, name="tasks.resume_scan")
def resume_scan(self, scan_task_id: str):
    """恢复暂停的扫描任务"""
    logger.info(f"Resuming scan task {scan_task_id}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    engine, session_factory = create_celery_session()
    scan_logger = get_scan_logger(scan_task_id)
    
    try:
        # 获取用户回复和 agent 状态
        user_reply, agent_state, scan_context, saved_findings = loop.run_until_complete(
            _get_pending_user_reply(session_factory, scan_task_id)
        )
        
        if not user_reply or not agent_state:
            logger.error(f"No pending user reply found for scan {scan_task_id}")
            return {"error": "No pending user reply found"}
        
        # 获取扫描任务信息
        async def get_scan_task():
            async with session_factory() as session:
                result = await session.execute(
                    select(ScanTask).where(ScanTask.id == scan_task_id)
                )
                return result.scalar_one_or_none()
        
        scan_task = loop.run_until_complete(get_scan_task())
        if not scan_task:
            logger.error(f"Scan task not found: {scan_task_id}")
            return {"error": "Scan task not found"}
        
        target = scan_task.target
        config = scan_task.config or {}
        
        # 更新状态为 running
        loop.run_until_complete(_update_scan_status(
            session_factory=session_factory,
            scan_task_id=scan_task_id,
            status=ScanStatus.RUNNING,
        ))
        
        scan_logger.info("▶️ 扫描恢复", f"用户回复: {user_reply[:100]}...")
        self.update_state(state="RUNNING", meta={"phase": "ai_agent_resumed"})
        
        # 创建日志回调
        async def agent_log_callback(log_type: str, message: str, details: str = None, tool: str = None):
            if log_type == "llm":
                scan_logger.llm(message, details)
            elif log_type == "tool":
                scan_logger.tool(tool or "agent", message, details)
            elif log_type == "output":
                scan_logger.output(tool or "agent", message, details)
            elif log_type == "error":
                scan_logger.error(message, details)
            elif log_type == "success":
                scan_logger.success(message, details)
            else:
                scan_logger.info(message, details)
        
        # 恢复 AI Agent
        custom_prompt = config.get("ai_custom_prompt")
        max_iterations = config.get("ai_max_iterations", 0)
        
        # 预加载 Agent 所需的配置
        llm_config, search_config = loop.run_until_complete(
            _fetch_agent_configs(session_factory)
        )
        
        agent_result = loop.run_until_complete(run_security_agent(
            target=target,
            scan_context=scan_context,
            log_callback=agent_log_callback,
            max_iterations=max_iterations,
            custom_prompt=custom_prompt,
            restored_state=agent_state,
            user_reply=user_reply,
            session_factory=session_factory,
            llm_config=llm_config,
            search_config=search_config
        ))
        
        # 检查是否再次暂停
        if agent_result.get("paused"):
            scan_logger.info("⏸️ AI Agent 再次暂停", f"等待用户回复: {agent_result.get('question')}")
            
            loop.run_until_complete(_save_agent_pause(
                session_factory=session_factory,
                scan_task_id=scan_task_id,
                question=agent_result.get("question"),
                context=agent_result.get("context"),
                options=agent_result.get("options"),
                agent_state=agent_result.get("agent_state"),
                scan_context=scan_context,
                findings=[]  # TODO: 从 saved_findings 恢复
            ))
            
            loop.run_until_complete(_update_scan_status(
                session_factory=session_factory,
                scan_task_id=scan_task_id,
                status=ScanStatus.PAUSED,
            ))
            
            return {
                "scan_task_id": scan_task_id,
                "status": "paused",
                "question": agent_result.get("question"),
            }
        
        # Agent 完成，继续 LLM 总结
        llm_summary = None
        risk_score = None
        
        if agent_result.get("summary"):
            scan_context["agent_summary"] = agent_result["summary"]
            scan_context["agent_tools_used"] = agent_result.get("tools_used", [])
            scan_context["agent_iterations"] = agent_result.get("iterations", 0)
        
        # LLM 总结
        if scan_context.get("agent_summary"):
            scan_logger.llm("🤖 AI 开始生成扫描报告", "综合 AI Agent 测试结果")
            
            try:
                analyzer = get_analyzer()
                scan_info = {
                    "scan_type": scan_task.scan_type,
                    "duration": "N/A",
                    "ai_agent_summary": scan_context.get("agent_summary"),
                    "ai_agent_tools": scan_context.get("agent_tools_used", []),
                }
                
                result = loop.run_until_complete(analyzer.summarize_scan(
                    target=target,
                    vulnerabilities=[],
                    scan_info=scan_info
                ))
                
                llm_summary = result.executive_summary
                risk_score = result.risk_score
                
                scan_logger.llm("📥 AI 分析完成", f"风险评分: {risk_score}/100")
                
            except Exception as e:
                logger.error(f"LLM analysis failed: {e}")
                llm_summary = _condense_agent_summary(scan_context.get("agent_summary")) or "AI Agent 已完成测试，但未生成可读摘要。"
        
        # 更新扫描状态为完成
        loop.run_until_complete(_update_scan_status(
            session_factory=session_factory,
            scan_task_id=scan_task_id,
            status=ScanStatus.COMPLETED,
            completed_at=datetime.utcnow(),
            llm_summary=llm_summary,
            risk_score=risk_score,
        ))
        
        scan_logger.success("🎉 扫描任务完成", f"风险评分: {risk_score}/100" if risk_score else "")
        
        return {
            "scan_task_id": scan_task_id,
            "status": "completed",
            "llm_summary": llm_summary,
            "risk_score": risk_score,
        }
        
    except Exception as e:
        logger.exception(f"Resume scan failed for {scan_task_id}: {e}")
        scan_logger.error("💥 恢复扫描失败", str(e))
        loop.run_until_complete(_update_scan_status(
            session_factory=session_factory,
            scan_task_id=scan_task_id,
            status=ScanStatus.FAILED,
            completed_at=datetime.utcnow(),
        ))
        raise
    finally:
        scan_logger.close()
        loop.run_until_complete(engine.dispose())
        asyncio.set_event_loop(None)
        loop.close()
