"""LLM integration for vulnerability analysis"""
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from loguru import logger
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal


class VulnAnalysisResult(BaseModel):
    """LLM 漏洞分析结果结构"""
    summary: str = Field(description="漏洞概述")
    severity_assessment: str = Field(description="严重性评估")
    exploitation_difficulty: str = Field(description="利用难度")
    business_impact: str = Field(description="业务影响")
    remediation_steps: list[str] = Field(description="修复步骤")
    false_positive_likelihood: int = Field(description="误报可能性 0-100")


class ScanSummaryResult(BaseModel):
    """扫描结果总结"""
    executive_summary: str = Field(description="执行摘要")
    risk_score: int = Field(description="风险评分 0-100")
    critical_findings: list[str] = Field(description="关键发现")
    attack_surface_analysis: str = Field(description="攻击面分析")
    priority_recommendations: list[str] = Field(description="优先修复建议")


# ============ 攻击路径分析模型 ============

class AttackPathItem(BaseModel):
    """攻击路径中的单个项目"""
    id: str = Field(description="项目唯一标识")
    name: str = Field(description="项目名称")
    severity: Optional[str] = Field(default=None, description="严重程度: critical/high/medium/low/info")
    details: Optional[str] = Field(default=None, description="详细说明")


class AttackPhase(BaseModel):
    """攻击阶段"""
    id: str = Field(description="阶段标识: recon/vuln/exploit/impact")
    name: str = Field(description="阶段名称")
    description: str = Field(description="阶段描述")
    items: list[AttackPathItem] = Field(description="该阶段的具体项目")


class AttackChainStep(BaseModel):
    """攻击链中的单个步骤"""
    order: int = Field(description="步骤顺序")
    action: str = Field(description="攻击动作")
    vulnerability: Optional[str] = Field(default=None, description="利用的漏洞")
    result: str = Field(description="执行结果")


class AttackChain(BaseModel):
    """完整的攻击链"""
    id: str = Field(description="攻击链标识")
    name: str = Field(description="攻击链名称")
    description: str = Field(description="攻击链描述")
    steps: list[AttackChainStep] = Field(description="攻击步骤列表")
    likelihood: str = Field(description="发生可能性: high/medium/low")
    impact: str = Field(description="影响程度: critical/high/medium/low")


class RiskAssessment(BaseModel):
    """风险评估"""
    overall_risk: str = Field(description="整体风险等级: critical/high/medium/low")
    risk_score: int = Field(description="风险评分 0-100")
    summary: str = Field(description="风险摘要")
    critical_paths: list[str] = Field(description="关键攻击路径")
    recommendations: list[str] = Field(description="安全建议")


class AttackPathResult(BaseModel):
    """攻击路径分析结果"""
    phases: list[AttackPhase] = Field(description="攻击阶段列表")
    attack_chains: list[AttackChain] = Field(description="攻击链列表")
    risk_assessment: RiskAssessment = Field(description="风险评估")


class VulnAnalyzer:
    """LLM 驱动的漏洞分析器"""
    
    def __init__(self, db: AsyncSession = None, session_factory = None):
        """
        Args:
            db: 可选的数据库会话（用于非异步上下文）
            session_factory: 数据库会话工厂（用于异步上下文）
        """
        self.db = db
        self.session_factory = session_factory or AsyncSessionLocal
        self.llm = None
        self.llm_available = False
        self._initialized = False
    
    def _filter_reliable_vulnerabilities(self, vulnerabilities: list[dict]) -> list[dict]:
        """过滤可靠的漏洞：优先使用确认的漏洞，过滤高误报率"""
        # 首先提取所有确认的漏洞
        confirmed = [v for v in vulnerabilities if v.get('category') == 'ai_confirmed_vulnerability']
        
        # 如果有确认的漏洞，主要使用它们
        if confirmed:
            logger.info(f"Found {len(confirmed)} confirmed vulnerabilities")
            # 也可以包含一些低误报率的潜在漏洞作为补充
            reliable_potential = [
                v for v in vulnerabilities 
                if v.get('category') != 'ai_confirmed_vulnerability' 
                and v.get('llm_false_positive_score', 100) < 40
            ]
            return confirmed + reliable_potential[:5]  # 最多加5个可靠的潜在漏洞
        
        # 如果没有确认漏洞，只使用低误报率的潜在漏洞
        reliable = [
            v for v in vulnerabilities 
            if v.get('llm_false_positive_score', 100) < 50
        ]
        
        if reliable:
            logger.info(f"No confirmed vulnerabilities, using {len(reliable)} reliable potential vulnerabilities")
            return reliable
        
        # 如果所有漏洞都是高误报率，返回空列表或最多2个作为参考
        logger.warning("All vulnerabilities have high false positive scores")
        return vulnerabilities[:2] if vulnerabilities else []
    
    async def _ensure_initialized(self):
        """确保 LLM 已初始化（从数据库加载配置）"""
        if self._initialized:
            return
        
        from app.api.settings import get_active_llm_config
        
        # 始终创建新的会话以避免异步操作冲突
        # 不要使用传入的 self.db，因为它可能在其他事务中
        async with self.session_factory() as db:
            db_config = await get_active_llm_config(db, role="sub")
        
        if not db_config:
            logger.warning("No active LLM config found in database, LLM analysis will be disabled")
            self.llm_available = False
            self._initialized = True
            return
        
        try:
            self.llm = ChatOpenAI(
                model=db_config.model,
                temperature=db_config.temperature / 100,
                api_key=db_config.api_key,
                base_url=db_config.api_base_url,
                max_tokens=db_config.max_tokens,
            )
            self.llm_available = True
            logger.info(f"Sub-agent analyzer LLM initialized with config: {db_config.name}")
        except Exception as e:
            logger.error(f"Failed to initialize LLM: {e}")
            self.llm = None
            self.llm_available = False
        
        self._initialized = True
    
    async def analyze_vulnerability(
        self,
        vuln_name: str,
        vuln_type: str,
        evidence: str,
        context: str = ""
    ) -> VulnAnalysisResult:
        """分析单个漏洞"""
        # 确保已初始化
        await self._ensure_initialized()
        
        # 如果 LLM 不可用，返回基础分析
        if not self.llm_available or not self.llm:
            return self._get_default_vuln_analysis(vuln_name, vuln_type, evidence)
        
        parser = PydanticOutputParser(pydantic_object=VulnAnalysisResult)
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一名资深的安全研究员和渗透测试专家。
请基于提供的漏洞信息进行深度分析。
注意：
1. 客观评估漏洞的真实风险
2. 考虑误报的可能性
3. 提供可操作的修复建议

{format_instructions}"""),
            ("human", """请分析以下漏洞:

漏洞名称: {vuln_name}
漏洞类型: {vuln_type}
证据/Payload: 
```
{evidence}
```
上下文信息: {context}
""")
        ])
        
        chain = prompt | self.llm | parser
        
        try:
            result = await chain.ainvoke({
                "vuln_name": vuln_name,
                "vuln_type": vuln_type,
                "evidence": evidence,
                "context": context,
                "format_instructions": parser.get_format_instructions()
            })
            return result
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            raise
    
    async def summarize_scan(
        self,
        target: str,
        vulnerabilities: list[dict],
        scan_info: dict
    ) -> ScanSummaryResult:
        """生成扫描结果总结"""
        # 确保已初始化
        await self._ensure_initialized()
        
        # 如果 LLM 不可用，返回基础总结
        if not self.llm_available or not self.llm:
            return self._get_default_summary(target, vulnerabilities, scan_info)
        
        parser = PydanticOutputParser(pydantic_object=ScanSummaryResult)
        
        # 构建漏洞摘要
        vuln_summary = "\n".join([
            f"- [{v.get('severity', 'UNKNOWN')}] {v.get('name', 'Unknown')}: {v.get('location', 'N/A')}"
            for v in vulnerabilities[:50]  # 限制数量避免 token 过多
        ])
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一名安全顾问，正在为客户生成漏洞扫描报告摘要。
请提供：
1. 面向管理层的执行摘要（用通俗、自然的中文，2-4 句，不要 Markdown、列表或标题；只保留用户需要的信息，避免技术细节）
2. 基于发现的实际漏洞给出风险评分（0-100）
3. 突出最关键的安全问题
4. 优先级排序的修复建议

重要指导：
- 如果未发现漏洞，风险评分应为 0-10 分（低风险）
- 如果只发现 info/low 级漏洞，风险评分应为 10-30 分
- 如果发现 medium 级漏洞，风险评分应为 30-60 分
- 如果发现 high 级漏洞，风险评分应为 60-80 分
- 如果发现 critical 级漏洞，风险评分应为 80-100 分
- 风险评分必须与实际发现的漏洞严重程度相符

{format_instructions}"""),
            ("human", """扫描目标: {target}

扫描信息:
- 扫描类型: {scan_type}
- 扫描时长: {duration}
- 发现漏洞总数: {vuln_count}

发现的漏洞:
{vuln_summary}

请生成分析报告。
""")
        ])
        
        chain = prompt | self.llm | parser
        
        try:
            result = await chain.ainvoke({
                "target": target,
                "scan_type": scan_info.get("scan_type", "unknown"),
                "duration": scan_info.get("duration", "N/A"),
                "vuln_count": len(vulnerabilities),
                "vuln_summary": vuln_summary or "未发现漏洞",
                "format_instructions": parser.get_format_instructions()
            })
            
            # 验证风险评分与漏洞数量的一致性
            result = self._validate_risk_score(result, vulnerabilities)
            return result
        except Exception as e:
            logger.error(f"LLM summarization failed: {e}")
            raise
    
    async def filter_false_positives(
        self,
        vulnerabilities: list[dict]
    ) -> list[dict]:
        """使用 LLM 过滤误报"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一名漏洞分析专家。
请判断以下漏洞报告是否为误报（false positive）。
考虑因素：
1. 证据是否充分
2. 漏洞特征是否明确
3. 上下文是否合理

对每个漏洞返回 JSON 格式：
{{"id": "漏洞ID", "is_false_positive": true/false, "confidence": 0-100, "reason": "判断理由"}}
"""),
            ("human", "漏洞列表：\n{vulns}")
        ])
        
        # 批量处理，每次最多 10 个
        results = []
        for i in range(0, len(vulnerabilities), 10):
            batch = vulnerabilities[i:i+10]
            # ... 处理逻辑
        
        return results
    
    async def analyze_attack_path(
        self,
        target: str,
        vulnerabilities: list[dict],
        open_ports: list[dict],
    ) -> AttackPathResult:
        """分析攻击路径，生成攻击链和风险评估"""
        # 确保已初始化
        await self._ensure_initialized()
        
        # 过滤可靠的漏洞：优先使用确认的漏洞，过滤高误报率
        reliable_vulns = self._filter_reliable_vulnerabilities(vulnerabilities)
        
        # 如果过滤后没有可靠漏洞，但有潜在漏洞，降低评分权重
        has_confirmed = any(v.get('category') == 'ai_confirmed_vulnerability' for v in reliable_vulns)
        
        # 如果 LLM 不可用，直接返回默认分析
        if not self.llm_available or not self.llm:
            logger.warning("LLM not available, using default attack path analysis")
            return self._get_default_attack_path(target, reliable_vulns, open_ports, has_confirmed)
        
        parser = PydanticOutputParser(pydantic_object=AttackPathResult)
        
        # 构建漏洞信息，优先展示确认的漏洞
        confirmed_vulns = [v for v in reliable_vulns if v.get('category') == 'ai_confirmed_vulnerability']
        potential_vulns = [v for v in reliable_vulns if v.get('category') != 'ai_confirmed_vulnerability']
        
        vuln_sections = []
        if confirmed_vulns:
            vuln_sections.append("### 已确认漏洞（高置信度）")
            for v in confirmed_vulns[:15]:
                vuln_sections.append(
                    f"- [{v.get('severity', 'unknown').upper()}] {v.get('name', 'Unknown')}\n"
                    f"  位置: {v.get('location', 'N/A')}\n"
                    f"  类型: {v.get('category', 'N/A')}\n"
                    f"  描述: {v.get('description', 'N/A')[:200]}"
                )
        
        if potential_vulns:
            vuln_sections.append("\n### 潜在漏洞（需进一步验证）")
            for v in potential_vulns[:15]:
                false_positive_score = v.get('llm_false_positive_score', 0)
                vuln_sections.append(
                    f"- [{v.get('severity', 'unknown').upper()}] {v.get('name', 'Unknown')} (误报可能性: {false_positive_score}%)\n"
                    f"  位置: {v.get('location', 'N/A')}\n"
                    f"  类型: {v.get('category', 'N/A')}"
                )
        
        vuln_info = "\n".join(vuln_sections) if vuln_sections else "未发现可靠漏洞"
        
        # 构建端口信息
        port_info = "\n".join([
            f"- {p.get('name', 'Unknown port')}: {p.get('location', 'N/A')} - {p.get('description', '')[:100]}"
            for p in open_ports[:20]
        ]) or "未发现开放端口"
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一名资深渗透测试专家和安全架构师，正在为客户进行攻击路径分析。

基于扫描发现的漏洞和开放端口，你需要：

1. **攻击阶段分析** (phases)：将发现分为四个阶段
   - recon (信息收集): 发现的开放端口和服务
   - vuln (漏洞发现): 识别的安全漏洞
   - exploit (漏洞利用): 可被利用的攻击点
   - impact (潜在影响): 攻击成功后的影响

2. **攻击链构建** (attack_chains)：基于漏洞组合构建可行的攻击路径
   - **优先基于"已确认漏洞"构建攻击链**，这些漏洞已被验证可利用
   - 每条攻击链应该是一个完整的攻击场景
   - 步骤应该是有序的、逻辑连贯的
   - 评估每条攻击链的可能性和影响

3. **风险评估** (risk_assessment)：给出整体风险评估
   - **已确认漏洞代表真实威胁，应给予高风险评分**
   - **潜在漏洞可能误报，仅作为参考**
   - 识别最危险的攻击路径
   - 提供针对性的安全建议

风险评分建议：
- 存在严重级别（critical）已确认漏洞：80-100分
- 存在高危级别（high）已确认漏洞：60-80分
- 仅有潜在漏洞：20-40分
- 无可靠漏洞：0-20分

注意：
- 如果没有发现严重漏洞，攻击链可以为空
- 保持专业、客观的分析
- 每个 ID 使用简单的标识如 "recon", "chain-1", "item-1" 等

{format_instructions}"""),
            ("human", """目标: {target}

## 开放端口和服务
{port_info}

## 发现的漏洞
{vuln_info}

请进行攻击路径分析。
""")
        ])
        
        chain = prompt | self.llm | parser
        
        try:
            result = await chain.ainvoke({
                "target": target,
                "port_info": port_info,
                "vuln_info": vuln_info,
                "format_instructions": parser.get_format_instructions()
            })
            return result
        except Exception as e:
            logger.error(f"Attack path analysis failed: {e}")
            # 返回默认结果
            return self._get_default_attack_path(target, reliable_vulns, open_ports, has_confirmed)
    
    def _get_default_attack_path(
        self,
        target: str,
        vulnerabilities: list[dict],
        open_ports: list[dict],
        has_confirmed: bool = False
    ) -> AttackPathResult:
        """LLM 失败时生成默认的攻击路径分析"""
        # 按严重程度分类
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'medium']
        
        # 构建阶段
        phases = [
            AttackPhase(
                id="recon",
                name="信息收集",
                description="发现目标开放的端口和服务",
                items=[
                    AttackPathItem(
                        id=f"port-{i}",
                        name=p.get('name', 'Unknown').replace('Open port: ', ''),
                        details=p.get('description', '')
                    )
                    for i, p in enumerate(open_ports[:10])
                ]
            ),
            AttackPhase(
                id="vuln",
                name="漏洞发现",
                description="识别可利用的安全漏洞",
                items=[
                    AttackPathItem(
                        id=f"vuln-{i}",
                        name=v.get('name', 'Unknown'),
                        severity=v.get('severity'),
                        details=v.get('location', '')
                    )
                    for i, v in enumerate((critical_vulns + high_vulns + medium_vulns)[:15])
                ]
            ),
            AttackPhase(
                id="exploit",
                name="漏洞利用",
                description="可被利用进行攻击的路径",
                items=[
                    AttackPathItem(
                        id=f"exploit-{i}",
                        name=v.get('name', 'Unknown'),
                        severity=v.get('severity'),
                        details=v.get('description', '')[:200]
                    )
                    for i, v in enumerate(critical_vulns[:5])
                ]
            ),
            AttackPhase(
                id="impact",
                name="潜在影响",
                description="攻击成功后的影响范围",
                items=self._infer_impacts(vulnerabilities)
            )
        ]
        
        # 构建基础攻击链
        attack_chains = []
        if critical_vulns:
            attack_chains.append(AttackChain(
                id="chain-1",
                name="高危漏洞利用链",
                description="通过严重漏洞获取系统访问权限",
                steps=[
                    AttackChainStep(order=1, action="端口扫描", result="发现开放服务"),
                    AttackChainStep(order=2, action="漏洞扫描", vulnerability=critical_vulns[0].get('name'), result="发现严重漏洞"),
                    AttackChainStep(order=3, action="漏洞利用", vulnerability=critical_vulns[0].get('name'), result="获取访问权限"),
                ],
                likelihood="high" if len(critical_vulns) > 1 else "medium",
                impact="critical"
            ))
        
        # 风险评估
        if critical_vulns:
            overall_risk = "critical"
            risk_score = 90
        elif high_vulns:
            overall_risk = "high"
            risk_score = 70
        elif medium_vulns:
            overall_risk = "medium"
            risk_score = 50
        else:
            overall_risk = "low"
            risk_score = 20
        
        risk_assessment = RiskAssessment(
            overall_risk=overall_risk,
            risk_score=risk_score,
            summary=f"目标 {target} 发现 {len(critical_vulns)} 个严重漏洞，{len(high_vulns)} 个高危漏洞",
            critical_paths=[v.get('name', '') for v in critical_vulns[:3]],
            recommendations=[
                "优先修复严重和高危漏洞",
                "加强网络访问控制",
                "定期进行安全扫描"
            ]
        )
        
        return AttackPathResult(
            phases=phases,
            attack_chains=attack_chains,
            risk_assessment=risk_assessment
        )
    
    def _infer_impacts(self, vulnerabilities: list[dict]) -> list[AttackPathItem]:
        """基于漏洞推断潜在影响"""
        impacts = []
        vuln_names = ' '.join([v.get('name', '').lower() for v in vulnerabilities])
        vuln_cats = ' '.join([v.get('category', '').lower() for v in vulnerabilities])
        combined = vuln_names + ' ' + vuln_cats
        
        if any(kw in combined for kw in ['rce', 'remote code', 'command injection', 'code execution']):
            impacts.append(AttackPathItem(
                id="impact-rce",
                name="远程代码执行",
                severity="critical",
                details="攻击者可能获得服务器完全控制权"
            ))
        if any(kw in combined for kw in ['sql', 'sqli', 'injection']):
            impacts.append(AttackPathItem(
                id="impact-data",
                name="数据库泄露",
                severity="critical",
                details="敏感数据可能被窃取或篡改"
            ))
        if any(kw in combined for kw in ['xss', 'cross-site', 'script']):
            impacts.append(AttackPathItem(
                id="impact-xss",
                name="用户会话劫持",
                severity="high",
                details="用户 Cookie 和凭据可能被窃取"
            ))
        if any(kw in combined for kw in ['auth', 'login', 'credential', 'bypass']):
            impacts.append(AttackPathItem(
                id="impact-auth",
                name="未授权访问",
                severity="high",
                details="攻击者可能绕过身份验证"
            ))
        if any(kw in combined for kw in ['ssrf', 'server-side']):
            impacts.append(AttackPathItem(
                id="impact-ssrf",
                name="内网渗透",
                severity="high",
                details="可能通过 SSRF 访问内部资源"
            ))
        if any(kw in combined for kw in ['file', 'upload', 'path', 'traversal', 'lfi', 'rfi']):
            impacts.append(AttackPathItem(
                id="impact-file",
                name="文件系统访问",
                severity="high",
                details="敏感文件可能被读取或上传恶意文件"
            ))
        
        if not impacts and vulnerabilities:
            impacts.append(AttackPathItem(
                id="impact-general",
                name="系统安全风险",
                severity="medium",
                details="存在被攻击利用的可能性"
            ))
        
        return impacts
    
    def _get_default_vuln_analysis(
        self,
        vuln_name: str,
        vuln_type: str,
        evidence: str
    ) -> VulnAnalysisResult:
        """LLM 不可用时的默认漏洞分析"""
        # 基于类型评估严重程度
        severity_map = {
            "sql_injection": "critical",
            "xss": "high",
            "csrf": "medium",
            "info_disclosure": "low",
        }
        severity = severity_map.get(vuln_type.lower(), "medium")
        
        return VulnAnalysisResult(
            summary=f"发现 {vuln_name}，类型为 {vuln_type}",
            severity_assessment=f"严重程度: {severity}",
            exploitation_difficulty="需要进一步人工验证",
            business_impact="可能影响系统安全性和数据完整性",
            remediation_steps=[
                "审查相关代码",
                "应用安全最佳实践",
                "进行安全测试验证",
                "部署修复后重新扫描"
            ],
            false_positive_likelihood=30
        )
    
    def _validate_risk_score(
        self,
        result: ScanSummaryResult,
        vulnerabilities: list[dict]
    ) -> ScanSummaryResult:
        """验证并调整风险评分，确保与实际漏洞严重程度相符"""
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        medium_count = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
        low_count = sum(1 for v in vulnerabilities if v.get('severity') in ['low', 'info'])
        
        # 根据漏洞严重程度强制执行上限
        enforced_score = result.risk_score
        
        if critical_count == 0:
            # 没有严重漏洞
            if high_count == 0:
                # 没有高危漏洞
                if medium_count == 0:
                    # 只有低级/信息性漏洞，上限 15 分
                    enforced_score = min(result.risk_score, 15)
                else:
                    # 有中等漏洞，上限 40 分
                    enforced_score = min(result.risk_score, 40)
            else:
                # 有高危漏洞，上限 75 分
                enforced_score = min(result.risk_score, 75)
        # 如果有 critical，允许 80-100 分
        
        if enforced_score != result.risk_score:
            old_score = result.risk_score
            result.risk_score = enforced_score
            logger.warning(
                f"Risk score capped from {old_score} to {enforced_score}. "
                f"Vulnerabilities: {critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low/info"
            )
        
        return result

    def _get_default_summary(
        self,
        target: str,
        vulnerabilities: list[dict],
        scan_info: dict
    ) -> ScanSummaryResult:
        """LLM 不可用时的默认扫描总结"""
        vuln_count = len(vulnerabilities)
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        
        # 计算风险评分
        risk_score = min(100, critical_count * 20 + high_count * 10 + vuln_count * 2)
        
        # 收集关键发现
        critical_findings = [
            f"{v.get('name')}: {v.get('location')}"
            for v in vulnerabilities
            if v.get('severity') in ['critical', 'high']
        ][:5]
        
        if vuln_count == 0:
            summary = f"已完成对 {target} 的安全扫描，未发现明显漏洞。当前整体风险较低。"
        else:
            summary = (
                f"已完成对 {target} 的安全扫描，发现 {vuln_count} 个安全问题，"
                f"其中严重 {critical_count} 个、高危 {high_count} 个。"
                "建议优先处理高风险问题并安排后续复测。"
            )

        return ScanSummaryResult(
            executive_summary=summary,
            risk_score=risk_score,
            critical_findings=critical_findings or ["未发现严重安全问题"],
            attack_surface_analysis="目标暴露了多个潜在攻击面，建议优先处理高危漏洞",
            priority_recommendations=[
                "优先修复所有严重和高危漏洞",
                "加强输入验证和输出编码",
                "更新过时的软件组件",
                "实施安全监控和日志审计"
            ]
        )


# 单例实例
_analyzer: VulnAnalyzer | None = None


def get_analyzer() -> VulnAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = VulnAnalyzer()
    return _analyzer
