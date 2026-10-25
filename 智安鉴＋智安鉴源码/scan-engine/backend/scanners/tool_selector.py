"""LLM-based security tool selector - 智能选择扫描工具"""
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

from loguru import logger


@dataclass
class ToolSelection:
    """工具选择结果"""
    tools: List[str]
    reason: str
    confidence: str  # high, medium, low


# 工具能力库
TOOL_CAPABILITIES = {
    "nmap": {
        "name": "Nmap",
        "category": "port_scanning",
        "description": "网络扫描和服务识别工具",
        "use_cases": ["端口扫描", "服务识别", "版本检测", "操作系统检测", "脚本扫描"],
        "targets": ["IP地址", "域名", "IP范围"],
        "output": "开放端口、运行服务、版本信息、漏洞提示"
    },
    "masscan": {
        "name": "Masscan",
        "category": "port_scanning",
        "description": "超高速端口扫描器",
        "use_cases": ["大规模端口扫描", "快速主机发现"],
        "targets": ["IP地址", "IP范围", "大型网络"],
        "output": "开放端口列表"
    },
    "nuclei": {
        "name": "Nuclei",
        "category": "vulnerability_scanning",
        "description": "基于模板的快速漏洞扫描工具",
        "use_cases": ["Web漏洞检测", "已知CVE检测", "错误配置检测", "暴露的服务"],
        "targets": ["HTTP/HTTPS URL", "Web应用"],
        "output": "漏洞详情、严重级别、PoC"
    },
    "nikto": {
        "name": "Nikto",
        "category": "web_scanning",
        "description": "Web服务器扫描工具",
        "use_cases": ["Web服务器漏洞", "配置问题", "过时文件", "危险CGI"],
        "targets": ["HTTP/HTTPS URL"],
        "output": "Web服务器问题列表"
    },
    "dirb": {
        "name": "Dirb",
        "category": "web_scanning",
        "description": "Web目录和文件暴力破解",
        "use_cases": ["隐藏目录发现", "备份文件查找", "管理面板发现"],
        "targets": ["HTTP/HTTPS URL"],
        "output": "发现的目录和文件"
    },
    "gobuster": {
        "name": "Gobuster",
        "category": "web_scanning",
        "description": "目录/DNS/VHost暴力破解工具",
        "use_cases": ["目录枚举", "DNS子域名", "VHost发现"],
        "targets": ["HTTP/HTTPS URL", "域名"],
        "output": "发现的资源列表"
    },
    "sqlmap": {
        "name": "SQLMap",
        "category": "exploitation",
        "description": "SQL注入检测和利用工具",
        "use_cases": ["SQL注入检测", "数据库指纹识别", "数据提取"],
        "targets": ["HTTP/HTTPS URL（带参数）"],
        "output": "注入点、数据库类型、可提取数据"
    },
    "sslscan": {
        "name": "SSLScan",
        "category": "ssl_tls",
        "description": "SSL/TLS配置扫描器",
        "use_cases": ["SSL/TLS漏洞", "密码套件检查", "证书验证"],
        "targets": ["HTTPS URL", "SSL/TLS服务"],
        "output": "支持的协议、密码套件、证书信息"
    },
    "whatweb": {
        "name": "WhatWeb",
        "category": "information_gathering",
        "description": "Web技术识别工具",
        "use_cases": ["CMS识别", "框架检测", "插件识别", "版本指纹"],
        "targets": ["HTTP/HTTPS URL"],
        "output": "Web技术栈、版本、插件"
    },
    "whois": {
        "name": "Whois",
        "category": "information_gathering",
        "description": "域名注册信息查询",
        "use_cases": ["域名所有者", "注册时间", "DNS服务器"],
        "targets": ["域名"],
        "output": "注册信息、联系方式、DNS"
    },
    "subfinder": {
        "name": "Subfinder",
        "category": "information_gathering",
        "description": "子域名发现工具",
        "use_cases": ["子域名枚举", "资产发现"],
        "targets": ["域名"],
        "output": "子域名列表"
    },
    "httpx": {
        "name": "httpx",
        "category": "information_gathering",
        "description": "HTTP探测工具",
        "use_cases": ["HTTP服务探测", "标题抓取", "技术识别"],
        "targets": ["URL列表", "主机列表"],
        "output": "HTTP响应信息、服务器头、标题"
    },
    "hydra": {
        "name": "Hydra",
        "category": "password_cracking",
        "description": "网络服务暴力破解工具",
        "use_cases": ["SSH/FTP/HTTP等服务的密码破解"],
        "targets": ["网络服务端口"],
        "output": "有效凭据"
    },
}


def analyze_target(target: str) -> Dict[str, any]:
    """分析目标类型和特征
    
    Args:
        target: 扫描目标（URL、IP、域名等）
        
    Returns:
        分析结果字典
    """
    result = {
        "type": "unknown",
        "is_url": False,
        "is_ip": False,
        "is_domain": False,
        "scheme": None,
        "has_path": False,
        "has_params": False,
        "port": None,
    }
    
    # 尝试解析为 URL
    if target.startswith(("http://", "https://")):
        result["is_url"] = True
        parsed = urlparse(target)
        result["scheme"] = parsed.scheme
        result["type"] = "url"
        result["has_path"] = bool(parsed.path and parsed.path != "/")
        result["has_params"] = bool(parsed.query)
        result["port"] = parsed.port
        
        # 检查主机名是 IP 还是域名
        hostname = parsed.hostname or ""
        if _is_ip(hostname):
            result["is_ip"] = True
        else:
            result["is_domain"] = True
    
    # 检查是否是纯 IP
    elif _is_ip(target):
        result["is_ip"] = True
        result["type"] = "ip"
    
    # 检查是否是域名
    elif "." in target and not "/" in target:
        result["is_domain"] = True
        result["type"] = "domain"
    
    return result


def _is_ip(s: str) -> bool:
    """简单的 IP 地址检查"""
    import re
    # IPv4
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', s):
        return True
    # IPv6 (简化)
    if ':' in s and re.match(r'^[0-9a-fA-F:]+$', s):
        return True
    return False


def build_llm_prompt(target: str, scan_type: str, target_analysis: Dict) -> str:
    """构建 LLM 提示词
    
    Args:
        target: 扫描目标
        scan_type: 扫描类型（quick/full/custom）
        target_analysis: 目标分析结果
        
    Returns:
        LLM 提示词
    """
    # 构建工具能力描述
    tools_desc = []
    for tool_name, cap in TOOL_CAPABILITIES.items():
        tools_desc.append(
            f"- **{cap['name']}** ({tool_name}): {cap['description']}\n"
            f"  用途: {', '.join(cap['use_cases'])}\n"
            f"  适用目标: {', '.join(cap['targets'])}"
        )
    
    tools_text = "\n".join(tools_desc)
    
    # 目标分析
    target_info = f"""
目标: {target}
目标类型: {target_analysis['type']}
- URL: {target_analysis['is_url']}
- IP地址: {target_analysis['is_ip']}
- 域名: {target_analysis['is_domain']}
- 协议: {target_analysis.get('scheme', 'N/A')}
- 端口: {target_analysis.get('port', 'default')}
"""
    
    # 扫描类型指导
    scan_guidance = {
        "quick": "快速扫描模式：选择最核心的2-4个工具，快速发现主要问题。",
        "full": "全面扫描模式：选择所有相关工具，进行深入全面的安全评估。",
        "custom": "自定义扫描：根据目标特征智能选择最合适的工具组合。"
    }
    
    prompt = f"""你是一位安全工具专家。根据扫描目标的特征，选择最合适的安全工具。

{target_info}

扫描类型: {scan_type}
{scan_guidance.get(scan_type, '')}

可用工具:
{tools_text}

请分析目标并选择工具，遵循以下原则:
1. **URL目标**: 优先选择 Web 扫描工具（nuclei, nikto, whatweb, sslscan等）
2. **IP目标**: 优先选择网络扫描工具（nmap, masscan等）
3. **域名目标**: 包含信息收集工具（whois, subfinder等）+ 网络/Web扫描
4. **HTTPS**: 必须包含 SSL/TLS 检查工具（sslscan）
5. **带参数URL**: 考虑包含 sqlmap 进行注入测试
6. **快速模式**: 最多选择4个核心工具
7. **全面模式**: 选择所有相关工具
8. **避免重复**: 同类工具选择最合适的1-2个

请以 JSON 格式返回，格式如下:
{{
  "tools": ["nmap", "nuclei", "sslscan"],
  "reason": "目标是HTTPS URL，需要端口扫描发现服务、Web漏洞检测和SSL安全检查",
  "confidence": "high"
}}

只返回 JSON，不要其他文字。"""
    
    return prompt


async def select_tools_with_llm(
    target: str,
    scan_type: str,
    llm_config: Optional[Dict] = None,
    log_callback=None
) -> ToolSelection:
    """使用 LLM 选择安全工具
    
    Args:
        target: 扫描目标
        scan_type: 扫描类型
        llm_config: LLM 配置
        log_callback: 日志回调
        
    Returns:
        ToolSelection: 工具选择结果
    """
    async def log(msg: str):
        logger.info(msg)
        if log_callback:
            await log_callback("info", f"🤖 {msg}")
    
    try:
        # 分析目标
        target_analysis = analyze_target(target)
        await log(f"目标分析: {target_analysis['type']}")
        
        # 构建提示词
        prompt = build_llm_prompt(target, scan_type, target_analysis)
        
        # 调用 LLM
        from llm.analyzer import get_analyzer
        
        analyzer = get_analyzer()
        await log("正在请求 LLM 选择工具...")
        
        response = await analyzer.analyze(
            prompt=prompt,
            context={},
            config=llm_config
        )
        
        # 解析 JSON 响应
        try:
            # 尝试提取 JSON（LLM 可能返回额外文字）
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = json.loads(response)
            
            tools = result.get("tools", [])
            reason = result.get("reason", "")
            confidence = result.get("confidence", "medium")
            
            await log(f"LLM 选择: {len(tools)} 个工具")
            await log(f"理由: {reason}")
            
            return ToolSelection(
                tools=tools,
                reason=reason,
                confidence=confidence
            )
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {response}")
            raise ValueError(f"LLM 返回格式错误: {e}")
    
    except Exception as e:
        logger.error(f"LLM tool selection failed: {e}")
        # 降级到规则选择
        await log(f"⚠️ LLM 选择失败，使用规则降级: {e}")
        return select_tools_with_rules(target, scan_type)


def select_tools_with_rules(target: str, scan_type: str) -> ToolSelection:
    """基于规则的工具选择（LLM 失败时的降级方案）
    
    Args:
        target: 扫描目标
        scan_type: 扫描类型
        
    Returns:
        ToolSelection: 工具选择结果
    """
    analysis = analyze_target(target)
    tools = []
    reason_parts = []
    
    # 基础规则
    if analysis["is_url"]:
        # URL 目标
        if scan_type == "quick":
            tools = ["nmap", "nuclei", "whatweb"]
            reason_parts.append("URL目标快速扫描：端口+Web漏洞+技术识别")
        else:
            tools = ["nmap", "nuclei", "nikto", "whatweb", "dirb"]
            reason_parts.append("URL目标全面扫描")
        
        # HTTPS 添加 SSL 检查
        if analysis["scheme"] == "https":
            tools.append("sslscan")
            reason_parts.append("HTTPS需要SSL检查")
        
        # 有参数添加 SQL 注入检测
        if analysis["has_params"] and scan_type == "full":
            tools.append("sqlmap")
            reason_parts.append("URL带参数，检测SQL注入")
    
    elif analysis["is_ip"]:
        # IP 目标
        if scan_type == "quick":
            tools = ["nmap"]
            reason_parts.append("IP目标快速端口扫描")
        else:
            tools = ["nmap", "masscan"]
            reason_parts.append("IP目标全面扫描")
    
    elif analysis["is_domain"]:
        # 域名目标
        if scan_type == "quick":
            tools = ["nmap", "whois"]
            reason_parts.append("域名目标：端口扫描+信息收集")
        else:
            tools = ["nmap", "whois", "subfinder", "nuclei"]
            reason_parts.append("域名目标全面扫描")
    
    else:
        # 未知目标，保守策略
        tools = ["nmap"]
        reason_parts.append("目标类型未知，使用保守策略")
    
    # 去重
    tools = list(dict.fromkeys(tools))
    
    return ToolSelection(
        tools=tools,
        reason=" + ".join(reason_parts) + "（基于规则）",
        confidence="medium"
    )


async def select_and_prepare_tools(
    target: str,
    scan_type: str,
    kali_client,
    llm_config: Optional[Dict] = None,
    use_llm: bool = True,
    log_callback=None
) -> Tuple[List[str], str]:
    """选择工具并确保已安装
    
    Args:
        target: 扫描目标
        scan_type: 扫描类型
        kali_client: Kali 客户端
        llm_config: LLM 配置
        use_llm: 是否使用 LLM
        log_callback: 日志回调
        
    Returns:
        Tuple[tools, reason]: 可用工具列表和选择理由
    """
    async def log(msg: str):
        logger.info(msg)
        if log_callback:
            await log_callback("info", f"🔧 {msg}")
    
    # 选择工具
    if use_llm:
        try:
            selection = await select_tools_with_llm(target, scan_type, llm_config, log_callback)
        except:
            selection = select_tools_with_rules(target, scan_type)
    else:
        selection = select_tools_with_rules(target, scan_type)
    
    await log(f"已选择 {len(selection.tools)} 个工具: {', '.join(selection.tools)}")
    await log(f"选择理由: {selection.reason}")
    
    # 确保工具已安装
    success = await kali_client.ensure_tools_installed(selection.tools, log_callback)
    
    if not success:
        logger.warning("Some tools failed to install, continuing with available tools")
    
    # 验证哪些工具真正可用
    available_tools = []
    for tool in selection.tools:
        try:
            info = await kali_client.get_tool_info(tool)
            if info.installed:
                available_tools.append(tool)
            else:
                await log(f"⚠️ {tool} 未能成功安装，跳过")
        except:
            pass
    
    return available_tools, selection.reason
