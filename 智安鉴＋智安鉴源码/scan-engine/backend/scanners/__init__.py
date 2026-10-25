"""Scanner factory and orchestration"""
from pathlib import Path
from loguru import logger
from sqlalchemy import select, cast, String, func

from app.core.database import AsyncSessionLocal
from app.models.database import SecurityTool
from .base import BaseScanner, ScannerType
from .kali_scanner import (
    KaliNmapScanner, 
    KaliNucleiScanner,
    KaliNiktoScanner,
    KaliGobusterScanner,
    KaliSqlmapScanner,
    KaliWhatWebScanner,
    KaliSslscanScanner
)
from .network_scanners import (
    KaliMasscanScanner,
    KaliNaabuScanner,
    KaliRustscanScanner,
    KaliHttpxScanner,
    KaliKatanaScanner,
    KaliSubfinderScanner,
    KaliAmassScanner,
    KaliDirbScanner,
    KaliDigScanner,
    KaliWhoisScanner,
    KaliArpingScanner,
    KaliFierceScanner,
)
from .vuln_scanners import (
    KaliWapitiScanner,
    KaliTrivyScanner,
    KaliGrypeScanner,
    KaliLynisScanner,
    KaliSearchsploitScanner,
    KaliYaraScanner,
    KaliZapScanner,
    KaliWafw00fScanner,
    KaliMsfconsoleScanner,
    KaliDavtestScanner,
    KaliSubjackScanner,
    KaliNmapVulnScanner,
)
from .web_scanners import (
    KaliFuffScanner,
    KaliDirsearchScanner,
    KaliFeroxbusterScanner,
    KaliWfuzzScanner,
    KaliDalfoxScanner,
    KaliXsstrikeScanner,
    KaliCommixScanner,
    KaliJwtToolScanner,
    KaliNewmanScanner,
    KaliSmbmapScanner,
    KaliNbtscanScanner,
    KaliCurlScanner,
    KaliWpscanScanner,
)
from .cred_scanners import (
    KaliHydraScanner,
    KaliMedusaScanner,
    KaliNetExecScanner,
    KaliCeWLScanner,
    KaliKerbruteScanner,
    KaliEnum4linuxScanner,
    KaliJohnScanner,
    KaliPatatorScanner,
    KaliCrowbarScanner,
)
from .post_exploit_scanners import (
    KaliGitleaksScanner,
    KaliTrufflehogScanner,
    KaliPspyScanner,
    KaliLinpeasScanner,
    KaliLinEnumScanner,
    KaliLinuxExploitSuggester,
    KaliResponderScanner,
)


# 扫描器注册表
SCANNER_REGISTRY = {
    # 网络扫描与资产识别
    ScannerType.NMAP: KaliNmapScanner,
    ScannerType.MASSCAN: KaliMasscanScanner,
    ScannerType.NAABU: KaliNaabuScanner,
    ScannerType.RUSTSCAN: KaliRustscanScanner,
    ScannerType.HTTPX: KaliHttpxScanner,
    ScannerType.WHATWEB: KaliWhatWebScanner,
    ScannerType.KATANA: KaliKatanaScanner,
    ScannerType.SUBFINDER: KaliSubfinderScanner,
    ScannerType.AMASS: KaliAmassScanner,
    ScannerType.DIRB: KaliDirbScanner,
    ScannerType.DIG: KaliDigScanner,
    ScannerType.WHOIS: KaliWhoisScanner,
    ScannerType.ARPING: KaliArpingScanner,
    ScannerType.DNS: KaliFierceScanner,
    
    # 漏洞扫描与组件分析
    ScannerType.NUCLEI: KaliNucleiScanner,
    ScannerType.NIKTO: KaliNiktoScanner,
    ScannerType.WAPITI: KaliWapitiScanner,
    ScannerType.TRIVY: KaliTrivyScanner,
    ScannerType.GRYPE: KaliGrypeScanner,
    ScannerType.LYNIS: KaliLynisScanner,
    ScannerType.SEARCHSPLOIT: KaliSearchsploitScanner,
    ScannerType.YARA: KaliYaraScanner,
    ScannerType.ZAP: KaliZapScanner,
    ScannerType.WAFW00F: KaliWafw00fScanner,
    ScannerType.MSFCONSOLE: KaliMsfconsoleScanner,
    ScannerType.DAVTEST: KaliDavtestScanner,
    ScannerType.SUBJACK: KaliSubjackScanner,
    ScannerType.NMAP_VULN: KaliNmapVulnScanner,
    
    # Web/API 测试
    ScannerType.SQLMAP: KaliSqlmapScanner,
    ScannerType.FFUF: KaliFuffScanner,
    ScannerType.DIRSEARCH: KaliDirsearchScanner,
    ScannerType.GOBUSTER: KaliGobusterScanner,
    ScannerType.FEROXBUSTER: KaliFeroxbusterScanner,
    ScannerType.WFUZZ: KaliWfuzzScanner,
    ScannerType.DALFOX: KaliDalfoxScanner,
    ScannerType.XSSTRIKE: KaliXsstrikeScanner,
    ScannerType.COMMIX: KaliCommixScanner,
    ScannerType.JWT_TOOL: KaliJwtToolScanner,
    ScannerType.NEWMAN: KaliNewmanScanner,
    ScannerType.SMBMAP: KaliSmbmapScanner,
    ScannerType.NBTSCAN: KaliNbtscanScanner,
    ScannerType.CURL_PROBE: KaliCurlScanner,
    ScannerType.WPSCAN: KaliWpscanScanner,
    
    # 凭证与身份验证
    ScannerType.HYDRA: KaliHydraScanner,
    ScannerType.MEDUSA: KaliMedusaScanner,
    ScannerType.NETEXEC: KaliNetExecScanner,
    ScannerType.CEWL: KaliCeWLScanner,
    ScannerType.KERBRUTE: KaliKerbruteScanner,
    ScannerType.ENUM4LINUX: KaliEnum4linuxScanner,
    ScannerType.JOHN: KaliJohnScanner,
    ScannerType.PATATOR: KaliPatatorScanner,
    ScannerType.CROWBAR: KaliCrowbarScanner,
    
    # 后渗透与取证
    ScannerType.GITLEAKS: KaliGitleaksScanner,
    ScannerType.TRUFFLEHOG: KaliTrufflehogScanner,
    ScannerType.PSY: KaliPspyScanner,
    ScannerType.LINPEAS: KaliLinpeasScanner,
    ScannerType.LINENUM: KaliLinEnumScanner,
    ScannerType.LINUX_EXPLOIT_SUGGESTER: KaliLinuxExploitSuggester,
    ScannerType.RESPONDER: KaliResponderScanner,
    
    # 通用
    ScannerType.SSLSCAN: KaliSslscanScanner,
}


# 扫描器类别分组
SCANNER_CATEGORIES = {
    "network": {
        "name": "网络扫描与资产识别",
        "description": "目标发现、端口识别、服务指纹、子域名枚举、DNS 查询",
        "tools": [
            ScannerType.NMAP, ScannerType.MASSCAN, ScannerType.NAABU,
            ScannerType.RUSTSCAN, ScannerType.HTTPX, ScannerType.WHATWEB, ScannerType.KATANA,
            ScannerType.SUBFINDER, ScannerType.AMASS, ScannerType.DIRB,
            ScannerType.DIG, ScannerType.WHOIS, ScannerType.ARPING,
            ScannerType.DNS,
        ]
    },
    "vuln": {
        "name": "漏洞扫描与组件分析",
        "description": "规则扫描、漏洞匹配、组件与配置检查、Web 应用安全扫描",
        "tools": [
            ScannerType.NUCLEI, ScannerType.NIKTO, ScannerType.WAPITI,
            ScannerType.TRIVY, ScannerType.GRYPE, ScannerType.LYNIS,
            ScannerType.SEARCHSPLOIT, ScannerType.YARA, ScannerType.ZAP,
            ScannerType.WAFW00F, ScannerType.MSFCONSOLE, ScannerType.DAVTEST,
            ScannerType.SUBJACK, ScannerType.NMAP_VULN,
        ]
    },
    "web": {
        "name": "Web/API 测试",
        "description": "Web 枚举、参数变异、API 回归、SMB/NetBIOS 探测",
        "tools": [
            ScannerType.SQLMAP, ScannerType.FFUF, ScannerType.DIRSEARCH,
            ScannerType.GOBUSTER, ScannerType.FEROXBUSTER, ScannerType.WFUZZ,
            ScannerType.DALFOX, ScannerType.XSSTRIKE, ScannerType.COMMIX,
            ScannerType.JWT_TOOL, ScannerType.NEWMAN, ScannerType.SSLSCAN,
            ScannerType.SMBMAP, ScannerType.NBTSCAN, ScannerType.CURL_PROBE,
            ScannerType.WPSCAN,
        ]
    },
    "cred": {
        "name": "凭证与身份验证",
        "description": "仅在授权靶场或教学环境下按策略启用",
        "tools": [
            ScannerType.HYDRA, ScannerType.MEDUSA, ScannerType.NETEXEC,
            ScannerType.CEWL, ScannerType.KERBRUTE, ScannerType.ENUM4LINUX,
            ScannerType.JOHN, ScannerType.PATATOR, ScannerType.CROWBAR,
        ]
    },
    "post_exploit": {
        "name": "后渗透与取证辅助",
        "description": "枚举、取证、配置分析、凭证暴露检查、LLMNR/NBT-NS 检测",
        "tools": [
            ScannerType.GITLEAKS, ScannerType.TRUFFLEHOG, ScannerType.PSY,
            ScannerType.LINPEAS, ScannerType.LINENUM, ScannerType.LINUX_EXPLOIT_SUGGESTER,
            ScannerType.RESPONDER,
        ]
    }
}


def get_scanner(scanner_type: ScannerType) -> BaseScanner:
    """获取扫描器实例"""
    if scanner_type not in SCANNER_REGISTRY:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
    
    return SCANNER_REGISTRY[scanner_type]()


def get_scanners_by_category(category: str) -> list[BaseScanner]:
    """按类别获取扫描器列表"""
    cat_config = SCANNER_CATEGORIES.get(category)
    if not cat_config:
        return []
    
    scanners = []
    for tool_type in cat_config["tools"]:
        try:
            scanners.append(get_scanner(tool_type))
        except Exception:
            pass
    return scanners


def get_all_scanner_types() -> list[ScannerType]:
    """获取所有扫描器类型"""
    return list(SCANNER_REGISTRY.keys())


async def _get_uploaded_scanners() -> list[str]:
    """获取已上传的扫描器名称"""
    scanners: list[str] = []
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityTool.name, SecurityTool.file_path, SecurityTool.is_enabled)
                .where(func.lower(cast(SecurityTool.tool_type, String)) == "scanner")
            )
            for name, file_path, is_enabled in result.all():
                if not is_enabled:
                    continue
                if file_path and Path(file_path).exists():
                    scanners.append(name)
    except Exception as exc:
        logger.warning(f"Failed to load uploaded scanners: {exc}")
    return scanners


async def get_available_scanners() -> tuple[list[ScannerType], list[str]]:
    """获取可用的扫描器列表"""
    available: list[ScannerType] = []
    
    for scanner_type in ScannerType:
        if scanner_type == ScannerType.CUSTOM:
            continue
        try:
            scanner = get_scanner(scanner_type)
            if await scanner.is_available():
                available.append(scanner_type)
        except Exception:
            pass
    
    uploaded = await _get_uploaded_scanners()
    return available, uploaded
