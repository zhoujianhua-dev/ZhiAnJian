"""Base scanner interface"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator
import os
import tempfile
from pathlib import Path


class ScannerType(str, Enum):
    # 网络扫描与资产识别
    NMAP = "nmap"
    MASSCAN = "masscan"
    NAABU = "naabu"
    RUSTSCAN = "rustscan"
    HTTPX = "httpx"
    WHATWEB = "whatweb"
    KATANA = "katana"
    SUBFINDER = "subfinder"
    AMASS = "amass"
    DIRB = "dirb"
    DIG = "dig"
    WHOIS = "whois"
    ARPING = "arping"
    DNS = "dns"
    
    # 漏洞扫描与组件分析
    NUCLEI = "nuclei"
    NIKTO = "nikto"
    WAPITI = "wapiti"
    TRIVY = "trivy"
    GRYPE = "grype"
    SCOUTSUITE = "scoutsuite"
    LYNIS = "lynis"
    OSV_SCANNER = "osv-scanner"
    SEARCHSPLOIT = "searchsploit"
    YARA = "yara"
    ZAP = "zap"
    WAFW00F = "wafw00f"
    MSFCONSOLE = "msfconsole"
    DAVTEST = "davtest"
    SUBJACK = "subjack"
    NMAP_VULN = "nmap-vuln"
    WPSCAN = "wpscan"
    
    # Web/API 测试
    OWASP_ZAP = "owasp-zap"
    SQLMAP = "sqlmap"
    FFUF = "ffuf"
    DIRSEARCH = "dirsearch"
    GOBUSTER = "gobuster"
    FEROXBUSTER = "feroxbuster"
    WFUZZ = "wfuzz"
    DALFOX = "dalfox"
    XSSTRIKE = "xsstrike"
    COMMIX = "commix"
    JWT_TOOL = "jwt_tool"
    NEWMAN = "newman"
    SMBMAP = "smbmap"
    NBTSCAN = "nbtscan"
    CURL_PROBE = "curl-probe"
    
    # 凭证与身份验证
    HYDRA = "hydra"
    MEDUSA = "medusa"
    PATATOR = "patator"
    CROWBAR = "crowbar"
    NETEXEC = "netexec"
    CEWL = "cewl"
    JOHN = "john"
    HASHCAT = "hashcat"
    KERBRUTE = "kerbrute"
    ENUM4LINUX = "enum4linux-ng"
    
    # 后渗透与取证辅助
    LINPEAS = "linpeas"
    WINPEAS = "winpeas"
    LINENUM = "linenum"
    LINUX_EXPLOIT_SUGGESTER = "linux-exploit-suggester"
    WINDOWS_EXPLOIT_SUGGESTER = "windows-exploit-suggester"
    SEATBELT = "seatbelt"
    PSY = "pspy"
    VOLATILITY = "volatility"
    GITLEAKS = "gitleaks"
    TRUFFLEHOG = "trufflehog"
    RESPONDER = "responder"
    
    # 通用
    SSLSCAN = "sslscan"
    WEB = "web"
    CUSTOM = "custom"


@dataclass
class ScanFinding:
    """扫描发现的统一数据结构"""
    scanner: ScannerType
    name: str
    severity: str  # critical, high, medium, low, info
    category: str
    description: str
    location: str  # URL/IP:Port/File path
    evidence: str = ""
    raw_data: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


class BaseScanner(ABC):
    """扫描器基类"""
    
    scanner_type: ScannerType
    
    @abstractmethod
    async def scan(self, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        """执行扫描，yield 发现的问题"""
        pass
    
    @abstractmethod
    async def is_available(self) -> bool:
        """检查扫描器是否可用"""
        pass
    
    def validate_target(self, target: str) -> bool:
        """验证目标格式"""
        # 基础验证，子类可覆盖
        return bool(target and len(target) < 500)
    
    def get_temp_dir(self) -> Path:
        """获取扫描器临时目录"""
        from app.core.config import get_settings
        settings = get_settings()
        # 优先从数据库读取，如果失败则使用 .env 配置作为后备
        temp_dir = Path(settings.scan_temp_dir) / self.scanner_type.value
        temp_dir.mkdir(parents=True, exist_ok=True)
        return temp_dir
    
    async def get_temp_dir_async(self) -> Path:
        """异步获取扫描器临时目录（优先从数据库读取）"""
        try:
            from app.core.database import async_session_factory
            from app.api.settings import get_scan_settings_from_db
            
            async with async_session_factory() as db:
                scan_settings = await get_scan_settings_from_db(db)
                temp_dir = Path(scan_settings.scan_temp_dir) / self.scanner_type.value
                temp_dir.mkdir(parents=True, exist_ok=True)
                return temp_dir
        except Exception:
            # 如果数据库读取失败，回退到 .env 配置
            return self.get_temp_dir()
    
    def get_temp_file(self, prefix: str = "", suffix: str = "") -> str:
        """创建临时文件路径（不创建文件本身）"""
        temp_dir = self.get_temp_dir()
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=str(temp_dir))
        os.close(fd)  # 关闭文件描述符，让扫描器自己管理文件
        return path
