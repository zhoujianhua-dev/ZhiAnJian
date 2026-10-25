"""Security tools that AI agent can invoke"""
import subprocess
import asyncio
import shlex
from typing import Optional, Callable, Awaitable
from pydantic import BaseModel, Field
from loguru import logger

from scanners.kali_client import KaliClient


class ToolResult(BaseModel):
    """工具执行结果"""
    success: bool
    output: str
    error: Optional[str] = None


# 全局 Kali 客户端
_kali_client: Optional[KaliClient] = None


def get_kali_client() -> KaliClient:
    """获取 Kali 客户端单例"""
    global _kali_client
    if _kali_client is None:
        _kali_client = KaliClient()
    return _kali_client


async def _run_in_kali(command: str, args: list = None, timeout: int = 60) -> ToolResult:
    """在 Kali 容器中执行命令"""
    try:
        kali = get_kali_client()
        result = await kali.execute(
            command=command,
            args=args or [],
            timeout=timeout
        )
        
        output = result.stdout
        if result.stderr:
            output = f"{output}\n\nSTDERR:\n{result.stderr}" if output else result.stderr
        
        return ToolResult(
            success=result.success,
            output=output,
            error=result.error
        )
    except Exception as e:
        logger.error(f"Error executing in Kali: {e}")
        return ToolResult(success=False, output="", error=f"Kali 执行错误: {str(e)}")


async def _run_shell_in_kali(cmd: str, timeout: int = 60) -> ToolResult:
    """在 Kali 容器中执行 shell 命令（支持管道、重定向等）"""
    return await _run_in_kali("sh", ["-c", cmd], timeout)


async def _run_shell_command(cmd: str, timeout: int = 60) -> ToolResult:
    """通用 shell 命令执行 - 现在重定向到 Kali 容器"""
    return await _run_shell_in_kali(cmd, timeout)


async def _ensure_tool_in_kali(tool_name: str, log_callback: Callable = None) -> bool:
    """确保工具在 Kali 容器中已安装"""
    try:
        kali = get_kali_client()
        try:
            tool_info = await kali.get_tool_info(tool_name)
            if tool_info.installed:
                return True
        except:
            pass  # Tool not found, try to install
        
        # 尝试安装
        if log_callback:
            await log_callback("info", f"📦 在 Kali 中安装 {tool_name}...")
        
        installed, failed, already = await kali.install_tools([tool_name])
        return tool_name in installed or tool_name in already
    except Exception as e:
        logger.error(f"Error checking/installing tool in Kali: {e}")
        return False


class SecurityTool:
    """安全工具基类"""
    name: str
    description: str
    binary_name: str = None  # 实际的二进制名称，默认与 name 相同
    
    def get_binary_name(self) -> str:
        return self.binary_name or self.name
    
    async def ensure_installed(self, log_callback: Callable = None) -> bool:
        """确保工具已安装（在 Kali 容器中）"""
        binary = self.get_binary_name()
        return await _ensure_tool_in_kali(binary, log_callback)
    
    async def execute(self, **kwargs) -> ToolResult:
        raise NotImplementedError


class NmapTool(SecurityTool):
    name = "nmap"
    description = "端口扫描和服务识别工具。默认扫描所有端口 (1-65535)。可以扫描特定端口、探测服务版本、执行脚本扫描等。"
    
    async def execute(
        self, 
        target: str = None,
        ports: str = None,
        scripts: str = None,
        options: str = None,
        args: str = None,  # 兼容 LLM 传入的 args 参数
        timeout: int = 300,
        **kwargs  # 忽略其他未知参数
    ) -> ToolResult:
        """执行 nmap 扫描
        
        Args:
            target: 扫描目标 (IP/域名)
            ports: 端口范围，如 "80,443" 或 "1-1000"。留空则扫描所有端口 (1-65535)
            scripts: NSE 脚本，如 "http-title,http-headers"
            options: 其他选项，如 "-sV" (版本探测)
            args: 完整的命令行参数字符串（LLM 可能使用）
            timeout: 超时时间(秒)
        """
        # 如果提供了 args，通过 shell 执行
        if args:
            # 确保 target 参数被包含
            if not target:
                return ToolResult(success=False, output="", error="缺少必需参数: target")
            
            # 自动添加 -Pn 跳过主机发现，避免因 ICMP 被过滤导致 "0 hosts up"
            if "-Pn" not in args and "-pn" not in args.lower():
                args = f"-Pn {args}"
            
            # 将 target 添加到命令末尾
            full_cmd = f"nmap {args} {target}"
            return await _run_shell_in_kali(full_cmd, timeout)
        
        # 标准参数模式
        if not target:
            return ToolResult(success=False, output="", error="缺少必需参数: target")
        
        cmd_args = ["-Pn", "-oX", "-"]  # -Pn 跳过主机发现，XML 输出到 stdout
        
        # 如果未指定端口，默认扫描所有端口
        if ports:
            cmd_args.extend(["-p", ports])
        else:
            cmd_args.extend(["-p", "1-65535"])  # 默认扫描所有端口
        
        if scripts:
            cmd_args.extend(["--script", scripts])
        if options:
            cmd_args.extend(shlex.split(options))
        
        cmd_args.append(target)
        
        return await _run_in_kali("nmap", cmd_args, timeout)


class CurlTool(SecurityTool):
    name = "curl"
    description = "HTTP 请求工具。可以发送各种 HTTP 请求测试 Web 服务。"
    
    async def execute(
        self,
        url: str = None,
        method: str = "GET",
        headers: dict = None,
        data: str = None,
        args: str = None,  # 兼容 LLM 传入的完整命令行参数
        timeout: int = 30,
        **kwargs  # 忽略其他未知参数
    ) -> ToolResult:
        """执行 HTTP 请求
        
        Args:
            url: 目标 URL
            method: HTTP 方法 (GET/POST/PUT/DELETE 等)
            headers: 请求头字典
            data: 请求体数据
            args: 完整的命令行参数字符串（LLM 可能使用）
            timeout: 超时时间(秒)
        """
        # 如果提供了 args，直接使用（通过 shell 执行以支持重定向等）
        if args:
            # 确保 url 参数被包含
            if not url:
                return ToolResult(success=False, output="", error="缺少必需参数: url")
            return await _run_shell_in_kali(f"curl {args} {url}", timeout+5)
        
        # 标准参数模式
        if not url:
            return ToolResult(success=False, output="", error="缺少必需参数: url")
        
        cmd_args = ["-s", "-i", "-X", method, "--max-time", str(timeout)]
        
        if headers:
            for k, v in headers.items():
                cmd_args.extend(["-H", f"{k}: {v}"])
        
        if data:
            cmd_args.extend(["-d", data])
        
        cmd_args.append(url)
        
        return await _run_in_kali("curl", cmd_args, timeout+5)


class DirBusterTool(SecurityTool):
    name = "dirbuster"
    description = "目录/文件枚举工具。可以发现隐藏的目录和文件。"
    binary_name = "gobuster"  # 实际使用 gobuster
    
    async def execute(
        self,
        url: str = None,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str = None,
        args: str = None,
        timeout: int = 300,
        **kwargs  # 忽略其他未知参数
    ) -> ToolResult:
        """执行目录枚举
        
        Args:
            url: 目标 URL
            wordlist: 字典文件路径
            extensions: 文件扩展名，如 "php,html,txt"
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        # 如果提供了 args，通过 shell 执行
        if args:
            if not url:
                return ToolResult(success=False, output="", error="缺少必需参数: url")
            return await _run_shell_in_kali(f"gobuster {args} -u {url}", timeout)
        
        if not url:
            return ToolResult(success=False, output="", error="缺少必需参数: url")
        
        # 使用 gobuster
        cmd_args = ["dir", "-u", url, "-w", wordlist, "-q", "-t", "10"]
        
        if extensions:
            cmd_args.extend(["-x", extensions])
        
        result = await _run_in_kali("gobuster", cmd_args, timeout)
        
        # 如果 gobuster 失败，尝试 dirb
        if not result.success and "not found" in (result.error or "").lower():
            cmd_args = [url, wordlist, "-S", "-r"]
            return await _run_in_kali("dirb", cmd_args, timeout)
        
        return result


class NucleiTool(SecurityTool):
    name = "nuclei"
    description = "基于模板的漏洞扫描器。自动使用 GitHub nuclei-templates 项目的所有模板检测安全漏洞。"
    
    async def execute(
        self,
        target: str = None,
        templates: str = None,
        tags: str = None,
        severity: str = None,
        args: str = None,
        timeout: int = 600,
        **kwargs  # 忽略其他未知参数
    ) -> ToolResult:
        """执行 Nuclei 扫描
        
        Args:
            target: 目标 URL
            templates: 自定义模板路径或名称（留空则使用所有官方模板）
            tags: 模板标签，如 "cve,rce"
            severity: 严重性过滤，如 "critical,high"
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        if args:
            if not target:
                return ToolResult(success=False, output="", error="缺少必需参数: target")
            return await _run_shell_in_kali(f"nuclei {args} -u {target}", timeout)
        
        if not target:
            return ToolResult(success=False, output="", error="缺少必需参数: target")
        
        # 基础参数
        cmd_args = ["-u", target, "-silent", "-nc"]
        
        # 如果没有指定模板，默认使用所有官方模板
        # nuclei 会自动从 ~/.nuclei-templates/ 加载
        if templates:
            cmd_args.extend(["-t", templates])
        else:
            # 不指定 -t 参数，nuclei 会使用所有已安装的模板
            pass
        
        if tags:
            cmd_args.extend(["-tags", tags])
        if severity:
            cmd_args.extend(["-s", severity])
        
        return await _run_in_kali("nuclei", cmd_args, timeout)


class WhatWebTool(SecurityTool):
    name = "whatweb"
    description = "Web 指纹识别工具。识别网站使用的技术、框架和版本。"
    
    async def execute(
        self,
        target: str = None,
        aggression: int = 1,
        args: str = None,
        timeout: int = 60,
        **kwargs  # 忽略其他未知参数
    ) -> ToolResult:
        """执行 Web 指纹识别
        
        Args:
            target: 目标 URL
            aggression: 扫描强度 1-4
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        if args:
            if not target:
                return ToolResult(success=False, output="", error="缺少必需参数: target")
            return await _run_shell_in_kali(f"whatweb {args} {target}", timeout)
        
        if not target:
            return ToolResult(success=False, output="", error="缺少必需参数: target")
        
        cmd_args = [f"-a{aggression}", "--color=never", target]
        return await _run_in_kali("whatweb", cmd_args, timeout)


class SSLScanTool(SecurityTool):
    name = "sslscan"
    description = "SSL/TLS 配置分析工具。检测证书问题和弱密码套件。"
    
    async def execute(
        self,
        target: str = None,
        args: str = None,
        timeout: int = 60,
        **kwargs  # 忽略其他未知参数
    ) -> ToolResult:
        """执行 SSL 扫描
        
        Args:
            target: 目标主机:端口
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        if args:
            if not target:
                return ToolResult(success=False, output="", error="缺少必需参数: target")
            return await _run_shell_in_kali(f"sslscan {args} {target}", timeout)
        
        if not target:
            return ToolResult(success=False, output="", error="缺少必需参数: target")
        
        cmd_args = ["--no-colour", target]
        return await _run_in_kali("sslscan", cmd_args, timeout)


class SQLMapTool(SecurityTool):
    name = "sqlmap"
    description = "SQL 注入检测和利用工具。自动检测和利用 SQL 注入漏洞。"
    
    async def execute(
        self,
        url: str = None,
        data: str = None,
        cookie: str = None,
        level: int = 1,
        risk: int = 1,
        args: str = None,
        timeout: int = 300,
        **kwargs  # 忽略其他未知参数
    ) -> ToolResult:
        """执行 SQL 注入测试
        
        Args:
            url: 目标 URL (带参数)
            data: POST 数据
            cookie: Cookie 值
            level: 测试级别 1-5
            risk: 风险级别 1-3
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        if args:
            if not url:
                return ToolResult(success=False, output="", error="缺少必需参数: url")
            return await _run_shell_in_kali(f"sqlmap {args} -u '{url}'", timeout)
        
        if not url:
            return ToolResult(success=False, output="", error="缺少必需参数: url")
        
        cmd_args = ["-u", url, "--batch", "--output-dir=/tmp/sqlmap"]
        cmd_args.extend(["--level", str(level), "--risk", str(risk)])
        
        if data:
            cmd_args.extend(["--data", data])
        if cookie:
            cmd_args.extend(["--cookie", cookie])
        
        return await _run_in_kali("sqlmap", cmd_args, timeout)


class NiktoTool(SecurityTool):
    name = "nikto"
    description = "Web 服务器漏洞扫描器。检测 Web 服务器的配置问题和已知漏洞。"
    
    async def execute(
        self,
        target: str = None,
        port: int = None,
        ssl: bool = False,
        args: str = None,
        timeout: int = 600,
        **kwargs
    ) -> ToolResult:
        """执行 Nikto 扫描
        
        Args:
            target: 目标 URL 或主机
            port: 端口号
            ssl: 是否使用 SSL
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        if args:
            if not target:
                return ToolResult(success=False, output="", error="缺少必需参数: target")
            return await _run_shell_in_kali(f"nikto {args} -h {target}", timeout)
        
        if not target:
            return ToolResult(success=False, output="", error="缺少必需参数: target")
        
        cmd_args = ["-h", target, "-nointeractive"]
        
        if port:
            cmd_args.extend(["-p", str(port)])
        if ssl:
            cmd_args.append("-ssl")
        
        return await _run_in_kali("nikto", cmd_args, timeout)


class HydraTool(SecurityTool):
    name = "hydra"
    description = "密码暴力破解工具。支持多种协议的登录爆破。"
    
    async def execute(
        self,
        target: str = None,
        service: str = None,
        username: str = None,
        userlist: str = None,
        password: str = None,
        passlist: str = None,
        port: int = None,
        args: str = None,
        timeout: int = 300,
        **kwargs
    ) -> ToolResult:
        """执行 Hydra 爆破
        
        Args:
            target: 目标主机
            service: 服务类型 (ssh, ftp, http-get, etc.)
            username: 单个用户名
            userlist: 用户名列表文件
            password: 单个密码
            passlist: 密码列表文件
            port: 端口号
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        # Security policy: Prohibit SSH brute force attacks
        # Check for SSH brute force attempt through args parameter
        if args:
            args_lower = args.lower()
            if " ssh" in args_lower or args_lower.startswith("ssh") or "-s 22" in args_lower:
                return ToolResult(
                    success=False,
                    output="",
                    error="❌ 安全策略禁止对 SSH (22端口) 进行密码爆破攻击。"
                )
        
        # Check for SSH brute force attempt through service parameter
        if service and service.lower() == "ssh":
            return ToolResult(
                success=False,
                output="",
                error="❌ 安全策略禁止对 SSH (22端口) 进行密码爆破攻击。"
            )
        
        # Check for SSH brute force attempt through port parameter
        if port == 22:
            return ToolResult(
                success=False,
                output="",
                error="❌ 安全策略禁止对 SSH (22端口) 进行密码爆破攻击。"
            )
        
        if args:
            if target and service:
                return await _run_shell_in_kali(f"hydra {args} {target} {service}", timeout)
            elif target:
                return await _run_shell_in_kali(f"hydra {args} {target}", timeout)
            else:
                return ToolResult(success=False, output="", error="缺少必需参数: target")
        
        if not target or not service:
            return ToolResult(success=False, output="", error="缺少必需参数: target 和 service")
        
        cmd_args = ["-t", "4"]  # 4 个线程
        
        if username:
            cmd_args.extend(["-l", username])
        elif userlist:
            cmd_args.extend(["-L", userlist])
        else:
            cmd_args.extend(["-l", "admin"])  # 默认用户名
        
        if password:
            cmd_args.extend(["-p", password])
        elif passlist:
            cmd_args.extend(["-P", passlist])
        else:
            cmd_args.extend(["-P", "/usr/share/wordlists/rockyou.txt"])  # 默认密码表
        
        if port:
            cmd_args.extend(["-s", str(port)])
        
        cmd_args.extend([target, service])
        
        return await _run_in_kali("hydra", cmd_args, timeout)


class DigTool(SecurityTool):
    name = "dig"
    description = "DNS 查询工具。执行各种 DNS 记录查询。"
    binary_name = "dig"
    
    async def execute(
        self,
        domain: str = None,
        record_type: str = "ANY",
        server: str = None,
        args: str = None,
        timeout: int = 30,
        **kwargs
    ) -> ToolResult:
        """执行 DNS 查询
        
        Args:
            domain: 域名
            record_type: 记录类型 (A, AAAA, MX, NS, TXT, ANY 等)
            server: DNS 服务器
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        if args:
            if not domain:
                return ToolResult(success=False, output="", error="缺少必需参数: domain")
            return await _run_shell_in_kali(f"dig {args} {domain}", timeout)
        
        if not domain:
            return ToolResult(success=False, output="", error="缺少必需参数: domain")
        
        cmd_args = ["+noall", "+answer", domain, record_type]
        
        if server:
            cmd_args.insert(0, f"@{server}")
        
        return await _run_in_kali("dig", cmd_args, timeout)


class WhoIsTool(SecurityTool):
    name = "whois"
    description = "域名/IP 信息查询工具。获取域名注册信息和 IP 归属信息。"
    
    async def execute(
        self,
        target: str = None,
        args: str = None,
        timeout: int = 30,
        **kwargs
    ) -> ToolResult:
        """执行 WHOIS 查询
        
        Args:
            target: 域名或 IP 地址
            args: 完整命令行参数
            timeout: 超时时间(秒)
        """
        if args:
            if not target:
                return ToolResult(success=False, output="", error="缺少必需参数: target")
            return await _run_shell_in_kali(f"whois {args} {target}", timeout)
        
        if not target:
            return ToolResult(success=False, output="", error="缺少必需参数: target")
        
        return await _run_in_kali("whois", [target], timeout)


class NetcatTool(SecurityTool):
    name = "netcat"
    description = "网络工具。用于端口测试、Banner 抓取等。"
    binary_name = "nc"
    
    def _parse_args_string(self, args_str: str) -> tuple[str, int]:
        """从 args 字符串中解析 target 和 port"""
        if not args_str:
            return None, None
        
        # 移除常见的 nc 参数
        clean_args = re.sub(r'-[a-zA-Z]+\s*', '', args_str).strip()
        
        # 尝试匹配 IP/域名:端口 格式
        match = re.search(r'([\w\.\-]+)[:\s]+(\d+)', clean_args)
        if match:
            return match.group(1), int(match.group(2))
        
        # 尝试匹配末尾的 IP/域名 端口 格式
        parts = clean_args.split()
        if len(parts) >= 2:
            potential_port = parts[-1]
            potential_host = parts[-2]
            if potential_port.isdigit():
                return potential_host, int(potential_port)
        
        return None, None
    
    async def execute(
        self,
        target: str = None,
        port: int = None,
        args: str = None,
        timeout: int = 10,
        **kwargs
    ) -> ToolResult:
        """执行 Netcat 连接
        
        Args:
            target: 目标主机
            port: 端口号
            args: 完整命令行参数（会尝试智能解析）
            timeout: 超时时间(秒)
        """
        # 智能参数解析
        if args and (not target or port is None):
            parsed_target, parsed_port = self._parse_args_string(args)
            if parsed_target and not target:
                target = parsed_target
            if parsed_port and port is None:
                port = parsed_port
            if target and port is not None:
                logger.debug(f"NetcatTool auto-parsed: target={target}, port={port}")
                args = None
        
        # 如果 target 中包含端口，提取它
        if target and ':' in target and port is None:
            parts = target.rsplit(':', 1)
            if len(parts) == 2 and parts[1].isdigit():
                target, port = parts[0], int(parts[1])
        
        # 如果仍有 args 字符串且无法解析，直接执行
        if args:
            return await _run_shell_in_kali(f"nc {args}", timeout)
        
        if not target or port is None:
            return ToolResult(
                success=False, 
                output="", 
                error="缺少必需参数: target 和 port。支持格式: target='127.0.0.1', port=80 或 args='127.0.0.1 80'"
            )
        
        cmd_args = ["-vz", "-w", str(timeout), target, str(port)]
        return await _run_in_kali("nc", cmd_args, timeout + 5)


# 可用工具注册表
AVAILABLE_TOOLS = {
    "nmap": NmapTool(),
    "curl": CurlTool(),
    "dirbuster": DirBusterTool(),
    "nuclei": NucleiTool(),
    "whatweb": WhatWebTool(),
    "sslscan": SSLScanTool(),
    "sqlmap": SQLMapTool(),
    "nikto": NiktoTool(),
    "hydra": HydraTool(),
    "dig": DigTool(),
    "whois": WhoIsTool(),
    "netcat": NetcatTool(),
}


def get_tool(name: str) -> Optional[SecurityTool]:
    """获取工具实例"""
    return AVAILABLE_TOOLS.get(name)


def get_tools_description() -> str:
    """获取所有工具的描述（供 LLM 使用）"""
    descriptions = []
    for name, tool in AVAILABLE_TOOLS.items():
        descriptions.append(f"- **{name}**: {tool.description}")
    return "\n".join(descriptions)


def get_tools_schema() -> list[dict]:
    """获取工具的 JSON Schema（供 function calling 使用）"""
    return [
        {
            "name": "nmap",
            "description": "端口扫描和服务识别。扫描目标的开放端口和服务版本。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "扫描目标 IP 或域名"},
                    "ports": {"type": "string", "description": "端口范围，如 '80,443' 或 '1-1000'"},
                    "scripts": {"type": "string", "description": "NSE 脚本，如 'http-title,http-headers'"},
                    "options": {"type": "string", "description": "其他 nmap 选项"}
                },
                "required": ["target"]
            }
        },
        {
            "name": "curl",
            "description": "发送 HTTP 请求。用于测试 Web 端点、检查响应头等。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL"},
                    "method": {"type": "string", "description": "HTTP 方法", "default": "GET"},
                    "headers": {"type": "object", "description": "请求头"},
                    "data": {"type": "string", "description": "请求体数据"}
                },
                "required": ["url"]
            }
        },
        {
            "name": "dirbuster",
            "description": "目录和文件枚举。发现隐藏的目录和敏感文件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL"},
                    "wordlist": {"type": "string", "description": "字典文件路径"},
                    "extensions": {"type": "string", "description": "文件扩展名，如 'php,html'"}
                },
                "required": ["url"]
            }
        },
        {
            "name": "nuclei",
            "description": "模板化漏洞扫描。使用预定义模板检测已知漏洞。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标 URL"},
                    "templates": {"type": "string", "description": "模板路径"},
                    "tags": {"type": "string", "description": "模板标签，如 'cve,rce'"},
                    "severity": {"type": "string", "description": "严重性过滤，如 'critical,high'"}
                },
                "required": ["target"]
            }
        },
        {
            "name": "whatweb",
            "description": "Web 指纹识别。识别目标使用的技术栈、框架和版本。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标 URL"},
                    "aggression": {"type": "integer", "description": "扫描强度 1-4", "default": 1}
                },
                "required": ["target"]
            }
        },
        {
            "name": "sslscan",
            "description": "SSL/TLS 安全检查。检测证书和加密配置问题。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标主机:端口"}
                },
                "required": ["target"]
            }
        },
        {
            "name": "sqlmap",
            "description": "SQL 注入测试。检测和验证 SQL 注入漏洞。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL（带参数）"},
                    "data": {"type": "string", "description": "POST 数据"},
                    "level": {"type": "integer", "description": "测试级别 1-5", "default": 1}
                },
                "required": ["url"]
            }
        },
        {
            "name": "nikto",
            "description": "Web 服务器漏洞扫描。检测配置问题和已知漏洞。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标 URL 或主机"},
                    "port": {"type": "integer", "description": "端口号"},
                    "ssl": {"type": "boolean", "description": "是否使用 SSL"}
                },
                "required": ["target"]
            }
        },
        {
            "name": "hydra",
            "description": "密码暴力破解。支持 SSH、FTP、HTTP 等多种协议。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标主机"},
                    "service": {"type": "string", "description": "服务类型 (ssh, ftp, http-get 等)"},
                    "username": {"type": "string", "description": "用户名"},
                    "passlist": {"type": "string", "description": "密码列表文件路径"}
                },
                "required": ["target", "service"]
            }
        },
        {
            "name": "dig",
            "description": "DNS 查询。获取域名的各种 DNS 记录。",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "域名"},
                    "record_type": {"type": "string", "description": "记录类型 (A, MX, NS, TXT 等)", "default": "ANY"},
                    "server": {"type": "string", "description": "DNS 服务器"}
                },
                "required": ["domain"]
            }
        },
        {
            "name": "whois",
            "description": "域名/IP 信息查询。获取注册信息和归属信息。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "域名或 IP 地址"}
                },
                "required": ["target"]
            }
        },
        {
            "name": "netcat",
            "description": "网络连接工具。用于端口测试和 Banner 抓取。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标主机"},
                    "port": {"type": "integer", "description": "端口号"}
                },
                "required": ["target", "port"]
            }
        }
    ]
