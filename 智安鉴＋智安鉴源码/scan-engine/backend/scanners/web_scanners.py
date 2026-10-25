"""Web/API 测试类扫描器"""
import re
import json
from typing import AsyncIterator, List

from loguru import logger
from .base import ScannerType, ScanFinding
from .kali_scanner import KaliBaseScanner


class KaliFuffScanner(KaliBaseScanner):
    """ffuf Web Fuzzer"""
    scanner_type = ScannerType.FFUF
    
    def get_tool_name(self) -> str:
        return "ffuf"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        wordlist = config.get("ffuf_wordlist", "/usr/share/wordlists/dirb/common.txt")
        return [
            "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-o", "/dev/stdout",
            "of", "json",
            "-mc", "200,204,301,302,307,401,403,405",
            "-t", "50"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for result in data.get("results", []):
                url = result.get("url", "")
                status = result.get("status", 0)
                severity = "info"
                if status == 200 and result.get("length", 0) > 0:
                    severity = "low"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"目录发现: {result.get('input', {}).get('FUZZ', '')}",
                    severity=severity,
                    category="directory_listing",
                    description=f"URL: {url}, 状态码: {status}, 大小: {result.get('length')}",
                    location=url,
                    raw_data=result
                )
        except json.JSONDecodeError:
            pass


class KaliDirsearchScanner(KaliBaseScanner):
    """Dirsearch 目录扫描器"""
    scanner_type = ScannerType.DIRSEARCH
    
    def get_tool_name(self) -> str:
        return "dirsearch"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-u", target,
            "-o", "/dev/stdout",
            "--format=json",
            "-t", "50",
            "--no-color"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for url, info in data.items():
                status = info.get("status", 0)
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"目录发现: {url}",
                    severity="low" if status == 200 else "info",
                    category="directory_listing",
                    description=f"状态码: {status}, 大小: {info.get('content-length')}",
                    location=url,
                    raw_data=info
                )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                if line.strip() and '200' in line:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"目录发现: {line.split()[0] if line.split() else ''}",
                        severity="low",
                        category="directory_listing",
                        description=line.strip(),
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliFeroxbusterScanner(KaliBaseScanner):
    """Feroxbuster 递归目录扫描器"""
    scanner_type = ScannerType.FEROXBUSTER
    
    def get_tool_name(self) -> str:
        return "feroxbuster"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        wordlist = config.get("ferox_wordlist", "/usr/share/wordlists/dirb/common.txt")
        return [
            "-u", target,
            "-w", wordlist,
            "--json", "--silent",
            "--auto-tune",
            "-t", "50"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                status = data.get("status", 0)
                
                severity = "info"
                sensitive = ['admin', 'backup', 'config', 'env', 'git', 'secret']
                if any(s in url.lower() for s in sensitive):
                    severity = "high"
                elif status == 200:
                    severity = "low"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"目录发现: {url.split('/')[-1] or '/'}",
                    severity=severity,
                    category="directory_listing",
                    description=f"URL: {url}, 状态码: {status}",
                    location=url,
                    raw_data=data
                )
            except json.JSONDecodeError:
                continue


class KaliWfuzzScanner(KaliBaseScanner):
    """Wfuzz Web Fuzzer"""
    scanner_type = ScannerType.WFUZZ
    
    def get_tool_name(self) -> str:
        return "wfuzz"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        wordlist = config.get("wfuzz_wordlist", "/usr/share/wordlists/dirb/common.txt")
        return [
            "-z", f"file,{wordlist}",
            "--hc", "404",
            "-f", "/dev/stdout,json",
            f"{target}/FUZZ"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for result in data.get("results", []):
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"FUZZ 发现: {result.get('url', '')}",
                    severity="low",
                    category="directory_listing",
                    description=f"状态码: {result.get('code')}, 行数: {result.get('lines')}",
                    location=result.get("url", target),
                    raw_data=result
                )
        except json.JSONDecodeError:
            pass


class KaliDalfoxScanner(KaliBaseScanner):
    """Dalfox XSS 扫描器"""
    scanner_type = ScannerType.DALFOX
    
    def get_tool_name(self) -> str:
        return "dalfox"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "url", target,
            "--silence",
            "--format", "json",
            "--only-poc", "r,v"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if data.get("type") == "vulnerable":
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"XSS 漏洞: {data.get('poc', '')[:60]}",
                        severity="high",
                        category="xss",
                        description=f"类型: {data.get('type')}, PoC: {data.get('poc')}",
                        location=data.get("url", target),
                        evidence=data.get("poc", ""),
                        raw_data=data
                    )
            except json.JSONDecodeError:
                if 'XSS' in line or 'vulnerable' in line.lower():
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"XSS 潜在漏洞",
                        severity="medium",
                        category="xss",
                        description=line.strip(),
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliXsstrikeScanner(KaliBaseScanner):
    """XSStrike XSS 扫描器"""
    scanner_type = ScannerType.XSSTRIKE
    
    def get_tool_name(self) -> str:
        return "xsstrike"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-u", target,
            "--json",
            "--skip-dom",
            "--threads", "10"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for url, vulns in data.items():
                for vuln in vulns:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"XSS: {vuln.get('details', '')[:60]}",
                        severity="high",
                        category="xss",
                        description=f"URL: {url}, 详情: {vuln.get('details')}",
                        location=url,
                        evidence=vuln.get("payload", ""),
                        raw_data=vuln
                    )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                if 'Vulnerable' in line or 'XSS' in line:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"XSS 潜在漏洞",
                        severity="medium",
                        category="xss",
                        description=line.strip(),
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliCommixScanner(KaliBaseScanner):
    """Commix 命令注入扫描器"""
    scanner_type = ScannerType.COMMIX
    
    def get_tool_name(self) -> str:
        return "commix"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-u", target,
            "--batch",
            "--output-dir=/tmp/commix_output"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if 'vulnerable' in line.lower() or 'injection' in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"命令注入: {line.strip()[:60]}",
                    severity="critical",
                    category="command_injection",
                    description=line.strip(),
                    location=target,
                    evidence=line,
                    raw_data={"raw": line}
                )
            elif 'payload' in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"命令注入 Payload",
                    severity="high",
                    category="command_injection",
                    description=line.strip(),
                    location=target,
                    evidence=line,
                    raw_data={"raw": line}
                )


class KaliJwtToolScanner(KaliBaseScanner):
    """JWT Tool JWT 分析/测试"""
    scanner_type = ScannerType.JWT_TOOL
    
    def get_tool_name(self) -> str:
        return "jwt_tool"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        jwt_token = config.get("jwt_token", target)
        return [
            jwt_token,
            "-M", "at",  # All Tests
            "-t", target
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if 'VULN' in line or 'CRITICAL' in line or 'HIGH' in line:
                severity = "critical" if 'CRITICAL' in line else "high"
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"JWT 漏洞: {line.strip()[:60]}",
                    severity=severity,
                    category="jwt_vulnerability",
                    description=line.strip(),
                    location=target,
                    evidence=line,
                    raw_data={"raw": line}
                )


class KaliNewmanScanner(KaliBaseScanner):
    """Newman Postman Collection 运行器"""
    scanner_type = ScannerType.NEWMAN
    
    def get_tool_name(self) -> str:
        return "newman"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "run", target,
            "--reporters", "json",
            "--reporter-json-export", "/dev/stdout"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for run in data.get("run", {}).get("executions", []):
                response = run.get("response", {})
                status = response.get("status", "")
                code = response.get("code", 0)
                
                if code >= 400:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"API 错误: {run.get('item', {}).get('name', '')}",
                        severity="medium" if code >= 500 else "low",
                        category="api_error",
                        description=f"状态码: {code}, 端点: {run.get('request', {}).get('url', '')}",
                        location=run.get("request", {}).get("url", target),
                        raw_data=run
                    )
        except json.JSONDecodeError:
            pass


class KaliSmbmapScanner(KaliBaseScanner):
    """SMBMap SMB 共享枚举工具"""
    scanner_type = ScannerType.SMBMAP

    def get_tool_name(self) -> str:
        return "smbmap"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        user = config.get("smb_user", "guest")
        args = ["-H", target, "-u", user]
        if config.get("smb_pass"):
            args.extend(["-p", config["smb_pass"]])
        args.extend(["-q", "--no-color"])
        return args

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("Disk"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                share_name = parts[0]
                perms = parts[1] if len(parts) > 1 else "unknown"
                severity = "medium" if "READ" in perms.upper() or "WRITE" in perms.upper() else "info"
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"SMB 共享: {share_name}",
                    severity=severity,
                    category="smb_shares",
                    description=f"SMB 共享 {share_name}, 权限: {perms}",
                    location=f"{target}/{share_name}",
                    raw_data={"share": share_name, "permissions": perms},
                )


class KaliNbtscanScanner(KaliBaseScanner):
    """Nbtscan NetBIOS 名称扫描器"""
    scanner_type = ScannerType.NBTSCAN

    def get_tool_name(self) -> str:
        return "nbtscan"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        return ["-v", "-e", target]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("Checking") or line.startswith("NetBIOS"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                name = parts[1]
                server_type = parts[2] if len(parts) > 2 else ""
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"NetBIOS: {name} ({ip})",
                    severity="info",
                    category="netbios",
                    description=f"NetBIOS 名称: {name}, 类型: {server_type}, IP: {ip}",
                    location=ip,
                    raw_data={"ip": ip, "name": name, "type": server_type},
                )


class KaliCurlScanner(KaliBaseScanner):
    """Curl HTTP 探测工具"""
    scanner_type = ScannerType.CURL_PROBE

    def get_tool_name(self) -> str:
        return "curl"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        return ["-sI", url]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        headers = {}
        for line in stdout.split("\n"):
            line = line.strip()
            if ":" in line and not line.startswith("HTTP"):
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        security_headers = {
            "strict-transport-security": "HSTS",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "X-XSS-Protection",
            "content-security-policy": "CSP",
        }
        missing = [name for header, name in security_headers.items() if header not in headers]

        if missing:
            yield ScanFinding(
                scanner=self.scanner_type,
                name="缺少安全响应头",
                severity="low",
                category="security_headers",
                description=f"缺少安全头: {', '.join(missing)}",
                location=target,
                raw_data={"missing": missing, "headers": headers},
            )

        server = headers.get("server", "")
        if server:
            yield ScanFinding(
                scanner=self.scanner_type,
                name=f"服务器信息泄露: {server}",
                severity="info",
                category="info_disclosure",
                description=f"服务器头暴露: {server}",
                location=target,
                raw_data={"server": server},
            )


class KaliWpscanScanner(KaliBaseScanner):
    """WPScan WordPress 漏洞扫描器"""
    scanner_type = ScannerType.WPSCAN

    def get_tool_name(self) -> str:
        return "wpscan"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        return ["--url", url, "--no-color", "--format", "cli-no-colour"]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        current_section = ""
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "WordPress version" in line:
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"WordPress 版本: {line.split(':', 1)[-1].strip() if ':' in line else line}",
                    severity="info",
                    category="cms_detection",
                    description=line,
                    location=target,
                )
            elif "Title:" in line and "http" in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"WordPress 主题: {line.split(':', 1)[-1].strip() if ':' in line else line}",
                    severity="info",
                    category="theme_detection",
                    description=line,
                    location=target,
                )
            elif "[!]" in line or "vulnerability" in line.lower() or "cve" in line.lower():
                severity = "high" if "vulnerability" in line.lower() else "medium"
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"WordPress 告警: {line[:60]}",
                    severity=severity,
                    category="wordpress_vulnerability",
                    description=line,
                    location=target,
                    evidence=line,
                )
