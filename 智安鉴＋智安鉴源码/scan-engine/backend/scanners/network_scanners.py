"""网络扫描与资产识别类扫描器"""
import re
import json
import xml.etree.ElementTree as ET
from typing import AsyncIterator, List

from loguru import logger
from .base import ScannerType, ScanFinding
from .kali_scanner import KaliBaseScanner


class KaliMasscanScanner(KaliBaseScanner):
    """Masscan 快速端口扫描器"""
    scanner_type = ScannerType.MASSCAN
    
    def get_tool_name(self) -> str:
        return "masscan"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        ports = config.get("custom_ports", "1-1000")
        rate = config.get("masscan_rate", 1000)
        return [
            target,
            "-p", str(ports),
            "--rate", str(rate),
            "--open",
            "-oJ", "/dev/stdout"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            line = line.strip().rstrip(',')
            if not line or line in ['[', ']']:
                continue
            try:
                data = json.loads(line)
                for port_info in data.get("ports", []):
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"开放端口: {port_info.get('port')}/{port_info.get('proto', 'tcp')}",
                        severity="info",
                        category="network",
                        description=f"Masscan 发现端口 {port_info.get('port')} 开放",
                        location=f"{data.get('ip', target)}:{port_info.get('port')}",
                        raw_data=data
                    )
            except json.JSONDecodeError:
                continue


class KaliNaabuScanner(KaliBaseScanner):
    """Naabu 端口扫描器"""
    scanner_type = ScannerType.NAABU
    
    def get_tool_name(self) -> str:
        return "naabu"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        ports = config.get("custom_ports", "top-1000")
        return [
            "-host", target,
            "-ports", str(ports),
            "-silent",
            "-json"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"开放端口: {data.get('port')}/{data.get('proto', 'tcp')}",
                    severity="info",
                    category="network",
                    description=f"Naabu 发现端口 {data.get('port')} 开放",
                    location=f"{data.get('host', target)}:{data.get('port')}",
                    raw_data=data
                )
            except json.JSONDecodeError:
                continue


class KaliRustscanScanner(KaliBaseScanner):
    """RustScan 快速端口扫描器"""
    scanner_type = ScannerType.RUSTSCAN
    
    def get_tool_name(self) -> str:
        return "rustscan"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-a", target,
            "--no-nmap",
            "-b", "500",
            "--json"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else []
            if isinstance(data, list):
                for item in data:
                    for port in item.get("ports", []):
                        yield ScanFinding(
                            scanner=self.scanner_type,
                            name=f"开放端口: {port.get('port')}",
                            severity="info",
                            category="network",
                            description=f"RustScan 发现端口 {port.get('port')} 开放",
                            location=f"{item.get('ip', target)}:{port.get('port')}",
                            raw_data=item
                        )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                match = re.search(r'(\d+)/(?:tcp|udp)', line)
                if match:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"开放端口: {match.group(1)}",
                        severity="info",
                        category="network",
                        description=f"RustScan 发现端口 {match.group(1)} 开放",
                        location=f"{target}:{match.group(1)}",
                        raw_data={"port": int(match.group(1))}
                    )


class KaliHttpxScanner(KaliBaseScanner):
    """httpx HTTP 探测器"""
    scanner_type = ScannerType.HTTPX
    
    def get_tool_name(self) -> str:
        return "httpx"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-u", target,
            "-silent",
            "-json",
            "-status-code",
            "-content-length",
            "-title",
            "-tech-detect",
            "-follow-redirects"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                technologies = data.get("tech", [])
                status_code = data.get("status_code", 0)
                
                severity = "info"
                if status_code >= 500:
                    severity = "low"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"HTTP 服务: {data.get('url', target)}",
                    severity=severity,
                    category="web_fingerprint",
                    description=f"状态码: {status_code}, 标题: {data.get('title', 'N/A')}, 技术栈: {', '.join(technologies[:5])}",
                    location=data.get("url", target),
                    evidence=f"Status: {status_code}, Length: {data.get('content_length')}",
                    raw_data=data
                )
            except json.JSONDecodeError:
                continue


class KaliKatanaScanner(KaliBaseScanner):
    """Katana 爬虫/链接发现"""
    scanner_type = ScannerType.KATANA
    
    def get_tool_name(self) -> str:
        return "katana"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        depth = config.get("katana_depth", 3)
        return [
            "-u", target,
            "-d", str(depth),
            "-silent",
            "-json",
            "-jc"  # 解析 JavaScript
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        urls_found = set()
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if url and url not in urls_found:
                    urls_found.add(url)
                    # 检测敏感路径
                    severity = "info"
                    sensitive_patterns = ['admin', 'login', 'api', 'config', 'backup', '.env', '.git', 'debug', 'test']
                    if any(p in url.lower() for p in sensitive_patterns):
                        severity = "medium"
                    
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"URL 发现: {url[:80]}",
                        severity=severity,
                        category="url_discovery",
                        description=f"Katana 发现 URL: {url}",
                        location=url,
                        raw_data=data
                    )
            except json.JSONDecodeError:
                continue


class KaliArpscanScanner(KaliBaseScanner):
    """ARP 网络扫描器"""
    scanner_type = ScannerType.NMAP  # 复用 NMAP 类型
    
    def get_tool_name(self) -> str:
        return "arp-scan"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return ["-l", "-localnet"] if '/' not in target else [target]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)', line)
            if match:
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"主机发现: {match.group(1)}",
                    severity="info",
                    category="network",
                    description=f"MAC: {match.group(2)}, 厂商: {match.group(3).strip()}",
                    location=match.group(1),
                    raw_data={"ip": match.group(1), "mac": match.group(2), "vendor": match.group(3).strip()}
                )


class KaliSubfinderScanner(KaliBaseScanner):
    """Subfinder 子域名枚举工具"""
    scanner_type = ScannerType.SUBFINDER
    
    def get_tool_name(self) -> str:
        return "subfinder"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        # 清理目标，提取域名
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        return ["-d", clean_target, "-silent", "-json"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                if host:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"子域名: {host}",
                        severity="info",
                        category="subdomain",
                        description=f"Subfinder 发现子域名 {host}",
                        location=host,
                        raw_data=data,
                    )
            except json.JSONDecodeError:
                # 非 JSON 行可能是纯文本子域名
                if "." in line and " " not in line:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"子域名: {line}",
                        severity="info",
                        category="subdomain",
                        description=f"Subfinder 发现子域名 {line}",
                        location=line,
                    )


class KaliAmassScanner(KaliBaseScanner):
    """Amass 子域名枚举与资产发现工具"""
    scanner_type = ScannerType.AMASS
    
    def get_tool_name(self) -> str:
        return "amass"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        return ["enum", "-passive", "-d", clean_target, "-json", "/dev/stdout"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                domain = data.get("domain", "")
                addresses = data.get("addresses", [])
                addr_str = ", ".join(a.get("ip", "") for a in addresses if a.get("ip")) if addresses else ""
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"子域名: {name}",
                    severity="info",
                    category="subdomain",
                    description=f"Amass 发现子域名 {name} (父域: {domain})" + (f", IP: {addr_str}" if addr_str else ""),
                    location=name,
                    raw_data=data,
                )
            except json.JSONDecodeError:
                continue


class KaliDirbScanner(KaliBaseScanner):
    """Dirb 目录枚举工具"""
    scanner_type = ScannerType.DIRB
    
    def get_tool_name(self) -> str:
        return "dirb"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        wordlist = config.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        return [url, wordlist, "-S", "-r"]  # -S 静默, -r 递归不进子目录
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        current_dir = ""
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith("+"):
                # 格式: + DIRECTORY (status-code) http://target/path
                match = re.search(r'\+\s+\S+\s+\((\d+)\)\s+(\S+)', line)
                if match:
                    status = match.group(1)
                    path = match.group(2)
                    severity = "info"
                    category = "directory"
                    # 高状态码可能表示管理界面
                    if status in ("200", "301", "302") and any(kw in path.lower() for kw in ["admin", "login", "backup", "config", "shell", "upload"]):
                        severity = "low"
                        category = "sensitive_directory"
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"发现目录: {path} [{status}]",
                        severity=severity,
                        category=category,
                        description=f"Dirb 发现路径 {path} (HTTP {status})",
                        location=path,
                        raw_data={"status": status, "path": path},
                    )


class KaliDigScanner(KaliBaseScanner):
    """Dig DNS 枚举工具"""
    scanner_type = ScannerType.DIG

    def get_tool_name(self) -> str:
        return "dig"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        record_type = config.get("dns_record", "ANY")
        return ["+noall", "+answer", target, record_type]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                name = parts[0].rstrip(".")
                ttl = parts[1]
                rtype = parts[2]
                value = " ".join(parts[3:]).rstrip(".")
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"DNS 记录: {rtype} {name}",
                    severity="info",
                    category="dns",
                    description=f"DNS {rtype} 记录: {name} -> {value} (TTL: {ttl})",
                    location=name,
                    raw_data={"name": name, "ttl": ttl, "type": rtype, "value": value},
                )


class KaliWhoisScanner(KaliBaseScanner):
    """WHOIS 域名/IP 查询工具"""
    scanner_type = ScannerType.WHOIS

    def get_tool_name(self) -> str:
        return "whois"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [target]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        info_fields = {}
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith("%") or not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key and value:
                info_fields[key] = value

        interesting_keys = ["registrar", "creation date", "registry expiry date",
                            "name server", " registrant org", "admin email", "tech email"]
        summary_parts = []
        for k in interesting_keys:
            if k in info_fields:
                summary_parts.append(f"{k}: {info_fields[k]}")

        yield ScanFinding(
            scanner=self.scanner_type,
            name=f"WHOIS 查询: {target}",
            severity="info",
            category="whois",
            description="\n".join(summary_parts[:10]) if summary_parts else f"WHOIS 查询 {target}",
            location=target,
            evidence=stdout[:2000],
            raw_data=info_fields,
        )


class KaliArpingScanner(KaliBaseScanner):
    """ARP Ping 扫描器"""
    scanner_type = ScannerType.ARPING

    def get_tool_name(self) -> str:
        return "arping"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        count = config.get("arping_count", "3")
        return ["-c", count, target]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        alive = "0 received" not in stdout and ("bytes from" in stdout.lower() or "reply from" in stdout.lower())
        if alive:
            mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', stdout)
            mac = mac_match.group(1) if mac_match else "unknown"
            yield ScanFinding(
                scanner=self.scanner_type,
                name=f"ARP 存活: {target}",
                severity="info",
                category="host_discovery",
                description=f"ARP Ping 确认 {target} 在线 (MAC: {mac})",
                location=target,
                raw_data={"target": target, "mac": mac, "alive": True},
            )

class KaliFierceScanner(KaliBaseScanner):
    """Fierce DNS 枚举和主机发现工具"""
    scanner_type = ScannerType.DNS

    def get_tool_name(self) -> str:
        return "fierce"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        return ["--domain", clean_target, "--subdomain-file", "/dev/null"]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Fierce 输出格式: found host xxx.xxx.xxx.xxx
            match = re.search(r'found host\s+(\S+)\s*\(?(\S+)?\)?', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                hostname = match.group(2) or ip
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"主机发现: {hostname} ({ip})",
                    severity="info",
                    category="dns_host",
                    description=f"Fierce 发现主机 {hostname} ({ip})",
                    location=ip,
                    raw_data={"ip": ip, "hostname": hostname},
                )
            elif "DNS" in line and "record" in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"DNS 发现",
                    severity="info",
                    category="dns_record",
                    description=line,
                    location=target,
                )
