"""Generic Kali-based scanner - 通过 Kali 容器执行扫描工具"""
import asyncio
import json
import re
from typing import AsyncIterator, List, Dict, Optional
from abc import ABC, abstractmethod

from loguru import logger

from .base import BaseScanner, ScanFinding, ScannerType
from .kali_client import get_kali_client, KaliClient


def split_host_port(target: str) -> tuple:
    """把 '10.0.5.11:8111' / 'http://host:8111/path' 拆成 (host, [port])。

    nmap 不认 host:port 写法（会 Failed to resolve），必须先拆出端口。
    """
    raw = (target or "").strip()
    if "//" in raw:
        raw = raw.split("//", 1)[1]
    raw = raw.split("/", 1)[0]
    if raw.startswith("["):          # IPv6 字面量 [::1]:8111
        host, _, rest = raw.partition("]")
        port = rest.lstrip(":")
        return host + "]", [port] if port.isdigit() else []
    host, sep, port = raw.rpartition(":")
    if sep and port.isdigit():
        return host, [port]
    return raw, []


class KaliBaseScanner(BaseScanner, ABC):
    """基于 Kali 容器的扫描器基类"""
    
    def __init__(self):
        self.kali_client: KaliClient = get_kali_client()
    
    @abstractmethod
    def get_tool_name(self) -> str:
        """获取工具名称"""
        pass
    
    @abstractmethod
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建命令参数"""
        pass
    
    @abstractmethod
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析输出"""
        pass
    
    async def is_available(self) -> bool:
        """检查工具是否可用"""
        try:
            # 检查 Kali 容器健康状态
            if not await self.kali_client.health_check():
                logger.warning("Kali scanner container is not healthy")
                return False
            
            # 检查工具是否已安装
            tool_name = self.get_tool_name()
            info = await self.kali_client.get_tool_info(tool_name)
            
            if not info.installed:
                logger.info(f"{tool_name} not installed in Kali container, will install on demand")
                # 返回 True，因为可以按需安装
                return True
            
            return True
        except Exception as e:
            logger.error(f"Failed to check {self.get_tool_name()} availability: {e}")
            return False
    
    async def scan(self, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        """执行扫描"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        tool_name = self.get_tool_name()
        
        # 确保工具已安装
        logger.info(f"Ensuring {tool_name} is installed in Kali container...")
        await self.kali_client.ensure_tools_installed([tool_name])
        
        # 构建命令
        args = self.build_command_args(target, config)
        
        logger.info(f"Executing {tool_name} in Kali: {' '.join(args)}")
        
        # 执行扫描
        # 扫描配置里没有 scan_timeout 字段，回落到设置项默认值（1 小时），
        # 否则 nuclei 跑全量模板会在 600s 处被 kill 并丢弃全部输出
        timeout = config.get("scan_timeout") or 3600
        result = await self.kali_client.execute(
            command=tool_name,
            args=args,
            timeout=timeout
        )
        
        if not result.success and result.returncode != 0:
            # 某些扫描工具即使发现漏洞也会返回非零
            logger.warning(
                f"{tool_name} returned code {result.returncode}, "
                f"but will try to parse output anyway"
            )
        
        # 解析输出
        async for finding in self.parse_output(
            result.stdout,
            result.stderr,
            target,
            config
        ):
            yield finding


class KaliNmapScanner(KaliBaseScanner):
    """Nmap 扫描器（通过 Kali 容器）"""
    
    scanner_type = ScannerType.NMAP
    
    def get_tool_name(self) -> str:
        return "nmap"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 Nmap 命令参数"""
        # nmap 不认 "host:port"（会 Failed to resolve），需拆出端口并入 -p
        host, target_ports = split_host_port(target)
        port_list = [str(p) for p in config.get("custom_ports", [])]
        for p in target_ports:
            if p not in port_list:
                port_list.append(p)
        # 未显式指定端口时扫描常见端口
        port_str = ",".join(port_list) if port_list else "1-1000"
        
        args = [
            "-sV",  # 服务版本检测
            "-sC",  # 默认脚本扫描
            "--open",  # 只显示开放端口
            "-T4",  # 快速模式
            "-p", port_str,
            "-oX", "-",  # XML 输出到 stdout
            host
        ]
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 Nmap XML 输出"""
        import xml.etree.ElementTree as ET
        
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            logger.debug(f"Stdout: {stdout[:500]}")
            return
        
        for host in root.findall(".//host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else target
            
            for port in host.findall(".//port"):
                portid = port.get("portid")
                protocol = port.get("protocol", "tcp")
                
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                
                service = port.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                version = service.get("version", "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                
                # 构建服务描述
                desc_parts = [f"端口 {portid}/{protocol} 开放"]
                if product:
                    desc_parts.append(f"服务: {product}")
                if version:
                    desc_parts.append(f"版本: {version}")
                
                # 检查脚本输出（可能包含漏洞信息）
                scripts = port.findall(".//script")
                vuln_scripts = []
                for script in scripts:
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    
                    # 标记可能的漏洞脚本
                    if any(keyword in script_id.lower() for keyword in ["vuln", "exploit", "cve"]):
                        vuln_scripts.append(f"{script_id}: {script_output[:200]}")
                
                severity = "info"
                category = "open_port"
                
                # 根据服务判断严重性
                if vuln_scripts:
                    severity = "medium"
                    category = "potential_vulnerability"
                    desc_parts.extend(vuln_scripts)
                elif service_name in ["telnet", "ftp", "smtp"]:
                    severity = "low"
                    category = "insecure_service"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"开放端口: {portid}/{protocol} - {service_name}",
                    severity=severity,
                    category=category,
                    description="\n".join(desc_parts),
                    location=f"{ip}:{portid}",
                    evidence=f"{service_name} {version}".strip(),
                    raw_data={
                        "port": portid,
                        "protocol": protocol,
                        "service": service_name,
                        "version": version,
                        "product": product,
                    }
                )


class KaliNucleiScanner(KaliBaseScanner):
    """Nuclei 扫描器（通过 Kali 容器）"""
    
    scanner_type = ScannerType.NUCLEI
    
    def get_tool_name(self) -> str:
        return "nuclei"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 Nuclei 命令参数"""
        args = [
            "-u", target,
            "-jsonl",  # JSONL 输出（Nuclei v3 起 -json 已废弃，改用 -jsonl）
            "-silent",  # 静默模式
        ]
        
        # 严重等级过滤
        severity = config.get("nuclei_severity", "critical,high,medium")
        if severity:
            args.extend(["-severity", severity])
        
        # 速率限制
        rate_limit = config.get("rate_limit", 150)
        args.extend(["-rate-limit", str(rate_limit)])
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 Nuclei JSON 输出"""
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            info = result.get("info", {})
            template_id = result.get("template-id", "unknown")
            name = info.get("name", template_id)
            # 模板标题里通常不含 CVE 编号，补进去便于检索（如 CVE-2023-42793）
            if template_id.upper().startswith("CVE-") and template_id.upper() not in str(name).upper():
                name = f"{name} ({template_id})"
            severity = info.get("severity", "info").lower()
            description = info.get("description", "")
            matched_at = result.get("matched-at", target)
            
            # 提取证据
            extracted_results = result.get("extracted-results", [])
            matcher_name = result.get("matcher-name", "")
            evidence_parts = []
            
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")
            if extracted_results:
                evidence_parts.append(f"Extracted: {', '.join(extracted_results[:3])}")
            
            yield ScanFinding(
                scanner=self.scanner_type,
                name=name,
                severity=severity,
                category=info.get("tags", ["nuclei"])[0] if info.get("tags") else "nuclei",
                description=description or f"Nuclei 模板 {template_id} 匹配",
                location=matched_at,
                evidence="\n".join(evidence_parts) if evidence_parts else "",
                raw_data=result
            )


class KaliNiktoScanner(KaliBaseScanner):
    """Nikto Web 服务器漏洞扫描器"""
    
    scanner_type = ScannerType.NIKTO
    
    def get_tool_name(self) -> str:
        return "nikto"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 Nikto 命令参数"""
        args = [
            "-h", target,
            "-Format", "json",  # JSON 输出
            "-output", "/dev/stdout",  # 输出到 stdout
            "-Tuning", "1234567890abc",  # 所有测试类型
        ]
        
        # 端口
        port = config.get("nikto_port")
        if port:
            args.extend(["-p", str(port)])
        
        # SSL
        if config.get("nikto_ssl") or (target.startswith("https://") or ":443" in target):
            args.append("-ssl")
        
        # 超时
        timeout = config.get("nikto_timeout", 10)
        args.extend(["-timeout", str(timeout)])
        
        # 最大扫描时间（秒）
        max_time = config.get("nikto_max_time", 600)
        args.extend(["-MaxTime", str(max_time)])
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 Nikto JSON 输出"""
        try:
            # Nikto JSON 输出可能包含多个 JSON 对象
            # 尝试解析整个输出
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            # 如果不是 JSON，尝试从文本中提取信息
            async for finding in self._parse_text_output(stdout, target):
                yield finding
            return
        
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            osvdb_id = vuln.get("OSVDB", "0")
            method = vuln.get("method", "GET")
            url = vuln.get("url", "/")
            msg = vuln.get("msg", "")
            references = vuln.get("references", {})
            
            # 评估严重性
            severity = "medium"
            if osvdb_id and osvdb_id != "0":
                severity = "high"
            if any(keyword in msg.lower() for keyword in ["remote code", "rce", "command injection"]):
                severity = "critical"
            elif any(keyword in msg.lower() for keyword in ["xss", "sql injection", "directory traversal"]):
                severity = "high"
            
            location = f"{target.rstrip('/')}{url}" if not url.startswith("http") else url
            
            yield ScanFinding(
                scanner=self.scanner_type,
                name=f"Nikto: {msg[:80]}",
                severity=severity,
                category="web_vulnerability",
                description=msg,
                location=location,
                evidence=f"Method: {method}, OSVDB: {osvdb_id}",
                raw_data=vuln
            )
    
    async def _parse_text_output(self, output: str, target: str) -> AsyncIterator[ScanFinding]:
        """解析 Nikto 文本输出（后备方案）"""
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('-') or line.startswith('+'):
                continue
            
            # 查找漏洞行（通常以 OSVDB 或 ID 开头）
            if 'OSVDB' in line or 'CVE' in line:
                severity = "medium"
                if any(keyword in line.lower() for keyword in ["critical", "remote code"]):
                    severity = "critical"
                elif any(keyword in line.lower() for keyword in ["high", "injection", "xss"]):
                    severity = "high"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"Nikto: {line[:80]}",
                    severity=severity,
                    category="web_vulnerability",
                    description=line,
                    location=target,
                    evidence=line,
                    raw_data={"raw_line": line}
                )


class KaliGobusterScanner(KaliBaseScanner):
    """Gobuster 目录/文件枚举扫描器"""
    
    scanner_type = ScannerType.GOBUSTER
    
    def get_tool_name(self) -> str:
        return "gobuster"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 Gobuster 命令参数"""
        mode = config.get("gobuster_mode", "dir")  # dir, dns, vhost, fuzz
        
        args = [
            mode,
            "-u", target,
            "-q",  # 安静模式
            "--no-color",
            "--no-error",
        ]
        
        # 字典文件
        wordlist = config.get("gobuster_wordlist", "/usr/share/wordlists/dirb/common.txt")
        args.extend(["-w", wordlist])
        
        # 线程数
        threads = config.get("gobuster_threads", 10)
        args.extend(["-t", str(threads)])
        
        # 扩展名
        extensions = config.get("gobuster_extensions")
        if extensions:
            args.extend(["-x", extensions])
        
        # 状态码过滤
        status_codes = config.get("gobuster_status_codes", "200,204,301,302,307,401,403")
        args.extend(["-s", status_codes])
        
        # 如果是 HTTPS
        if target.startswith("https://"):
            args.append("-k")  # 跳过 TLS 验证
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 Gobuster 输出"""
        for line in stdout.split('\n'):
            line = line.strip()
            if not line or line.startswith('=') or line.startswith('Starting'):
                continue
            
            # Gobuster dir 输出格式: /path (Status: 200) [Size: 1234]
            match = re.match(r'(/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]', line)
            if match:
                path = match.group(1)
                status_code = int(match.group(2))
                size = int(match.group(3))
                
                # 根据路径和状态码评估风险
                severity = "info"
                category = "directory_listing"
                
                # 敏感路径检测
                sensitive_patterns = [
                    'admin', 'backup', 'config', 'database', 'db', 'debug',
                    'env', 'git', 'htaccess', 'log', 'phpmyadmin', 'server-info',
                    'server-status', 'wp-admin', 'wp-config', '.svn', '.env'
                ]
                
                if any(pattern in path.lower() for pattern in sensitive_patterns):
                    severity = "high"
                    category = "sensitive_path"
                elif status_code == 200 and size > 0:
                    severity = "low"
                
                location = f"{target.rstrip('/')}{path}"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"目录发现: {path}",
                    severity=severity,
                    category=category,
                    description=f"发现可访问路径 {path}，状态码: {status_code}，大小: {size} 字节",
                    location=location,
                    evidence=f"Status: {status_code}, Size: {size}",
                    raw_data={"path": path, "status": status_code, "size": size}
                )


class KaliSqlmapScanner(KaliBaseScanner):
    """SQLMap SQL 注入检测扫描器"""
    
    scanner_type = ScannerType.SQLMAP
    
    def get_tool_name(self) -> str:
        return "sqlmap"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 SQLMap 命令参数"""
        args = [
            "-u", target,
            "--batch",  # 自动模式
            "--random-agent",  # 随机 User-Agent
            "--output-dir=/tmp/sqlmap_output",
            "--level=3",  # 测试级别
            "--risk=2",  # 风险级别
        ]
        
        # 指定参数
        parameters = config.get("sqlmap_parameters")
        if parameters:
            args.extend(["-p", parameters])
        
        # 数据库类型
        dbms = config.get("sqlmap_dbms")
        if dbms:
            args.extend(["--dbms", dbms])
        
        # 技术
        techniques = config.get("sqlmap_techniques", "BEUSTQ")
        args.extend(["--technique", techniques])
        
        # 跳过静态测试
        args.append("--skip-static")
        
        # 只检测，不利用
        if config.get("sqlmap_detect_only", True):
            args.append("--smart")
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 SQLMap 输出"""
        current_param = None
        current_type = None
        current_payload = None
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # 检测注入点
            if 'is vulnerable' in line or 'injectable' in line.lower():
                # 提取参数名
                param_match = re.search(r"Parameter: ([^\s]+)", line)
                if param_match:
                    current_param = param_match.group(1)
                
                severity = "critical"
                if "OR" in line or "UNION" in line:
                    severity = "critical"
                elif "time-based" in line or "blind" in line:
                    severity = "high"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"SQL 注入: {current_param or '未知参数'}",
                    severity=severity,
                    category="sql_injection",
                    description=f"在参数 {current_param} 中发现 SQL 注入漏洞",
                    location=target,
                    evidence=line,
                    raw_data={"parameter": current_param, "line": line}
                )
            
            # 提取注入类型
            elif 'Type:' in line and current_param:
                type_match = re.search(r'Type:\s*(.+)', line)
                if type_match:
                    current_type = type_match.group(1)
            
            # 提取 payload
            elif 'Payload:' in line and current_param:
                payload_match = re.search(r'Payload:\s*(.+)', line)
                if payload_match:
                    current_payload = payload_match.group(1)
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"SQL 注入 Payload: {current_param}",
                        severity="high",
                        category="sql_injection",
                        description=f"注入类型: {current_type}\nPayload: {current_payload}",
                        location=target,
                        evidence=current_payload,
                        raw_data={
                            "parameter": current_param,
                            "type": current_type,
                            "payload": current_payload
                        }
                    )
            
            # 数据库信息
            elif 'back-end DBMS:' in line:
                db_match = re.search(r'back-end DBMS:\s*(.+)', line)
                if db_match:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"数据库识别: {db_match.group(1)}",
                        severity="info",
                        category="information",
                        description=f"识别到后端数据库: {db_match.group(1)}",
                        location=target,
                        evidence=line,
                        raw_data={"database": db_match.group(1)}
                    )


class KaliWhatWebScanner(KaliBaseScanner):
    """WhatWeb Web 指纹识别扫描器"""
    
    scanner_type = ScannerType.WHATWEB
    
    def get_tool_name(self) -> str:
        return "whatweb"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 WhatWeb 命令参数"""
        aggression = config.get("whatweb_aggression", 3)  # 1-4
        
        args = [
            target,
            f"-a{aggression}",
            "--color=never",
            "--log-json=/dev/stdout",  # JSON 输出
        ]
        
        # 用户代理
        args.extend(["--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"])
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 WhatWeb JSON 输出"""
        for line in stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            # 提取目标信息
            target_url = data.get("target", target)
            plugins = data.get("plugins", {})
            
            # 收集所有发现的技术
            technologies = []
            interesting_findings = []
            
            for plugin_name, plugin_data in plugins.items():
                if plugin_name in ["IP", "Country", "UncommonHeaders"]:
                    continue
                
                version = plugin_data.get("version", [])
                string_matches = plugin_data.get("string", [])
                
                if version:
                    technologies.append(f"{plugin_name} {', '.join(version)}")
                elif string_matches:
                    technologies.append(f"{plugin_name}: {', '.join(string_matches[:2])}")
                else:
                    technologies.append(plugin_name)
                
                # 检查有趣的发现
                if plugin_name.lower() in ['wordpress', 'joomla', 'drupal', 'magento']:
                    interesting_findings.append({
                        "cms": plugin_name,
                        "version": version[0] if version else "unknown"
                    })
            
            # 技术栈发现
            if technologies:
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"Web 技术栈: {target_url}",
                    severity="info",
                    category="technology_fingerprint",
                    description=f"识别到以下技术:\n" + "\n".join(technologies[:20]),
                    location=target_url,
                    evidence=", ".join(technologies[:10]),
                    raw_data=data
                )
            
            # CMS 特别报告
            for finding in interesting_findings:
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"CMS 识别: {finding['cms']}",
                    severity="info",
                    category="cms_detection",
                    description=f"检测到 CMS: {finding['cms']} {finding['version']}",
                    location=target_url,
                    evidence=f"{finding['cms']} {finding['version']}",
                    raw_data=finding
                )


class KaliSslscanScanner(KaliBaseScanner):
    """SSLScan SSL/TLS 配置分析扫描器"""
    
    scanner_type = ScannerType.SSLSCAN
    
    def get_tool_name(self) -> str:
        return "sslscan"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 SSLScan 命令参数"""
        # 从 target 中提取 host:port
        host = target
        port = "443"
        
        if "://" in host:
            host = host.split("://")[1]
        if ":" in host:
            host, port = host.rsplit(":", 1)
        if "/" in host:
            host = host.split("/")[0]
        
        args = [
            f"{host}:{port}",
            "--no-colour",
            "--show-certificate",
        ]
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 SSLScan 输出"""
        host = target
        if "://" in host:
            host = host.split("://")[1]
        if "/" in host:
            host = host.split("/")[0]
        
        # 收集 SSL/TLS 信息
        protocols = []
        ciphers = []
        vulnerabilities = []
        certificate_info = []
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # 协议检测
            if 'SSLv2' in line and 'enabled' in line.lower():
                vulnerabilities.append("SSLv2 已启用（不安全）")
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: SSLv2 已启用",
                    severity="critical",
                    category="ssl_vulnerability",
                    description="SSLv2 协议已启用，存在严重安全风险",
                    location=host,
                    evidence=line,
                    raw_data={"protocol": "SSLv2", "status": "enabled"}
                )
            elif 'SSLv3' in line and 'enabled' in line.lower():
                vulnerabilities.append("SSLv3 已启用（不安全）")
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: SSLv3 已启用",
                    severity="high",
                    category="ssl_vulnerability",
                    description="SSLv3 协议已启用，易受 POODLE 攻击",
                    location=host,
                    evidence=line,
                    raw_data={"protocol": "SSLv3", "status": "enabled"}
                )
            elif 'TLSv1.0' in line and 'enabled' in line.lower():
                vulnerabilities.append("TLSv1.0 已启用（过时）")
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: TLSv1.0 已启用",
                    severity="medium",
                    category="ssl_vulnerability",
                    description="TLSv1.0 已启用，建议升级到 TLSv1.2+",
                    location=host,
                    evidence=line,
                    raw_data={"protocol": "TLSv1.0", "status": "enabled"}
                )
            elif 'TLSv1.1' in line and 'enabled' in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: TLSv1.1 已启用",
                    severity="low",
                    category="ssl_vulnerability",
                    description="TLSv1.1 已启用，建议升级到 TLSv1.2+",
                    location=host,
                    evidence=line,
                    raw_data={"protocol": "TLSv1.1", "status": "enabled"}
                )
            
            # 弱密码套件检测
            if 'RC4' in line and 'enabled' in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: RC4 密码套件启用",
                    severity="high",
                    category="ssl_vulnerability",
                    description="RC4 密码套件已启用，存在安全风险",
                    location=host,
                    evidence=line,
                    raw_data={"cipher": "RC4", "status": "enabled"}
                )
            elif 'DES' in line and 'enabled' in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: DES 密码套件启用",
                    severity="high",
                    category="ssl_vulnerability",
                    description="DES 密码套件已启用，强度不足",
                    location=host,
                    evidence=line,
                    raw_data={"cipher": "DES", "status": "enabled"}
                )
            elif 'NULL' in line and 'enabled' in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: NULL 密码套件启用",
                    severity="critical",
                    category="ssl_vulnerability",
                    description="NULL 密码套件已启用，不提供加密",
                    location=host,
                    evidence=line,
                    raw_data={"cipher": "NULL", "status": "enabled"}
                )
            
            # 证书信息
            if 'Issuer:' in line:
                certificate_info.append(line)
            elif 'Not valid before:' in line or 'Not valid after:' in line:
                certificate_info.append(line)
            
            # Heartbleed 检测
            if 'Heartbleed' in line and 'vulnerable' in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name="SSL/TLS: Heartbleed 漏洞",
                    severity="critical",
                    category="ssl_vulnerability",
                    description="服务器存在 Heartbleed (CVE-2014-0160) 漏洞",
                    location=host,
                    evidence=line,
                    raw_data={"vulnerability": "Heartbleed", "cve": "CVE-2014-0160"}
                )
        
        # 如果没有发现严重问题，报告基本 SSL 信息
        if not vulnerabilities:
            yield ScanFinding(
                scanner=self.scanner_type,
                name=f"SSL/TLS 配置: {host}",
                severity="info",
                category="ssl_configuration",
                description=f"SSL/TLS 配置检查完成，未发现严重问题",
                location=host,
                evidence="\n".join(certificate_info[:5]) if certificate_info else "配置正常",
                raw_data={"certificate_info": certificate_info}
            )
