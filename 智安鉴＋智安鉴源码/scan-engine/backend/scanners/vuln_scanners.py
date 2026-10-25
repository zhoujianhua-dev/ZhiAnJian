"""漏洞扫描与组件分析类扫描器"""
import re
import json
from typing import AsyncIterator, List

from loguru import logger
from .base import ScannerType, ScanFinding
from .kali_scanner import KaliBaseScanner


class KaliWapitiScanner(KaliBaseScanner):
    """Wapiti Web 漏洞扫描器"""
    scanner_type = ScannerType.WAPITI
    
    def get_tool_name(self) -> str:
        return "wapiti"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-u", target,
            "-f", "json",
            "-o", "/dev/stdout",
            "-m", "common", "blindsql", "xss", "exec", "file", "sql",
            "--no-verify",
            "--timeout", "10"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for vuln_type, vulns in data.get("vulnerabilities", {}).items():
                for vuln in vulns:
                    severity_map = {"High": "high", "Medium": "medium", "Low": "low", "Information": "info"}
                    severity = severity_map.get(vuln.get("level", ""), "medium")
                    
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Wapiti: {vuln_type} - {vuln.get('info', '')[:60]}",
                        severity=severity,
                        category="web_vulnerability",
                        description=vuln.get("info", ""),
                        location=vuln.get("path", target),
                        evidence=vuln.get("payload", ""),
                        raw_data=vuln
                    )
        except json.JSONDecodeError:
            # 文本解析后备
            for line in stdout.split('\n'):
                if 'vulnerability' in line.lower() or 'vuln' in line.lower():
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Wapiti 发现: {line[:60]}",
                        severity="medium",
                        category="web_vulnerability",
                        description=line,
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliTrivyScanner(KaliBaseScanner):
    """Trivy 容器/文件系统漏洞扫描器"""
    scanner_type = ScannerType.TRIVY
    
    def get_tool_name(self) -> str:
        return "trivy"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        scan_type = config.get("trivy_type", "fs")  # fs, image, repo
        severity = config.get("trivy_severity", "CRITICAL,HIGH,MEDIUM")
        
        args = [scan_type, "--format", "json", "--severity", severity]
        
        if scan_type == "image":
            args.append(target)
        else:
            args.extend(["--scanners", "vuln", target])
        
        return args
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"{vuln.get('VulnerabilityID', 'N/A')}: {vuln.get('PkgName', '')}",
                        severity=vuln.get("Severity", "medium").lower(),
                        category="dependency_vulnerability",
                        description=vuln.get("Description", "")[:500],
                        location=f"{result.get('Target', target)} - {vuln.get('PkgName')}",
                        evidence=f"Installed: {vuln.get('InstalledVersion')}, Fixed: {vuln.get('FixedVersion', 'N/A')}",
                        raw_data=vuln
                    )
        except json.JSONDecodeError:
            pass


class KaliGrypeScanner(KaliBaseScanner):
    """Grype 依赖漏洞扫描器"""
    scanner_type = ScannerType.GRYPE
    
    def get_tool_name(self) -> str:
        return "grype"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [target, "-o", "json", "--only-fixed"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"{vuln.get('id', 'N/A')}: {artifact.get('name', '')}",
                    severity=vuln.get("severity", "medium").lower(),
                    category="dependency_vulnerability",
                    description=vuln.get("description", "")[:500],
                    location=f"{artifact.get('name')} {artifact.get('version')}",
                    evidence=f"Fix: {vuln.get('fix', {}).get('versions', ['N/A'])}",
                    raw_data=match
                )
        except json.JSONDecodeError:
            pass


class KaliLynisScanner(KaliBaseScanner):
    """Lynis 系统安全审计"""
    scanner_type = ScannerType.LYNIS
    
    def get_tool_name(self) -> str:
        return "lynis"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return ["audit", "system", "--quick", "--no-colors", "--json"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for test in data.get("tests", []):
                status = test.get("status", "")
                if status in ["warning", "suggestion"]:
                    severity = "medium" if status == "warning" else "low"
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Lynis: {test.get('id', '')} - {test.get('description', '')[:60]}",
                        severity=severity,
                        category="system_hardening",
                        description=test.get("description", ""),
                        location=target,
                        evidence=test.get("solution", ""),
                        raw_data=test
                    )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                if 'WARNING' in line or 'SUGGESTION' in line:
                    severity = "medium" if 'WARNING' in line else "low"
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Lynis: {line.strip()[:60]}",
                        severity=severity,
                        category="system_hardening",
                        description=line.strip(),
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliSearchsploitScanner(KaliBaseScanner):
    """SearchSploit 漏洞利用数据库搜索"""
    scanner_type = ScannerType.SEARCHSPLOIT
    
    def get_tool_name(self) -> str:
        return "searchsploit"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        search_terms = config.get("searchsploit_terms", target)
        return [search_terms, "--json", "-t"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for exploit in data.get("RESULTS_EXPLOIT", []):
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"Exploit: {exploit.get('Title', '')[:60]}",
                    severity="high",
                    category="exploit_available",
                    description=f"EDB-ID: {exploit.get('EDB-ID')}, 作者: {exploit.get('Author')}",
                    location=exploit.get("Path", ""),
                    evidence=f"平台: {exploit.get('Platform')}, 类型: {exploit.get('Type')}",
                    raw_data=exploit
                )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                if '|' in line and 'Exploit' not in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 2:
                        yield ScanFinding(
                            scanner=self.scanner_type,
                            name=f"Exploit: {parts[0][:60]}",
                            severity="medium",
                            category="exploit_available",
                            description=parts[0],
                            location=target,
                            raw_data={"raw": line}
                        )


class KaliYaraScanner(KaliBaseScanner):
    """YARA 恶意软件/规则匹配扫描器"""
    scanner_type = ScannerType.YARA
    
    def get_tool_name(self) -> str:
        return "yara"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        rules_path = config.get("yara_rules", "/usr/share/yara-rules/")
        return ["-r", "-s", rules_path, target]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if not line.strip() or line.startswith('error:'):
                continue
            match = re.match(r'(\S+)\s+(.+)', line)
            if match:
                rule_name = match.group(1)
                matched_file = match.group(2)
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"YARA 匹配: {rule_name}",
                    severity="high",
                    category="malware_detection",
                    description=f"YARA 规则 {rule_name} 匹配到文件 {matched_file}",
                    location=matched_file,
                    evidence=line,
                    raw_data={"rule": rule_name, "file": matched_file}
                )


class KaliZapScanner(KaliBaseScanner):
    """OWASP ZAP 基线扫描器 - Web 应用安全扫描"""
    scanner_type = ScannerType.ZAP
    
    def get_tool_name(self) -> str:
        return "zap-cli"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        return ["quick-scan", "-s", "xss,sqli,info", "-r", "html", url]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        # 解析 ZAP 的告警输出
        current_alert = {}
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("Alert:"):
                if current_alert:
                    yield self._make_finding(current_alert, target)
                current_alert = {"name": line[6:].strip()}
            elif "Risk:" in line or "risk:" in line.lower():
                risk = line.split(":", 1)[1].strip().lower()
                current_alert["risk"] = risk
            elif "URL:" in line or "url:" in line.lower():
                current_alert["url"] = line.split(":", 1)[1].strip()
            elif "Description:" in line:
                current_alert["description"] = line.split(":", 1)[1].strip()
            elif "Solution:" in line:
                current_alert["solution"] = line.split(":", 1)[1].strip()
        
        if current_alert:
            yield self._make_finding(current_alert, target)
    
    def _make_finding(self, alert: dict, target: str) -> ScanFinding:
        risk = alert.get("risk", "medium")
        severity_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}
        severity = severity_map.get(risk, "medium")
        
        desc = alert.get("description", "")
        solution = alert.get("solution", "")
        if solution:
            desc += f"\n修复建议: {solution}"
        
        return ScanFinding(
            scanner=self.scanner_type,
            name=f"ZAP: {alert.get('name', '未知告警')}",
            severity=severity,
            category="web_vulnerability",
            description=desc,
            location=alert.get("url", target),
            evidence=alert.get("name", ""),
            raw_data=alert,
        )


class KaliWafw00fScanner(KaliBaseScanner):
    """WafW00f Web 应用防火墙检测工具"""
    scanner_type = ScannerType.WAFW00F

    def get_tool_name(self) -> str:
        return "wafw00f"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        return ["-a", url, "-o", "/dev/stdout", "-f", "json"]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout)
            results = data.get("results", []) if isinstance(data, dict) else []
            for entry in results:
                firewall = entry.get("firewall", "Unknown")
                url = entry.get("url", target)
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"WAF 检测: {firewall}",
                    severity="info",
                    category="waf_detection",
                    description=f"目标 {url} 使用 {firewall} WAF",
                    location=url,
                    raw_data=entry,
                )
        except json.JSONDecodeError:
            for line in stdout.split("\n"):
                if "behind" in line.lower() or "waf" in line.lower():
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name="WAF 检测",
                        severity="info",
                        category="waf_detection",
                        description=line.strip(),
                        location=target,
                        evidence=line,
                    )


class KaliMsfconsoleScanner(KaliBaseScanner):
    """Metasploit Framework 漏洞利用扫描器"""
    scanner_type = ScannerType.MSFCONSOLE

    def get_tool_name(self) -> str:
        return "msfconsole"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        module = config.get("msf_module", "auxiliary/scanner/portscan/tcp")
        return ["-q", "-x", f"use {module}; set RHOSTS {target}; run; exit", "--no-color"]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        for line in output.split("\n"):
            line = line.strip()
            if "[+]" in line:
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"Metasploit 发现: {line[:60]}",
                    severity="medium",
                    category="msf_finding",
                    description=line,
                    location=target,
                    evidence=line,
                    raw_data={"raw": line},
                )
            elif "[*]" in line and ("found" in line.lower() or "open" in line.lower() or "vuln" in line.lower()):
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"Metasploit: {line[:60]}",
                    severity="low",
                    category="msf_info",
                    description=line,
                    location=target,
                    evidence=line,
                )


class KaliDavtestScanner(KaliBaseScanner):
    """DAVTest WebDAV 服务器测试工具"""
    scanner_type = ScannerType.DAVTEST

    def get_tool_name(self) -> str:
        return "davtest"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        return ["-url", url, "-nocolor"]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split("\n"):
            line = line.strip()
            if "WRITE" in line.upper() and "OK" in line.upper():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"WebDAV 写入权限: {target}",
                    severity="high",
                    category="webdav_vulnerability",
                    description=f"WebDAV 服务器允许写入操作: {line}",
                    location=target,
                    evidence=line,
                    raw_data={"raw": line},
                )
            elif "TESTING" in line.upper() and "PROPFIND" in line.upper():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"WebDAV PROPFIND 可用",
                    severity="low",
                    category="webdav_detection",
                    description=f"WebDAV PROPFIND 方法可用: {line}",
                    location=target,
                    evidence=line,
                )


class KaliSubjackScanner(KaliBaseScanner):
    """Subjack 子域名接管检测工具"""
    scanner_type = ScannerType.SUBJACK

    def get_tool_name(self) -> str:
        return "subjack"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
        return ["-d", clean_target, "-t", "100", "-timeout", "30", "-ssl", "-a", "/dev/stdout"]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "vulnerable" in line.lower() or "takeover" in line.lower() or "cname" in line.lower():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"子域名接管风险: {line[:60]}",
                    severity="high",
                    category="subdomain_takeover",
                    description=f"Subjack 检测到潜在子域名接管: {line}",
                    location=target,
                    evidence=line,
                    raw_data={"raw": line},
                )
            elif "." in line and not line.startswith("-"):
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"子域名扫描: {line}",
                    severity="info",
                    category="subdomain",
                    description=f"Subjack 扫描子域名: {line}",
                    location=line,
                )


class KaliNmapVulnScanner(KaliBaseScanner):
    """Nmap 漏洞脚本扫描器"""
    scanner_type = ScannerType.NMAP_VULN

    def get_tool_name(self) -> str:
        return "nmap"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        return ["-sV", "--script", "vuln,exploit", "-T4", "-Pn", "-oX", "-", target]

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(stdout)
        except Exception:
            for line in stdout.split("\n"):
                line = line.strip()
                if "VULNERABLE" in line.upper() or "CVE-" in line:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Nmap 漏洞: {line[:60]}",
                        severity="high",
                        category="vulnerability",
                        description=line,
                        location=target,
                        evidence=line,
                    )
            return

        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                portid = port.get("portid", "")
                for script in port.findall(".//script"):
                    script_id = script.get("id", "")
                    output = script.get("output", "")
                    if "VULNERABLE" in output.upper() or "CVE" in output.upper():
                        severity = "critical" if "VULNERABLE" in output.upper() else "high"
                        yield ScanFinding(
                            scanner=self.scanner_type,
                            name=f"Nmap 漏洞: {script_id} (port {portid})",
                            severity=severity,
                            category="vulnerability",
                            description=output[:500],
                            location=f"{target}:{portid}",
                            evidence=output[:1000],
                            raw_data={"script": script_id, "output": output},
                        )
