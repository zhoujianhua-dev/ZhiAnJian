"""Nmap scanner integration"""
import asyncio
import re
from typing import AsyncIterator
from loguru import logger

from .base import BaseScanner, ScanFinding, ScannerType


class NmapScanner(BaseScanner):
    """Nmap 端口扫描器"""
    
    scanner_type = ScannerType.NMAP
    
    def __init__(self):
        self.nmap_path = "nmap"
    
    async def is_available(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nmap_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            return proc.returncode == 0
        except FileNotFoundError:
            return False
    
    async def scan(self, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        """执行 Nmap 扫描"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        # 构建 Nmap 命令
        ports = config.get("ports", "1-1000")
        scan_args = [
            self.nmap_path,
            "-sV",  # 版本检测
            "-sC",  # 默认脚本
            "--open",  # 只显示开放端口
            "-T4",  # 快速扫描
            "-p", str(ports),
            "-oX", "-",  # XML 输出到 stdout
            target
        ]
        
        logger.info(f"Starting Nmap scan: {target}")
        
        proc = await asyncio.create_subprocess_exec(
            *scan_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            logger.error(f"Nmap error: {stderr.decode()}")
            return
        
        # 解析 XML 输出
        async for finding in self._parse_xml_output(stdout.decode(), target):
            yield finding
    
    async def _parse_xml_output(self, xml_output: str, target: str) -> AsyncIterator[ScanFinding]:
        """解析 Nmap XML 输出"""
        import xml.etree.ElementTree as ET
        
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return
        
        for host in root.findall(".//host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else target
            
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                
                service = port.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                service_version = service.get("version", "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                
                # 检查脚本输出中的漏洞
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    
                    # 检测高危服务
                    severity = self._assess_severity(script_id, script_output, service_name)
                    
                    if severity != "info" or "vuln" in script_id.lower():
                        yield ScanFinding(
                            scanner=self.scanner_type,
                            name=f"{script_id} on {service_name}",
                            severity=severity,
                            category="network",
                            description=script_output[:500],
                            location=f"{ip}:{port_id}/{protocol}",
                            evidence=script_output,
                            raw_data={
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "version": service_version,
                                "script_id": script_id
                            }
                        )
                
                # 报告开放端口（info 级别）
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"Open port: {service_name}",
                    severity="info",
                    category="network",
                    description=f"{product} {service_version}".strip() or service_name,
                    location=f"{ip}:{port_id}/{protocol}",
                    raw_data={
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "version": service_version
                    }
                )
    
    def _assess_severity(self, script_id: str, output: str, service: str) -> str:
        """评估漏洞严重性"""
        output_lower = output.lower()
        script_lower = script_id.lower()
        
        # 关键漏洞指标
        if any(x in script_lower for x in ["vuln", "exploit", "cve"]):
            if "critical" in output_lower:
                return "critical"
            return "high"
        
        # 危险服务
        dangerous_services = ["telnet", "ftp", "rsh", "rlogin"]
        if service.lower() in dangerous_services:
            return "medium"
        
        # 弱加密
        if any(x in output_lower for x in ["ssl", "weak", "deprecated"]):
            return "medium"
        
        return "info"
