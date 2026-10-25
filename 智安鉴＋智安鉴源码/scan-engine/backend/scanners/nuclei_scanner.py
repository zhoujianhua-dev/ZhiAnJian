"""Nuclei scanner integration"""
import asyncio
import json
from typing import AsyncIterator
from loguru import logger

from .base import BaseScanner, ScanFinding, ScannerType


class NucleiScanner(BaseScanner):
    """Nuclei 漏洞扫描器"""
    
    scanner_type = ScannerType.NUCLEI
    
    def __init__(self):
        self.nuclei_path = "nuclei"
    
    async def is_available(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            return proc.returncode == 0
        except FileNotFoundError:
            return False
    
    async def scan(self, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        """执行 Nuclei 扫描"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        # 构建 Nuclei 命令
        severity = config.get("severity", "critical,high,medium")
        rate_limit = config.get("rate_limit", 10)
        
        scan_args = [
            self.nuclei_path,
            "-u", target,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-json",  # JSON 输出
            "-silent",
        ]
        
        # 可选：指定模板
        if templates := config.get("templates"):
            scan_args.extend(["-t", templates])
        
        logger.info(f"Starting Nuclei scan: {target}")
        
        proc = await asyncio.create_subprocess_exec(
            *scan_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 逐行读取 JSON 输出
        async for line in self._read_lines(proc.stdout):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                yield self._parse_finding(data)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON line: {line[:100]}")
        
        await proc.wait()
        
        if proc.returncode not in (0, 1):  # 1 = found vulnerabilities
            stderr = await proc.stderr.read()
            logger.error(f"Nuclei error: {stderr.decode()}")
    
    async def _read_lines(self, stream) -> AsyncIterator[str]:
        """异步读取输出行"""
        while True:
            line = await stream.readline()
            if not line:
                break
            yield line.decode().strip()
    
    def _parse_finding(self, data: dict) -> ScanFinding:
        """解析 Nuclei JSON 输出"""
        info = data.get("info", {})
        
        # 映射严重性
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "unknown": "info"
        }
        
        severity = severity_map.get(
            info.get("severity", "info").lower(),
            "info"
        )
        
        # 提取 CVE/CWE 信息
        classification = info.get("classification", {})
        cve_id = classification.get("cve-id", [])
        cwe_id = classification.get("cwe-id", [])
        
        return ScanFinding(
            scanner=self.scanner_type,
            name=info.get("name", "Unknown Vulnerability"),
            severity=severity,
            category=info.get("tags", ["web"])[0] if info.get("tags") else "web",
            description=info.get("description", ""),
            location=data.get("matched-at", data.get("host", "")),
            evidence=data.get("extracted-results", data.get("matcher-name", "")),
            raw_data=data,
            metadata={
                "template_id": data.get("template-id", ""),
                "cve": cve_id,
                "cwe": cwe_id,
                "reference": info.get("reference", []),
                "matcher_name": data.get("matcher-name", ""),
            }
        )
