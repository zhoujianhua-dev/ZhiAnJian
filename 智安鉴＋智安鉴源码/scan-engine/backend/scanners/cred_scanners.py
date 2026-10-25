"""凭证与身份验证类扫描器 - 仅在授权环境下使用"""
import re
import json
from typing import AsyncIterator, List

from loguru import logger
from .base import ScannerType, ScanFinding
from .kali_scanner import KaliBaseScanner


class KaliHydraScanner(KaliBaseScanner):
    """Hydra 暴力破解工具"""
    scanner_type = ScannerType.HYDRA
    
    def get_tool_name(self) -> str:
        return "hydra"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        service = config.get("hydra_service", "ssh")
        user = config.get("hydra_user", "root")
        password_list = config.get("hydra_passlist", "/usr/share/wordlists/rockyou.txt")
        
        return [
            "-l", user,
            "-P", password_list,
            "-t", "4",
            "-f",
            target, service
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if '[' in line and ']' in line and 'host:' in line:
                match = re.search(r'\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)', line)
                if match:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"凭证发现: {match.group(2)}",
                        severity="critical",
                        category="credential_found",
                        description=f"服务: {match.group(2)}, 用户: {match.group(4)}, 密码: {match.group(5)}",
                        location=f"{target}:{match.group(2)}",
                        evidence=line,
                        raw_data={"service": match.group(2), "login": match.group(4), "password": match.group(5)}
                    )


class KaliMedusaScanner(KaliBaseScanner):
    """Medusa 暴力破解工具"""
    scanner_type = ScannerType.MEDUSA
    
    def get_tool_name(self) -> str:
        return "medusa"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        service = config.get("medusa_service", "ssh")
        user = config.get("medusa_user", "root")
        password_list = config.get("medusa_passlist", "/usr/share/wordlists/rockyou.txt")
        
        return [
            "-h", target,
            "-u", user,
            "-P", password_list,
            "-M", service,
            "-t", "4",
            "-f"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if 'SUCCESS' in line:
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"凭证发现: {line.split()[0] if line.split() else ''}",
                    severity="critical",
                    category="credential_found",
                    description=line.strip(),
                    location=target,
                    evidence=line,
                    raw_data={"raw": line}
                )


class KaliNetExecScanner(KaliBaseScanner):
    """NetExec 网络执行工具 (CrackMapExec 继任)"""
    scanner_type = ScannerType.NETEXEC
    
    def get_tool_name(self) -> str:
        return "netexec"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        protocol = config.get("netexec_protocol", "smb")
        return [protocol, target]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if line.strip():
                severity = "info"
                if 'signing:False' in line:
                    severity = "medium"
                if 'Pwn3d!' in line:
                    severity = "critical"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"NetExec: {line.strip()[:60]}",
                    severity=severity,
                    category="network_service",
                    description=line.strip(),
                    location=target,
                    raw_data={"raw": line}
                )


class KaliCeWLScanner(KaliBaseScanner):
    """CeWL 自定义字典生成器"""
    scanner_type = ScannerType.CEWL
    
    def get_tool_name(self) -> str:
        return "cewl"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        depth = config.get("cewl_depth", 2)
        return [
            target,
            "-d", str(depth),
            "-m", "5",
            "--with-numbers",
            "-w", "/dev/stdout"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        words = [w.strip() for w in stdout.split('\n') if w.strip()]
        if words:
            yield ScanFinding(
                scanner=self.scanner_type,
                name=f"字典生成: {len(words)} 个单词",
                severity="info",
                category="wordlist_generation",
                description=f"CeWL 从 {target} 提取了 {len(words)} 个潜在密码/用户名单词",
                location=target,
                evidence=', '.join(words[:20]),
                raw_data={"word_count": len(words), "sample": words[:50]}
            )


class KaliKerbruteScanner(KaliBaseScanner):
    """Kerbrute Kerberos 枚举/暴力破解"""
    scanner_type = ScannerType.KERBRUTE
    
    def get_tool_name(self) -> str:
        return "kerbrute"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        mode = config.get("kerbrute_mode", "userenum")
        wordlist = config.get("kerbrute_wordlist", "/usr/share/wordlists/usernames.txt")
        dc = config.get("kerbrute_dc", target)
        
        return [
            mode,
            "--dc", dc,
            "-d", config.get("domain", "WORKGROUP"),
            wordlist
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if 'VALID' in line:
                match = re.search(r'VALID\s+(\S+)', line)
                if match:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"有效账户: {match.group(1)}",
                        severity="medium",
                        category="account_enumeration",
                        description=f"发现有效的 Kerberos 账户: {match.group(1)}",
                        location=target,
                        evidence=line,
                        raw_data={"username": match.group(1)}
                    )


class KaliEnum4linuxScanner(KaliBaseScanner):
    """Enum4linux-ng SMB/NetBIOS 枚举"""
    scanner_type = ScannerType.ENUM4LINUX
    
    def get_tool_name(self) -> str:
        return "enum4linux-ng"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return ["-A", "-oJ", "/dev/stdout", target]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            
            # 用户枚举
            for user in data.get("users", []):
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"SMB 用户: {user.get('username', '')}",
                    severity="low",
                    category="user_enumeration",
                    description=f"发现 SMB 用户: {user.get('username')}, RID: {user.get('rid')}",
                    location=target,
                    raw_data=user
                )
            
            # 共享枚举
            for share in data.get("shares", []):
                severity = "medium" if share.get("comment", "").lower() in ['ipc$', 'print$'] else "low"
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"SMB 共享: {share.get('name', '')}",
                    severity=severity,
                    category="share_enumeration",
                    description=f"共享: {share.get('name')}, 类型: {share.get('type')}, 备注: {share.get('comment')}",
                    location=f"{target}/{share.get('name')}",
                    raw_data=share
                )
                
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                if 'user:' in line.lower() or 'share:' in line.lower():
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"枚举发现: {line.strip()[:60]}",
                        severity="low",
                        category="enumeration",
                        description=line.strip(),
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliJohnScanner(KaliBaseScanner):
    """John the Ripper 密码破解工具"""
    scanner_type = ScannerType.JOHN
    
    def get_tool_name(self) -> str:
        return "john"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        wordlist = config.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_opt = config.get("john_format")
        args = ["--wordlist=" + wordlist]
        if format_opt:
            args.append("--format=" + format_opt)
        args.append(target)
        return args
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        for line in output.split("\n"):
            line = line.strip()
            # 匹配 John 成功破解的行，格式如: password123   (user1)
            if "(" in line and ")" in line and not line.startswith("--") and not line.startswith("Loaded"):
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"密码破解成功",
                    severity="critical",
                    category="credential_found",
                    description=f"John the Ripper 成功破解密码: {line}",
                    location=target,
                    evidence=line,
                    raw_data={"raw": line},
                )


class KaliPatatorScanner(KaliBaseScanner):
    """Patator 多协议暴力破解工具"""
    scanner_type = ScannerType.PATATOR
    
    def get_tool_name(self) -> str:
        return "patator"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        module = config.get("patator_module", "ftp_login")
        user = config.get("patator_user", "admin")
        password_list = config.get("patator_passlist", "/usr/share/wordlists/rockyou.txt")
        
        args = [
            f"{module} host={target} user={user} password=FILE0",
            f"0={password_list}",
            "-x", "ignore:fgrep='Login incorrect.'",
            "-t", "1",
            "--timeout", "10",
        ]
        return args
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        for line in output.split("\n"):
            line = line.strip()
            # 匹配 Patator 成功行
            if "200" in line or "SUCCESS" in line.upper() or "230" in line:
                if any(kw in line.lower() for kw in ["login", "authenticated", "success"]):
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"凭证发现: {config.get('patator_module', 'unknown')}",
                        severity="critical",
                        category="credential_found",
                        description=f"Patator 暴力破解成功: {line}",
                        location=target,
                        evidence=line,
                        raw_data={"raw": line, "module": config.get("patator_module")},
                    )


class KaliCrowbarScanner(KaliBaseScanner):
    """Crowbar 暴力破解工具"""
    scanner_type = ScannerType.CROWBAR

    def get_tool_name(self) -> str:
        return "crowbar"

    def build_command_args(self, target: str, config: dict) -> List[str]:
        service = config.get("crowbar_service", "rdp")
        user = config.get("crowbar_user", "admin")
        password_list = config.get("crowbar_passlist", "/usr/share/wordlists/rockyou.txt")
        port = config.get("crowbar_port")

        args = ["-b", service, "-s", target]
        if port:
            args.extend(["-p", str(port)])
        args.extend(["-u", user])
        args.extend(["-C", password_list])
        return args

    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        output = stdout + "\n" + stderr
        for line in output.split("\n"):
            line = line.strip()
            if "SUCCESS" in line.upper() or "FOUND" in line.upper():
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"凭证发现: {config.get('crowbar_service', 'rdp')}",
                    severity="critical",
                    category="credential_found",
                    description=f"Crowbar 暴力破解成功: {line}",
                    location=target,
                    evidence=line,
                    raw_data={"raw": line, "service": config.get("crowbar_service", "rdp")},
                )
