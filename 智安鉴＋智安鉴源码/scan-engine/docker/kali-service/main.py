"""Kali Scanner API Service - 运行在 Kali 容器内的微服务"""
import asyncio
import os
import shutil
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from loguru import logger
import uvicorn

# 配置日志
logger.add(
    "/scanner/logs/kali-service.log",
    rotation="10 MB",
    retention="7 days",
    level="INFO"
)

app = FastAPI(title="Kali Scanner Service", version="1.0.0")

# ============= 数据模型 =============

class ExecuteRequest(BaseModel):
    """命令执行请求"""
    command: str = Field(..., description="要执行的命令")
    args: List[str] = Field(default_factory=list, description="命令参数")
    timeout: int = Field(default=300, ge=1, le=3600, description="超时时间（秒）")
    cwd: Optional[str] = Field(default=None, description="工作目录")
    env: Optional[Dict[str, str]] = Field(default=None, description="环境变量")


class ShellCommandRequest(BaseModel):
    """Shell 命令执行请求"""
    command: str = Field(..., description="要执行的 shell 命令字符串")
    timeout: int = Field(default=300, ge=1, le=3600, description="超时时间（秒）")
    cwd: Optional[str] = Field(default=None, description="工作目录")
    env: Optional[Dict[str, str]] = Field(default=None, description="环境变量")


class ExecuteResponse(BaseModel):
    """命令执行响应"""
    success: bool
    returncode: int
    stdout: str
    stderr: str
    duration: float
    error: Optional[str] = None


class InstallRequest(BaseModel):
    """工具安装请求"""
    tools: List[str] = Field(..., description="要安装的工具列表")
    update_cache: bool = Field(default=False, description="是否先更新 apt 缓存")


class InstallResponse(BaseModel):
    """工具安装响应"""
    success: bool
    installed: List[str]
    failed: List[str]
    already_installed: List[str]
    details: str


class ToolInfo(BaseModel):
    """工具信息"""
    name: str
    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None


# ============= 工具管理 =============

# Kali 工具元包映射
KALI_METAPACKAGES = {
    "web": "kali-tools-web",
    "vulnerability": "kali-tools-vulnerability", 
    "information-gathering": "kali-tools-information-gathering",
    "passwords": "kali-tools-passwords",
    "wireless": "kali-tools-wireless",
    "forensics": "kali-tools-forensics",
    "sniffing": "kali-tools-sniffing-spoofing",
    "exploitation": "kali-tools-exploitation",
}

# 工具到包名的映射
TOOL_PACKAGES = {
    # 网络扫描与资产识别
    "nmap": ["nmap"],
    "masscan": ["masscan"],
    "naabu": [],  # Go 安装
    "rustscan": [],  # 特殊安装
    "httpx": [],  # Go 安装
    "whatweb": ["whatweb"],
    "katana": [],  # Go 安装
    
    # 漏洞扫描与组件分析
    "nuclei": [],  # 特殊安装
    "nikto": ["nikto"],
    "wapiti": ["wapiti"],
    "trivy": [],  # 特殊安装
    "grype": [],  # 特殊安装
    "lynis": ["lynis"],
    "searchsploit": [],  # Git 安装
    "yara": ["yara"],
    
    # Web/API 测试
    "sqlmap": ["sqlmap"],
    "ffuf": [],  # Go 安装
    "dirsearch": [],  # pip 安装
    "gobuster": [],  # Go 安装
    "feroxbuster": [],  # Go 安装
    "wfuzz": ["wfuzz"],
    "dalfox": [],  # Go 安装
    "xsstrike": [],  # Git 安装
    "commix": [],  # Git 安装
    "jwt_tool": [],  # Git 安装
    "newman": [],  # npm 安装
    "sslscan": ["sslscan"],
    "dirb": ["dirb"],
    
    # 凭证与身份验证
    "hydra": ["hydra"],
    "medusa": ["medusa"],
    "patator": [],  # pip 安装
    "crowbar": ["crowbar"],
    "netexec": [],  # pip 安装
    "cewl": ["cewl"],
    "john": ["john"],
    "hashcat": ["hashcat"],
    "kerbrute": [],  # 特殊安装
    "enum4linux-ng": [],  # Git 安装
    
    # 后渗透与取证辅助
    "linpeas": [],  # 特殊安装
    "winpeas": [],  # 特殊安装
    "linenum": [],  # Git 安装
    "linux-exploit-suggester": [],  # Git 安装
    "pspy": [],  # 特殊安装
    "gitleaks": [],  # 特殊安装
    "trufflehog": [],  # pip 安装
    
    # 其他工具
    "metasploit": ["metasploit-framework"],
    "subfinder": [],  # Go 安装
    "amass": ["amass"],
    "dnsenum": ["dnsenum"],
    "theharvester": ["theharvester"],
    "john": ["john"],
    "hashcat": ["hashcat"],
}

# 安装状态缓存
_tool_cache: Dict[str, bool] = {}
_install_lock = asyncio.Lock()


def is_tool_installed(tool_name: str) -> bool:
    """检查工具是否已安装"""
    if tool_name in _tool_cache:
        return _tool_cache[tool_name]
    
    result = shutil.which(tool_name) is not None
    _tool_cache[tool_name] = result
    return result


def get_tool_version(tool_name: str) -> Optional[str]:
    """获取工具版本"""
    try:
        # 尝试常见的版本命令
        for flag in ["--version", "-v", "-V", "version"]:
            proc = asyncio.create_subprocess_exec(
                tool_name, flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = asyncio.run(asyncio.wait_for(proc.communicate(), timeout=5))
            if stdout:
                version = stdout.decode().split('\n')[0]
                return version[:100]
    except:
        pass
    return None


async def install_apt_packages(packages: List[str], update_cache: bool = False) -> tuple[bool, str]:
    """安装 APT 包"""
    if not packages:
        return True, "No packages to install"
    
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    
    try:
        # 更新缓存
        if update_cache:
            logger.info("Updating apt cache...")
            proc = await asyncio.create_subprocess_exec(
                "apt-get", "update",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
        
        # 安装包
        logger.info(f"Installing packages: {packages}")
        cmd = ["apt-get", "install", "-y", "--no-install-recommends"] + packages
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        
        if proc.returncode == 0:
            return True, stdout.decode()
        else:
            return False, stderr.decode()
    
    except asyncio.TimeoutError:
        return False, "Installation timeout"
    except Exception as e:
        return False, str(e)


async def install_special_tool(tool_name: str) -> tuple[bool, str]:
    """安装需要特殊处理的工具"""
    try:
        if tool_name == "nuclei":
            # 安装 nuclei
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip -o /tmp/nuclei.zip && "
                "unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && "
                "chmod +x /usr/local/bin/nuclei && "
                "rm /tmp/nuclei.zip && "
                "nuclei -update-templates"
            ]
        elif tool_name == "ffuf":
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz | "
                "tar -xzf - -C /usr/local/bin/ && "
                "chmod +x /usr/local/bin/ffuf"
            ]
        elif tool_name == "httpx":
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_$(uname -s)_$(uname -m).zip -o /tmp/httpx.zip && "
                "unzip -o /tmp/httpx.zip -d /usr/local/bin/ && "
                "chmod +x /usr/local/bin/httpx && "
                "rm /tmp/httpx.zip"
            ]
        elif tool_name == "subfinder":
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(uname -s)_$(uname -m).zip -o /tmp/subfinder.zip && "
                "unzip -o /tmp/subfinder.zip -d /usr/local/bin/ && "
                "chmod +x /usr/local/bin/subfinder && "
                "rm /tmp/subfinder.zip"
            ]
        elif tool_name == "testssl":
            cmd = [
                "sh", "-c",
                "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && "
                "ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl"
            ]
        else:
            return False, f"Unknown special tool: {tool_name}"
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        
        if proc.returncode == 0:
            return True, stdout.decode()
        else:
            return False, stderr.decode()
    
    except Exception as e:
        return False, str(e)


# ============= API 端点 =============

@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy", "service": "kali-scanner"}


@app.post("/execute", response_model=ExecuteResponse)
async def execute_command(request: ExecuteRequest):
    """执行命令"""
    logger.info(f"Executing command: {request.command} {' '.join(request.args)}")
    
    start_time = datetime.now()
    
    try:
        # 构建环境变量
        env = os.environ.copy()
        if request.env:
            env.update(request.env)
        
        # 执行命令
        proc = await asyncio.create_subprocess_exec(
            request.command,
            *request.args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=request.cwd,
            env=env
        )
        
        # 等待执行完成
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=request.timeout
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ExecuteResponse(
            success=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout.decode('utf-8', errors='replace'),
            stderr=stderr.decode('utf-8', errors='replace'),
            duration=duration
        )
    
    except asyncio.TimeoutError:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Command timeout: {request.command}")
        return ExecuteResponse(
            success=False,
            returncode=-1,
            stdout="",
            stderr="",
            duration=duration,
            error=f"Command timeout after {request.timeout}s"
        )
    
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Command execution error: {e}")
        return ExecuteResponse(
            success=False,
            returncode=-1,
            stdout="",
            stderr="",
            duration=duration,
            error=str(e)
        )


@app.post("/execute_shell", response_model=ExecuteResponse)
async def execute_shell_command(request: ShellCommandRequest):
    """执行 shell 命令（支持管道、重定向等）"""
    logger.info(f"Executing shell command: {request.command[:100]}...")
    
    start_time = datetime.now()
    
    try:
        # 构建环境变量
        env = os.environ.copy()
        if request.env:
            env.update(request.env)
        
        # 使用 shell 执行命令
        proc = await asyncio.create_subprocess_shell(
            request.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=request.cwd,
            env=env
        )
        
        # 等待执行完成
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=request.timeout
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ExecuteResponse(
            success=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout.decode('utf-8', errors='replace'),
            stderr=stderr.decode('utf-8', errors='replace'),
            duration=duration
        )
    
    except asyncio.TimeoutError:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Shell command timeout: {request.command[:100]}")
        return ExecuteResponse(
            success=False,
            returncode=-1,
            stdout="",
            stderr="",
            duration=duration,
            error=f"Command timeout after {request.timeout}s"
        )
    
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Shell command execution error: {e}")
        return ExecuteResponse(
            success=False,
            returncode=-1,
            stdout="",
            stderr="",
            duration=duration,
            error=str(e)
        )


@app.post("/install", response_model=InstallResponse)
async def install_tools(request: InstallRequest):
    """安装工具"""
    logger.info(f"Installing tools: {request.tools}")
    
    async with _install_lock:
        installed = []
        failed = []
        already_installed = []
        details_list = []
        
        # 检查已安装
        for tool in request.tools:
            if is_tool_installed(tool):
                already_installed.append(tool)
        
        # 需要安装的工具
        to_install = [t for t in request.tools if t not in already_installed]
        
        if not to_install:
            return InstallResponse(
                success=True,
                installed=[],
                failed=[],
                already_installed=already_installed,
                details="All tools already installed"
            )
        
        # 收集 APT 包
        apt_packages = []
        special_tools = []
        
        for tool in to_install:
            packages = TOOL_PACKAGES.get(tool, [])
            if packages:
                apt_packages.extend(packages)
            else:
                special_tools.append(tool)
        
        # 去重
        apt_packages = list(set(apt_packages))
        
        # 安装 APT 包
        if apt_packages:
            success, output = await install_apt_packages(apt_packages, request.update_cache)
            details_list.append(f"APT install: {output[:500]}")
            
            if success:
                for tool in to_install:
                    if TOOL_PACKAGES.get(tool):
                        _tool_cache.pop(tool, None)
                        if is_tool_installed(tool):
                            installed.append(tool)
                        else:
                            failed.append(tool)
            else:
                failed.extend([t for t in to_install if TOOL_PACKAGES.get(t)])
        
        # 安装特殊工具
        for tool in special_tools:
            success, output = await install_special_tool(tool)
            details_list.append(f"{tool}: {output[:200]}")
            
            _tool_cache.pop(tool, None)
            if success and is_tool_installed(tool):
                installed.append(tool)
            else:
                failed.append(tool)
        
        return InstallResponse(
            success=len(failed) == 0,
            installed=installed,
            failed=failed,
            already_installed=already_installed,
            details="\n".join(details_list)
        )


@app.get("/tools", response_model=List[ToolInfo])
async def list_tools(filter: Optional[str] = None):
    """列出工具状态"""
    tools = []
    
    # 检查所有已知工具
    tool_list = list(TOOL_PACKAGES.keys())
    if filter:
        tool_list = [t for t in tool_list if filter.lower() in t.lower()]
    
    for tool_name in tool_list:
        installed = is_tool_installed(tool_name)
        version = get_tool_version(tool_name) if installed else None
        path = shutil.which(tool_name) if installed else None
        
        tools.append(ToolInfo(
            name=tool_name,
            installed=installed,
            version=version,
            path=path
        ))
    
    return tools


@app.get("/tools/{tool_name}", response_model=ToolInfo)
async def get_tool_info(tool_name: str):
    """获取单个工具信息"""
    installed = is_tool_installed(tool_name)
    version = get_tool_version(tool_name) if installed else None
    path = shutil.which(tool_name) if installed else None
    
    return ToolInfo(
        name=tool_name,
        installed=installed,
        version=version,
        path=path
    )


# ============= Nuclei 模板 =============

# 常见的 Nuclei 模板目录
NUCLEI_TEMPLATES_DIRS = [
    Path("/root/nuclei-templates"),
    Path.home() / "nuclei-templates",
    Path("/opt/nuclei-templates"),
    Path("/usr/share/nuclei-templates"),
]

# 模板分类映射（基于目录名）
TEMPLATE_CATEGORY_MAP = {
    "http": "HTTP 漏洞",
    "network": "网络协议",
    "dns": "DNS 检测",
    "ssl": "SSL/TLS",
    "file": "文件检测",
    "headless": "无头浏览器",
    "websocket": "WebSocket",
    "whois": "WHOIS",
    "code": "代码审计",
    "cloud": "云安全",
    "javascript": "JavaScript",
    "misconfiguration": "错误配置",
    "exposures": "信息泄露",
    "cves": "CVE 漏洞",
    "cnvd": "CNVD 漏洞",
    "cnnvd": "CNNVD 漏洞",
    "default-logins": "默认凭据",
    "Exposed-Panels": "暴露面板",
    "file/keys": "密钥泄露",
    "takeovers": "子域接管",
    "token-spray": "Token 检测",
    "helpers": "辅助模板",
    "workflow": "工作流",
}

# 模板严重级别关键字到标签的映射
SEVERITY_KEYWORDS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _find_nuclei_templates_dir() -> Optional[Path]:
    """查找 Nuclei 模板目录"""
    for d in NUCLEI_TEMPLATES_DIRS:
        if d.is_dir() and any(d.iterdir()):
            return d
    # 尝试从 nuclei 命令获取
    try:
        import subprocess
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split("\n"):
            if "templates" in line.lower() and "/" in line:
                # 提取路径
                parts = line.split()
                for part in parts:
                    p = Path(part.strip())
                    if p.is_dir():
                        return p
    except Exception:
        pass
    return None


class NucleiTemplateInfo(BaseModel):
    """Nuclei 模板信息"""
    id: str
    name: str
    path: str
    category: str
    severity: str
    file_size: int
    tags: List[str] = []


class NucleiTemplateList(BaseModel):
    """Nuclei 模板列表"""
    total: int
    items: List[NucleiTemplateInfo]
    templates_dir: str


@app.get("/nuclei-templates", response_model=NucleiTemplateList)
async def list_nuclei_templates(
    category: Optional[str] = Query(None, description="模板分类过滤"),
    severity: Optional[str] = Query(None, description="严重级别过滤"),
    search: Optional[str] = Query(None, description="搜索关键字"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """列出 Kali 容器中的 Nuclei 模板"""
    templates_dir = _find_nuclei_templates_dir()
    
    if not templates_dir or not templates_dir.is_dir():
        return NucleiTemplateList(total=0, items=[], templates_dir="")
    
    # 收集所有 YAML 模板文件
    all_templates: List[NucleiTemplateInfo] = []
    
    for yaml_file in templates_dir.rglob("*.yaml"):
        try:
            rel_path = yaml_file.relative_to(templates_dir)
            parts = list(rel_path.parts)
            
            # 确定分类
            cat = parts[0] if parts else "other"
            mapped_category = TEMPLATE_CATEGORY_MAP.get(cat, cat)
            
            # 从文件名提取 ID
            template_id = yaml_file.stem
            
            # 从文件路径提取标签
            tags = []
            if len(parts) > 1:
                # 子目录名作为标签
                tags.extend(parts[:-1])
            
            # 快速读取文件头部提取元数据
            name = template_id
            severity_val = "info"
            
            try:
                with open(yaml_file, 'r', errors='ignore') as f:
                    # 只读取前 30 行以提高性能
                    for i, line in enumerate(f):
                        if i >= 30:
                            break
                        line = line.strip()
                        if line.startswith('name:'):
                            raw_name = line[5:].strip().strip('"').strip("'")
                            if raw_name:
                                name = raw_name
                        elif line.startswith('severity:'):
                            raw_sev = line[9:].strip().strip('"').strip("'").lower()
                            if raw_sev in SEVERITY_KEYWORDS:
                                severity_val = raw_sev
                        elif line.startswith('tags:'):
                            raw_tags = line[5:].strip()
                            for t in raw_tags.split(','):
                                t = t.strip().strip('"').strip("'")
                                if t and t not in tags:
                                    tags.append(t)
            except Exception:
                pass
            
            # 过滤
            if category and category.lower() not in mapped_category.lower() and category.lower() != cat.lower():
                continue
            if severity and severity.lower() != severity_val:
                continue
            if search:
                search_lower = search.lower()
                if (search_lower not in name.lower() 
                    and search_lower not in template_id.lower()
                    and not any(search_lower in t.lower() for t in tags)):
                    continue
            
            all_templates.append(NucleiTemplateInfo(
                id=template_id,
                name=name,
                path=str(rel_path),
                category=mapped_category,
                severity=severity_val,
                file_size=yaml_file.stat().st_size,
                tags=tags[:10],  # 限制标签数量
            ))
        except Exception as e:
            logger.debug(f"Skip template {yaml_file}: {e}")
            continue
    
    # 排序：按分类 + 名称
    all_templates.sort(key=lambda t: (t.category, t.name))
    
    total = len(all_templates)
    items = all_templates[skip:skip + limit]
    
    return NucleiTemplateList(
        total=total,
        items=items,
        templates_dir=str(templates_dir)
    )


@app.get("/nuclei-templates/stats")
async def get_nuclei_templates_stats():
    """获取 Nuclei 模板统计信息"""
    templates_dir = _find_nuclei_templates_dir()
    
    if not templates_dir or not templates_dir.is_dir():
        return {"total": 0, "categories": {}, "severities": {}, "templates_dir": ""}
    
    categories: Dict[str, int] = {}
    severities: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    
    for yaml_file in templates_dir.rglob("*.yaml"):
        total += 1
        rel_path = yaml_file.relative_to(templates_dir)
        parts = list(rel_path.parts)
        cat = parts[0] if parts else "other"
        mapped = TEMPLATE_CATEGORY_MAP.get(cat, cat)
        categories[mapped] = categories.get(mapped, 0) + 1
        
        # 快速读取严重级别
        try:
            with open(yaml_file, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= 20:
                        break
                    if line.strip().startswith('severity:'):
                        sev = line.strip().split(':', 1)[1].strip().strip('"').strip("'").lower()
                        if sev in severities:
                            severities[sev] += 1
                        break
        except Exception:
            pass
    
    return {
        "total": total,
        "categories": categories,
        "severities": severities,
        "templates_dir": str(templates_dir),
    }


@app.get("/nuclei-templates/content")
async def get_nuclei_template_content(
    path: str = Query(..., description="模板相对路径")
):
    """读取 Nuclei 模板文件内容"""
    templates_dir = _find_nuclei_templates_dir()
    
    if not templates_dir:
        raise HTTPException(status_code=404, detail="Nuclei 模板目录不存在")
    
    # 安全检查：防止路径遍历
    template_path = (templates_dir / path).resolve()
    if not str(template_path).startswith(str(templates_dir.resolve())):
        raise HTTPException(status_code=403, detail="非法路径")
    
    if not template_path.is_file():
        raise HTTPException(status_code=404, detail="模板文件不存在")
    
    try:
        content = template_path.read_text(errors='replace')
        return {"content": content, "path": path, "size": template_path.stat().st_size}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读取文件失败: {str(e)}")


# ============= 启动服务 =============

if __name__ == "__main__":
    logger.info("Starting Kali Scanner Service...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8888,
        log_level="info"
    )
