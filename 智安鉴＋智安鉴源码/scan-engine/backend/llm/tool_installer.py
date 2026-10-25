"""Security tool installer - auto-install tools when needed"""
import asyncio
import shutil
import os
import re
from typing import Optional, Dict, List
from loguru import logger

# APT 源是否已配置的标记
_apt_mirror_configured = False

# 工具名称到 apt 包名的映射
TOOL_PACKAGES: Dict[str, List[str]] = {
    "nmap": ["nmap"],
    "curl": ["curl"],
    "gobuster": ["gobuster"],
    "dirb": ["dirb"],
    "nuclei": [],  # 需要特殊安装
    "whatweb": ["whatweb"],
    "sslscan": ["sslscan"],
    "sqlmap": ["sqlmap"],
    "nikto": ["nikto"],
    "wfuzz": ["wfuzz"],
    "ffuf": [],  # 需要特殊安装
    "httpx": [],  # 需要特殊安装
    "subfinder": [],  # 需要特殊安装
    "masscan": ["masscan"],
    "hydra": ["hydra"],
    "john": ["john"],
    "hashcat": ["hashcat"],
    "netcat": ["netcat-openbsd"],
    "nc": ["netcat-openbsd"],
    "socat": ["socat"],
    "tcpdump": ["tcpdump"],
    "wireshark": ["tshark"],
    "tshark": ["tshark"],
    "dnsutils": ["dnsutils"],
    "dig": ["dnsutils"],
    "nslookup": ["dnsutils"],
    "whois": ["whois"],
    "traceroute": ["traceroute"],
    "arp-scan": ["arp-scan"],
    "nbtscan": ["nbtscan"],
    "enum4linux": ["enum4linux"],
    "smbclient": ["smbclient"],
    "snmpwalk": ["snmp"],
    "onesixtyone": ["onesixtyone"],
    "wordlists": ["wordlists", "seclists"],
}

# 主流安全工具列表（首次启动安装）
ESSENTIAL_TOOLS = [
    "nmap",
    "curl", 
    "dirb",
    "nikto",
    "sqlmap",
    "whatweb",
    "sslscan",
    "masscan",
    "hydra",
    "netcat",
    "socat",
    "dnsutils",
    "whois",
    "traceroute",
    "wordlists",
]

# 安装状态缓存
_installed_cache: Dict[str, bool] = {}
# 每个事件循环使用独立的锁，避免跨事件循环问题
_install_locks: Dict[int, asyncio.Lock] = {}


def _get_install_lock() -> asyncio.Lock:
    """获取当前事件循环的安装锁（每个事件循环独立）"""
    try:
        loop = asyncio.get_running_loop()
        loop_id = id(loop)
    except RuntimeError:
        # 没有运行中的事件循环，返回一个临时锁
        return asyncio.Lock()
    
    if loop_id not in _install_locks:
        _install_locks[loop_id] = asyncio.Lock()
    return _install_locks[loop_id]


def is_tool_available(tool_name: str) -> bool:
    """检查工具是否已安装"""
    if tool_name in _installed_cache:
        return _installed_cache[tool_name]
    
    result = shutil.which(tool_name) is not None
    _installed_cache[tool_name] = result
    return result


async def _configure_apt_mirror(log_callback=None) -> bool:
    """配置 APT 源为 BFSU 镜像（北京外国语大学）"""
    global _apt_mirror_configured
    
    if _apt_mirror_configured:
        return True
    
    async def log(msg: str):
        logger.info(msg)
        if log_callback:
            await log_callback("info", f"📦 {msg}")
    
    sources_list = "/etc/apt/sources.list"
    bfsu_mirror = "mirrors.bfsu.edu.cn"
    
    try:
        # 检查是否已经是 BFSU 源
        if os.path.exists(sources_list):
            with open(sources_list, 'r') as f:
                content = f.read()
                if bfsu_mirror in content:
                    _apt_mirror_configured = True
                    return True
        
        await log("正在配置 BFSU 镜像源...")
        
        # 检测系统版本
        os_release = {}
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_release[key] = value.strip('"')
        
        distro_id = os_release.get("ID", "debian").lower()
        version_codename = os_release.get("VERSION_CODENAME", "bookworm")
        
        # 生成新的 sources.list
        if distro_id == "ubuntu":
            new_sources = f"""# BFSU Mirror
deb https://{bfsu_mirror}/ubuntu/ {version_codename} main restricted universe multiverse
deb https://{bfsu_mirror}/ubuntu/ {version_codename}-updates main restricted universe multiverse
deb https://{bfsu_mirror}/ubuntu/ {version_codename}-security main restricted universe multiverse
"""
        else:
            # Debian / Kali 等
            if distro_id == "kali":
                new_sources = f"""# BFSU Mirror
deb https://{bfsu_mirror}/kali kali-rolling main contrib non-free non-free-firmware
"""
            else:
                new_sources = f"""# BFSU Mirror
deb https://{bfsu_mirror}/debian/ {version_codename} main contrib non-free non-free-firmware
deb https://{bfsu_mirror}/debian/ {version_codename}-updates main contrib non-free non-free-firmware
deb https://{bfsu_mirror}/debian-security/ {version_codename}-security main contrib non-free non-free-firmware
"""
        
        # 备份原文件
        if os.path.exists(sources_list):
            backup_path = f"{sources_list}.bak"
            if not os.path.exists(backup_path):
                shutil.copy(sources_list, backup_path)
        
        # 写入新配置
        with open(sources_list, 'w') as f:
            f.write(new_sources)
        
        # 更新 apt 缓存
        await log("正在更新软件包列表...")
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        
        proc = await asyncio.create_subprocess_exec(
            "apt-get", "update",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        await asyncio.wait_for(proc.communicate(), timeout=120)
        
        if proc.returncode == 0:
            await log("✅ BFSU 镜像源配置成功")
            _apt_mirror_configured = True
            return True
        else:
            await log("⚠️ apt update 返回非零，但继续尝试安装")
            _apt_mirror_configured = True
            return True
            
    except Exception as e:
        logger.error(f"配置镜像源失败: {e}")
        # 即使失败也标记为已配置，避免重复尝试
        _apt_mirror_configured = True
        return False


async def install_apt_packages(packages: List[str], log_callback=None) -> bool:
    """通过 apt 安装包"""
    if not packages:
        return True
    
    async def log(msg: str):
        logger.info(msg)
        if log_callback:
            await log_callback("info", f"📦 {msg}")
    
    try:
        # 首次安装前配置镜像源
        await _configure_apt_mirror(log_callback)
        
        await log(f"安装软件包: {', '.join(packages)}")
        
        # 设置非交互模式
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        
        # 执行 apt-get install
        cmd = ["apt-get", "install", "-y", "--no-install-recommends"] + packages
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        
        if proc.returncode == 0:
            await log(f"✅ 安装成功: {', '.join(packages)}")
            return True
        else:
            error_msg = stderr.decode('utf-8', errors='replace')
            await log(f"❌ 安装失败: {error_msg[:200]}")
            return False
            
    except asyncio.TimeoutError:
        await log(f"❌ 安装超时: {', '.join(packages)}")
        return False
    except Exception as e:
        logger.error(f"Installation error: {e}")
        return False


async def install_special_tool(tool_name: str, log_callback=None) -> bool:
    """安装需要特殊处理的工具"""
    async def log(msg: str):
        logger.info(msg)
        if log_callback:
            await log_callback("info", f"📦 {msg}")
    
    try:
        if tool_name == "nuclei":
            await log("安装 Nuclei...")
            # 获取最新版本号并下载
            # GitHub release 文件名格式: nuclei_{version}_linux_amd64.zip
            cmd = [
                "sh", "-c",
                """
                VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
                ARCH=$(uname -m)
                case $ARCH in
                    x86_64) ARCH="amd64" ;;
                    aarch64) ARCH="arm64" ;;
                    armv*) ARCH="arm" ;;
                esac
                OS=$(uname -s | tr '[:upper:]' '[:lower:]')
                URL="https://github.com/projectdiscovery/nuclei/releases/download/${VERSION}/nuclei_${VERSION#v}_${OS}_${ARCH}.zip"
                echo "Downloading from: $URL"
                curl -sSL "$URL" -o /tmp/nuclei.zip && \
                unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
                chmod +x /usr/local/bin/nuclei && \
                rm /tmp/nuclei.zip
                """
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            logger.debug(f"Nuclei install stdout: {stdout.decode()}")
            logger.debug(f"Nuclei install stderr: {stderr.decode()}")
            
            if proc.returncode == 0:
                # 更新 nuclei 模板
                proc2 = await asyncio.create_subprocess_exec(
                    "nuclei", "-update-templates",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc2.communicate()
                await log("✅ Nuclei 安装成功")
                return True
            else:
                await log(f"❌ Nuclei 安装失败: {stderr.decode()}")
                return False
                
        elif tool_name == "ffuf":
            await log("安装 ffuf...")
            # ffuf 的文件名格式: ffuf_{version}_{os}_{arch}.tar.gz
            cmd = [
                "sh", "-c",
                """
                VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
                ARCH=$(uname -m)
                case $ARCH in
                    x86_64) ARCH="amd64" ;;
                    aarch64) ARCH="arm64" ;;
                    armv*) ARCH="arm" ;;
                esac
                OS=$(uname -s | tr '[:upper:]' '[:lower:]')
                URL="https://github.com/ffuf/ffuf/releases/download/${VERSION}/ffuf_${VERSION#v}_${OS}_${ARCH}.tar.gz"
                echo "Downloading from: $URL"
                curl -sSL "$URL" | tar -xzf - -C /usr/local/bin/ ffuf && \
                chmod +x /usr/local/bin/ffuf
                """
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
            
        elif tool_name == "httpx":
            await log("安装 httpx...")
            cmd = [
                "sh", "-c",
                """
                VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
                ARCH=$(uname -m)
                case $ARCH in
                    x86_64) ARCH="amd64" ;;
                    aarch64) ARCH="arm64" ;;
                    armv*) ARCH="arm" ;;
                esac
                OS=$(uname -s | tr '[:upper:]' '[:lower:]')
                URL="https://github.com/projectdiscovery/httpx/releases/download/${VERSION}/httpx_${VERSION#v}_${OS}_${ARCH}.zip"
                echo "Downloading from: $URL"
                curl -sSL "$URL" -o /tmp/httpx.zip && \
                unzip -o /tmp/httpx.zip -d /usr/local/bin/ && \
                chmod +x /usr/local/bin/httpx && \
                rm /tmp/httpx.zip
                """
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
            
        elif tool_name == "subfinder":
            await log("安装 subfinder...")
            cmd = [
                "sh", "-c",
                """
                VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
                ARCH=$(uname -m)
                case $ARCH in
                    x86_64) ARCH="amd64" ;;
                    aarch64) ARCH="arm64" ;;
                    armv*) ARCH="arm" ;;
                esac
                OS=$(uname -s | tr '[:upper:]' '[:lower:]')
                URL="https://github.com/projectdiscovery/subfinder/releases/download/${VERSION}/subfinder_${VERSION#v}_${OS}_${ARCH}.zip"
                echo "Downloading from: $URL"
                curl -sSL "$URL" -o /tmp/subfinder.zip && \
                unzip -o /tmp/subfinder.zip -d /usr/local/bin/ && \
                chmod +x /usr/local/bin/subfinder && \
                rm /tmp/subfinder.zip
                """
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
            
        elif tool_name == "gobuster":
            # gobuster 可能不在默认 apt 仓库，尝试下载
            await log("安装 gobuster...")
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/OJ/gobuster/releases/latest/download/gobuster-linux-amd64.7z -o /tmp/gobuster.7z && "
                "7z x /tmp/gobuster.7z -o/tmp/gobuster && "
                "mv /tmp/gobuster/gobuster-linux-amd64/gobuster /usr/local/bin/ && "
                "chmod +x /usr/local/bin/gobuster && "
                "rm -rf /tmp/gobuster*"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
            
        return False
        
    except Exception as e:
        logger.error(f"Special tool installation error: {e}")
        return False


async def ensure_tool_available(tool_name: str, log_callback=None) -> bool:
    """确保工具可用，如果不可用则自动安装"""
    async with _get_install_lock():
        # 检查是否已安装
        if is_tool_available(tool_name):
            return True
        
        async def log(msg: str):
            logger.info(msg)
            if log_callback:
                await log_callback("info", f"📦 {msg}")
        
        await log(f"工具 {tool_name} 未安装，正在自动安装...")
        
        # 获取对应的 apt 包
        packages = TOOL_PACKAGES.get(tool_name, [])
        
        if packages:
            # 使用 apt 安装
            success = await install_apt_packages(packages, log_callback)
        else:
            # 需要特殊安装
            success = await install_special_tool(tool_name, log_callback)
        
        if success:
            # 清除缓存并重新检查
            _installed_cache.pop(tool_name, None)
            if is_tool_available(tool_name):
                await log(f"✅ 工具 {tool_name} 安装成功")
                return True
        
        await log(f"❌ 工具 {tool_name} 安装失败")
        return False


async def install_essential_tools(log_callback=None) -> Dict[str, bool]:
    """安装所有基础安全工具"""
    results = {}
    
    async def log(msg: str):
        logger.info(msg)
        if log_callback:
            await log_callback("info", f"📦 {msg}")
    
    await log("🚀 开始安装基础安全工具...")
    
    # 首先更新 apt 缓存
    try:
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        
        await log("更新软件包列表...")
        proc = await asyncio.create_subprocess_exec(
            "apt-get", "update",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        await asyncio.wait_for(proc.communicate(), timeout=120)
    except Exception as e:
        logger.warning(f"apt-get update failed: {e}")
    
    # 收集所有需要安装的 apt 包
    all_packages = []
    special_tools = []
    
    for tool in ESSENTIAL_TOOLS:
        if not is_tool_available(tool):
            packages = TOOL_PACKAGES.get(tool, [])
            if packages:
                all_packages.extend(packages)
            else:
                special_tools.append(tool)
    
    # 去重
    all_packages = list(set(all_packages))
    
    # 批量安装 apt 包
    if all_packages:
        await log(f"批量安装: {', '.join(all_packages)}")
        success = await install_apt_packages(all_packages, log_callback)
        for tool in ESSENTIAL_TOOLS:
            packages = TOOL_PACKAGES.get(tool, [])
            if packages and set(packages).issubset(set(all_packages)):
                _installed_cache.pop(tool, None)
                results[tool] = is_tool_available(tool) if success else False
    
    # 安装特殊工具
    for tool in special_tools:
        success = await install_special_tool(tool, log_callback)
        _installed_cache.pop(tool, None)
        results[tool] = is_tool_available(tool) if success else False
    
    # 统计结果
    installed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    
    await log(f"🎉 安装完成: {installed} 成功, {failed} 失败")
    
    return results


# 初始化标记文件
INIT_MARKER = "/app/data/.tools_initialized"


def is_initialized() -> bool:
    """检查是否已完成首次初始化"""
    return os.path.exists(INIT_MARKER)


def mark_initialized():
    """标记初始化完成"""
    os.makedirs(os.path.dirname(INIT_MARKER), exist_ok=True)
    with open(INIT_MARKER, "w") as f:
        f.write("1")


async def initialize_tools_if_needed(log_callback=None):
    """首次启动时安装基础工具"""
    if is_initialized():
        logger.info("Tools already initialized, skipping...")
        return
    
    logger.info("First startup detected, installing essential security tools...")
    
    try:
        await install_essential_tools(log_callback)
        mark_initialized()
    except Exception as e:
        logger.error(f"Tool initialization failed: {e}")
