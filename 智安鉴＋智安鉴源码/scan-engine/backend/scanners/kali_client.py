"""Kali Scanner Client - Backend 与 Kali 容器的通信客户端"""
import asyncio
import os
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass

import httpx
from loguru import logger


@dataclass
class ExecuteResult:
    """命令执行结果"""
    success: bool
    returncode: int
    stdout: str
    stderr: str
    duration: float
    error: Optional[str] = None
    
    @property
    def output(self) -> str:
        """兼容性属性：返回 stdout"""
        return self.stdout


@dataclass
class ToolInfo:
    """工具信息"""
    name: str
    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None


class KaliClient:
    """Kali Scanner 容器客户端"""
    
    def __init__(self, base_url: Optional[str] = None):
        """初始化客户端
        
        Args:
            base_url: Kali API 地址，默认从环境变量 KALI_SCANNER_URL 读取
        """
        self.base_url = base_url or os.getenv("KALI_SCANNER_URL", "http://kali_scanner:8888")
        self.timeout = httpx.Timeout(600.0, connect=10.0)  # 默认 10 分钟超时
        
    async def _request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        timeout: Optional[float] = None
    ) -> Dict:
        """发送 HTTP 请求"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            custom_timeout = httpx.Timeout(timeout) if timeout else self.timeout
            
            async with httpx.AsyncClient(timeout=custom_timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params
                )
                response.raise_for_status()
                return response.json()
        
        except httpx.TimeoutException as e:
            logger.error(f"Kali API timeout: {url}")
            raise TimeoutError(f"Kali scanner timeout: {e}")
        
        except httpx.HTTPStatusError as e:
            logger.error(f"Kali API error {e.response.status_code}: {url}")
            raise RuntimeError(f"Kali scanner API error: {e.response.status_code}")
        
        except Exception as e:
            logger.error(f"Kali API connection error: {e}")
            raise RuntimeError(f"Cannot connect to Kali scanner: {e}")
    
    async def health_check(self) -> bool:
        """健康检查"""
        try:
            response = await self._request("GET", "/health", timeout=5.0)
            return response.get("status") == "healthy"
        except:
            return False
    
    async def execute(
        self,
        command: str,
        args: Optional[List[str]] = None,
        timeout: int = 300,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecuteResult:
        """执行命令
        
        Args:
            command: 命令名称
            args: 命令参数列表
            timeout: 超时时间（秒）
            cwd: 工作目录
            env: 环境变量
            
        Returns:
            ExecuteResult: 执行结果
        """
        payload = {
            "command": command,
            "args": args or [],
            "timeout": timeout,
        }
        
        if cwd:
            payload["cwd"] = cwd
        if env:
            payload["env"] = env
        
        logger.info(f"Executing in Kali: {command} {' '.join(args or [])}")
        
        response = await self._request(
            "POST",
            "/execute",
            json_data=payload,
            timeout=timeout + 10  # 留出额外时间
        )
        
        return ExecuteResult(
            success=response["success"],
            returncode=response["returncode"],
            stdout=response["stdout"],
            stderr=response["stderr"],
            duration=response["duration"],
            error=response.get("error")
        )
    
    async def execute_shell_command(
        self,
        command: str,
        timeout: int = 300,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecuteResult:
        """执行 shell 命令（支持管道、重定向等）
        
        Args:
            command: 完整的 shell 命令字符串
            timeout: 超时时间（秒）
            cwd: 工作目录
            env: 环境变量
            
        Returns:
            ExecuteResult: 执行结果
        """
        payload = {
            "command": command,
            "timeout": timeout,
        }
        
        if cwd:
            payload["cwd"] = cwd
        if env:
            payload["env"] = env
        
        logger.info(f"Executing shell command in Kali: {command[:100]}...")
        
        response = await self._request(
            "POST",
            "/execute_shell",
            json_data=payload,
            timeout=timeout + 10
        )
        
        return ExecuteResult(
            success=response["success"],
            returncode=response["returncode"],
            stdout=response["stdout"],
            stderr=response["stderr"],
            duration=response["duration"],
            error=response.get("error")
        )
    
    async def install_tools(
        self,
        tools: List[str],
        update_cache: bool = False
    ) -> Tuple[List[str], List[str], List[str]]:
        """安装工具
        
        Args:
            tools: 工具名称列表
            update_cache: 是否先更新 apt 缓存
            
        Returns:
            Tuple[installed, failed, already_installed]: 安装结果
        """
        logger.info(f"Installing tools in Kali: {tools}")
        
        payload = {
            "tools": tools,
            "update_cache": update_cache
        }
        
        response = await self._request(
            "POST",
            "/install",
            json_data=payload,
            timeout=900  # 安装可能需要更长时间
        )
        
        return (
            response["installed"],
            response["failed"],
            response["already_installed"]
        )
    
    async def get_tool_info(self, tool_name: str) -> ToolInfo:
        """获取单个工具信息
        
        Args:
            tool_name: 工具名称
            
        Returns:
            ToolInfo: 工具信息
        """
        response = await self._request("GET", f"/tools/{tool_name}")
        
        return ToolInfo(
            name=response["name"],
            installed=response["installed"],
            version=response.get("version"),
            path=response.get("path")
        )
    
    async def list_tools(self, filter: Optional[str] = None) -> List[ToolInfo]:
        """列出所有工具
        
        Args:
            filter: 过滤关键词
            
        Returns:
            List[ToolInfo]: 工具列表
        """
        params = {"filter": filter} if filter else None
        response = await self._request("GET", "/tools", params=params)
        
        return [
            ToolInfo(
                name=item["name"],
                installed=item["installed"],
                version=item.get("version"),
                path=item.get("path")
            )
            for item in response
        ]
    
    async def ensure_tools_installed(
        self,
        tools: List[str],
        log_callback=None
    ) -> bool:
        """确保工具已安装，如果没有则自动安装
        
        Args:
            tools: 工具列表
            log_callback: 日志回调函数
            
        Returns:
            bool: 是否所有工具都安装成功
        """
        if not tools:
            return True
        
        async def log(msg: str):
            logger.info(msg)
            if log_callback:
                await log_callback("info", f"🔧 {msg}")
        
        # 检查哪些工具需要安装
        to_install = []
        for tool in tools:
            try:
                info = await self.get_tool_info(tool)
                if not info.installed:
                    to_install.append(tool)
                else:
                    await log(f"✅ {tool} 已安装 ({info.version or 'unknown version'})")
            except:
                to_install.append(tool)
        
        if not to_install:
            return True
        
        # 安装缺失的工具
        await log(f"需要安装: {', '.join(to_install)}")
        
        try:
            installed, failed, already = await self.install_tools(to_install, update_cache=True)
            
            if installed:
                await log(f"✅ 安装成功: {', '.join(installed)}")
            
            if already:
                await log(f"ℹ️ 已存在: {', '.join(already)}")
            
            if failed:
                await log(f"❌ 安装失败: {', '.join(failed)}")
                return False
            
            return True
        
        except Exception as e:
            await log(f"❌ 安装过程出错: {str(e)}")
            return False


# 全局单例
_kali_client: Optional[KaliClient] = None


def get_kali_client() -> KaliClient:
    """获取 Kali 客户端单例"""
    global _kali_client
    if _kali_client is None:
        _kali_client = KaliClient()
    return _kali_client
