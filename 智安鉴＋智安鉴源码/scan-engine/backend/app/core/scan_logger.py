"""Real-time scan logging using Redis"""
import json
import time
from datetime import datetime
from enum import Enum
from typing import Optional
import redis

from app.core.config import get_settings

settings = get_settings()


class LogType(str, Enum):
    INFO = "info"
    TOOL = "tool"
    OUTPUT = "output"
    LLM = "llm"
    ERROR = "error"
    SUCCESS = "success"


class ScanLogger:
    """管理扫描日志，使用 Redis 存储"""
    
    def __init__(self, scan_id: str, redis_url: str = None):
        self.scan_id = scan_id
        self.redis_url = redis_url or settings.redis_url
        self._client: Optional[redis.Redis] = None
        self._log_key = f"scan_logs:{scan_id}"
        self._max_logs = 500  # 最多保存 500 条日志
        self._expire_seconds = 3600 * 24  # 24 小时后过期
    
    @property
    def client(self) -> redis.Redis:
        if self._client is None:
            self._client = redis.from_url(self.redis_url, decode_responses=True)
        return self._client
    
    def log(self, log_type: LogType, message: str, details: str = None, tool: str = None, agent: str = None):
        """添加一条日志"""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": log_type.value,
            "message": message,
            "details": details,
            "tool": tool,
            "agent": agent,
        }
        
        # 添加到 Redis list
        self.client.rpush(self._log_key, json.dumps(entry, ensure_ascii=False))
        
        # 限制日志数量
        self.client.ltrim(self._log_key, -self._max_logs, -1)
        
        # 设置过期时间
        self.client.expire(self._log_key, self._expire_seconds)
    
    def info(self, message: str, details: str = None, agent: str = None):
        self.log(LogType.INFO, message, details, agent=agent)
    
    def tool(self, tool_name: str, message: str, output: str = None, agent: str = None):
        self.log(LogType.TOOL, message, output, tool=tool_name, agent=agent)
    
    def output(self, tool_name: str, message: str, details: str = None, agent: str = None):
        self.log(LogType.OUTPUT, message, details, tool=tool_name, agent=agent)
    
    def llm(self, message: str, response: str = None, agent: str = None):
        self.log(LogType.LLM, message, response, agent=agent)
    
    def error(self, message: str, details: str = None, agent: str = None):
        self.log(LogType.ERROR, message, details, agent=agent)
    
    def success(self, message: str, details: str = None, agent: str = None):
        self.log(LogType.SUCCESS, message, details, agent=agent)
    
    def get_logs(self, since_index: int = 0) -> tuple[list[dict], int]:
        """获取日志，返回 (logs, next_index)"""
        logs_raw = self.client.lrange(self._log_key, since_index, -1)
        logs = [json.loads(log) for log in logs_raw]
        next_index = since_index + len(logs)
        return logs, next_index
    
    def clear(self):
        """清除日志"""
        self.client.delete(self._log_key)
    
    def close(self):
        """关闭连接"""
        if self._client:
            self._client.close()
            self._client = None


def get_scan_logger(scan_id: str) -> ScanLogger:
    """获取扫描日志记录器"""
    return ScanLogger(scan_id)
