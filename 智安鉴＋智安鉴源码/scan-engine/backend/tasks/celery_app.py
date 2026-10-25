"""Celery application configuration"""
import asyncio
from celery import Celery
from celery.signals import worker_ready
from loguru import logger

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "vulnscanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["tasks.scan_tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.scan_timeout,
    worker_prefetch_multiplier=1,
    worker_concurrency=settings.max_concurrent_scans,
)


@worker_ready.connect
def on_worker_ready(**kwargs):
    """Worker 启动后初始化安全工具"""
    logger.info("Celery worker ready, checking security tools...")
    
    try:
        from llm.tool_installer import initialize_tools_if_needed
        
        # 创建新的事件循环来运行异步初始化
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(initialize_tools_if_needed())
            logger.info("Security tools initialization completed")
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"Failed to initialize security tools: {e}")

