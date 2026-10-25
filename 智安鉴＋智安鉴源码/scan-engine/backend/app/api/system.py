"""Health check and system info endpoints"""
from fastapi import APIRouter
from scanners import get_available_scanners

router = APIRouter(tags=["system"])


@router.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "ok"}


@router.get("/scanners")
async def list_scanners():
    """列出可用的扫描器"""
    available, uploaded = await get_available_scanners()
    return {
        "available_scanners": [s.value for s in available] + uploaded
    }
