#!/usr/bin/env python3
"""清理过期的临时扫描文件"""
import os
import time
from pathlib import Path
import sys

# 添加父目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import get_settings
from loguru import logger


def cleanup_old_scans(max_age_hours: int = 24):
    """
    清理超过指定时间的临时扫描文件
    
    Args:
        max_age_hours: 文件保留的最大小时数
    """
    settings = get_settings()
    scan_temp_dir = Path(settings.scan_temp_dir)
    
    if not scan_temp_dir.exists():
        logger.info(f"临时目录不存在: {scan_temp_dir}")
        return
    
    current_time = time.time()
    max_age_seconds = max_age_hours * 3600
    deleted_count = 0
    deleted_size = 0
    
    logger.info(f"开始清理 {scan_temp_dir}，保留时间: {max_age_hours} 小时")
    
    # 遍历所有文件
    for file_path in scan_temp_dir.rglob("*"):
        if not file_path.is_file():
            continue
        
        try:
            # 检查文件年龄
            file_age = current_time - file_path.stat().st_mtime
            
            if file_age > max_age_seconds:
                file_size = file_path.stat().st_size
                file_path.unlink()
                deleted_count += 1
                deleted_size += file_size
                logger.debug(f"删除: {file_path} (年龄: {file_age/3600:.1f}小时)")
        
        except Exception as e:
            logger.error(f"删除文件失败 {file_path}: {e}")
    
    # 删除空目录
    for dir_path in sorted(scan_temp_dir.rglob("*"), reverse=True):
        if dir_path.is_dir() and not any(dir_path.iterdir()):
            try:
                dir_path.rmdir()
                logger.debug(f"删除空目录: {dir_path}")
            except Exception as e:
                logger.error(f"删除目录失败 {dir_path}: {e}")
    
    logger.info(
        f"清理完成: 删除 {deleted_count} 个文件, "
        f"释放 {deleted_size / 1024 / 1024:.2f} MB"
    )


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="清理过期的扫描临时文件")
    parser.add_argument(
        "--max-age",
        type=int,
        default=24,
        help="文件保留的最大小时数 (默认: 24)"
    )
    
    args = parser.parse_args()
    cleanup_old_scans(max_age_hours=args.max_age)
