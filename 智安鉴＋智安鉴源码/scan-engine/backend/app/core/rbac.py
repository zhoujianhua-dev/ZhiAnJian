"""RBAC (Role-Based Access Control) utilities"""
from enum import Enum
from typing import Callable, Optional, List
from fastapi import Depends, HTTPException, status
from app.models.database import User, UserRole


class Permission(str, Enum):
    """权限定义"""
    # 用户权限
    VIEW_OWN_SCANS = "view_own_scans"
    CREATE_SCAN = "create_scan"
    MANAGE_OWN_CONFIG = "manage_own_config"
    
    # 管理员权限
    VIEW_ALL_SCANS = "view_all_scans"
    MANAGE_ALL_SCANS = "manage_all_scans"
    MANAGE_USERS = "manage_users"
    MANAGE_SYSTEM_CONFIG = "manage_system_config"
    VIEW_SYSTEM_TOOLS = "view_system_tools"


# 权限映射
ROLE_PERMISSIONS = {
    UserRole.USER: {
        Permission.VIEW_OWN_SCANS,
        Permission.CREATE_SCAN,
        Permission.MANAGE_OWN_CONFIG,
    },
    UserRole.ADMIN: {
        Permission.VIEW_OWN_SCANS,
        Permission.CREATE_SCAN,
        Permission.MANAGE_OWN_CONFIG,
        Permission.VIEW_ALL_SCANS,
        Permission.MANAGE_ALL_SCANS,
        Permission.MANAGE_USERS,
        Permission.MANAGE_SYSTEM_CONFIG,
        Permission.VIEW_SYSTEM_TOOLS,
    },
}


def require_permission(*permissions: Permission):
    """权限检查装饰器"""
    async def check_permission(user: User):
        user_permissions = ROLE_PERMISSIONS.get(user.role, set())
        
        for permission in permissions:
            if permission not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission}"
                )
        
        return user
    
    return check_permission


def check_resource_ownership(
    resource_owner_id: Optional[str],
    current_user: User
) -> bool:
    """检查资源所有权"""
    if current_user.role == UserRole.ADMIN:
        return True
    
    return resource_owner_id == current_user.id


def check_scan_access(current_user: User, scan_owner_id: str) -> bool:
    """检查扫描记录访问权限"""
    if current_user.role == UserRole.ADMIN:
        return True
    
    return scan_owner_id == current_user.id
