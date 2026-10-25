"""Admin user management API endpoints"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_password_manager
from app.models.database import User, UserRole
from app.schemas.auth import (
    UserResponse, UserListResponse, UserAdminUpdate
)
from app.api.auth import get_current_admin

router = APIRouter(prefix="/admin/users", tags=["admin"])


@router.get("", response_model=UserListResponse)
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    role: str | None = Query(None),
    is_active: bool | None = Query(None),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """获取用户列表（管理员）"""
    filters = []
    
    if role:
        try:
            role_enum = UserRole(role)
            filters.append(User.role == role_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role: {role}"
            )
    
    if is_active is not None:
        filters.append(User.is_active == is_active)
    
    # 获取总数
    count_result = await db.execute(
        select(func.count(User.id)).where(*filters) if filters else select(func.count(User.id))
    )
    total = count_result.scalar() or 0
    
    # 获取分页数据
    query = select(User).order_by(User.created_at.desc()).offset(skip).limit(limit)
    if filters:
        query = query.where(*filters)
    
    result = await db.execute(query)
    users = result.scalars().all()
    
    return UserListResponse(
        total=total,
        items=[UserResponse.from_orm(user) for user in users]
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """获取用户详情（管理员）"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse.from_orm(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    req: UserAdminUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """更新用户（管理员）"""
    if user_id == admin.id and req.role and req.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot demote yourself"
        )
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # 更新字段
    if req.username:
        # 检查用户名是否已被占用
        existing = await db.execute(
            select(User).where(
                User.username == req.username,
                User.id != user_id
            )
        )
        if existing.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        user.username = req.username
    
    if req.email:
        # 检查邮箱是否已被占用
        existing = await db.execute(
            select(User).where(
                User.email == req.email,
                User.id != user_id
            )
        )
        if existing.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        user.email = req.email
    
    if req.password:
        password_manager = get_password_manager()
        user.password_hash = password_manager.hash_password(req.password)
    
    if req.role is not None:
        user.role = req.role
    
    if req.is_active is not None:
        user.is_active = req.is_active
    
    user.updated_at = datetime.utcnow()
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    return UserResponse.from_orm(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """删除用户（管理员）"""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself"
        )
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    await db.delete(user)
    await db.commit()
