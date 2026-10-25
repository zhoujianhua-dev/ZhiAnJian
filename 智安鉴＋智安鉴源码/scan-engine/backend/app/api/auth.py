"""Authentication API endpoints"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_password_manager, get_jwt_manager
from app.models.database import User, UserRole
from app.schemas.auth import (
    UserRegister, UserLogin, UserResponse, UserUpdate,
    TokenResponse, AuthResponse
)

router = APIRouter(prefix="/auth", tags=["auth"])


async def get_current_user(
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db)
) -> User:
    """获取当前用户（依赖）"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid token"
        )
    
    token = authorization.replace("Bearer ", "")
    jwt_manager = get_jwt_manager()
    payload = jwt_manager.verify_token(token, token_type='access')
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    user_id = payload.get('sub')
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    """获取当前管理员用户（依赖）"""
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return user


@router.post("/register", response_model=AuthResponse)
async def register(
    req: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """用户注册"""
    # 验证密码一致性
    if req.password != req.password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match"
        )
    
    # 检查用户名是否已存在
    result = await db.execute(
        select(User).where(User.username == req.username)
    )
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # 检查邮箱是否已存在
    result = await db.execute(
        select(User).where(User.email == req.email)
    )
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # 创建用户
    password_manager = get_password_manager()
    user = User(
        id=str(uuid.uuid4()),
        username=req.username,
        email=req.email,
        password_hash=password_manager.hash_password(req.password),
        role=UserRole.USER,
        is_active=True
    )
    
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    # 生成 tokens
    jwt_manager = get_jwt_manager()
    access_token = jwt_manager.create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role.value
    )
    refresh_token = jwt_manager.create_refresh_token(user_id=user.id)
    
    return AuthResponse(
        user=UserResponse.from_orm(user),
        token=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=jwt_manager.access_token_expire * 60
        )
    )


@router.post("/login", response_model=AuthResponse)
async def login(
    req: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """用户登录"""
    # 查询用户
    result = await db.execute(
        select(User).where(User.username == req.username)
    )
    user = result.scalars().first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # 验证密码
    password_manager = get_password_manager()
    if not password_manager.verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # 更新最后登录时间
    user.last_login_at = datetime.utcnow()
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    # 生成 tokens
    jwt_manager = get_jwt_manager()
    access_token = jwt_manager.create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role.value
    )
    refresh_token = jwt_manager.create_refresh_token(user_id=user.id)
    
    return AuthResponse(
        user=UserResponse.from_orm(user),
        token=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=jwt_manager.access_token_expire * 60
        )
    )


@router.get("/profile", response_model=UserResponse)
async def get_profile(
    current_user: User = Depends(get_current_user)
):
    """获取当前用户信息"""
    return UserResponse.from_orm(current_user)


@router.patch("/profile", response_model=UserResponse)
async def update_profile(
    req: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """更新当前用户信息"""
    if req.username:
        # 检查新用户名是否已被占用
        result = await db.execute(
            select(User).where(
                User.username == req.username,
                User.id != current_user.id
            )
        )
        if result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        current_user.username = req.username
    
    if req.email:
        # 检查新邮箱是否已被占用
        result = await db.execute(
            select(User).where(
                User.email == req.email,
                User.id != current_user.id
            )
        )
        if result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        current_user.email = req.email
    
    if req.password:
        password_manager = get_password_manager()
        current_user.password_hash = password_manager.hash_password(req.password)
    
    current_user.updated_at = datetime.utcnow()
    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)
    
    return UserResponse.from_orm(current_user)


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user)
):
    """用户登出（前端清理 token）"""
    return {"message": "Logged out successfully"}
