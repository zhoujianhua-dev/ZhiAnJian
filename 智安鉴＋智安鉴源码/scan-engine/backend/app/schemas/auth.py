"""Authentication schemas"""
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr
from app.models.database import UserRole


# ============ User Schemas ============

class UserRegister(BaseModel):
    """用户注册"""
    username: str = Field(..., min_length=3, max_length=100, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    password_confirm: str = Field(..., min_length=8, max_length=100)

    def validate_passwords_match(self):
        if self.password != self.password_confirm:
            raise ValueError("Passwords do not match")


class UserLogin(BaseModel):
    """用户登录"""
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)


class UserResponse(BaseModel):
    """用户响应"""
    id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None

    class Config:
        from_attributes = True


class UserDetailResponse(UserResponse):
    """用户详细信息响应"""
    pass


class UserListResponse(BaseModel):
    """用户列表响应（管理员）"""
    total: int
    items: list[UserResponse]


class UserUpdate(BaseModel):
    """更新用户信息"""
    email: EmailStr | None = None
    username: str | None = Field(None, min_length=3, max_length=100, pattern="^[a-zA-Z0-9_-]+$")
    password: str | None = Field(None, min_length=8, max_length=100)


class UserAdminUpdate(UserUpdate):
    """管理员更新用户"""
    role: UserRole | None = None
    is_active: bool | None = None


# ============ Token Schemas ============

class TokenResponse(BaseModel):
    """Token 响应"""
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int  # 秒


class TokenRefresh(BaseModel):
    """Token 刷新"""
    refresh_token: str


class AuthResponse(BaseModel):
    """认证响应（登录/注册）"""
    user: UserResponse
    token: TokenResponse
