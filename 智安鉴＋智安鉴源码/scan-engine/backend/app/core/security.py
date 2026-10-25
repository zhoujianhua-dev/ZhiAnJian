"""Security utilities for authentication"""
from datetime import datetime, timedelta
from typing import Optional
import jwt
import bcrypt
from functools import lru_cache

from app.core.config import get_settings

settings = get_settings()


class PasswordManager:
    """密码管理工具"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """哈希密码"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """验证密码"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False


class JWTManager:
    """JWT Token 管理工具"""
    
    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire = settings.jwt_access_token_expire_minutes
        self.refresh_token_expire = settings.jwt_refresh_token_expire_days
    
    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        """创建 access token"""
        expires = datetime.utcnow() + timedelta(minutes=self.access_token_expire)
        payload = {
            'sub': user_id,
            'username': username,
            'role': role,
            'exp': expires,
            'iat': datetime.utcnow(),
            'type': 'access'
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user_id: str) -> str:
        """创建 refresh token"""
        expires = datetime.utcnow() + timedelta(days=self.refresh_token_expire)
        payload = {
            'sub': user_id,
            'exp': expires,
            'iat': datetime.utcnow(),
            'type': 'refresh'
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str, token_type: str = 'access') -> Optional[dict]:
        """验证 token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # 检查 token 类型
            if payload.get('type') != token_type:
                return None
            
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def get_token_expiry_seconds(self, token: str) -> Optional[int]:
        """获取 token 剩余有效期（秒）"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            exp = payload.get('exp')
            if exp:
                remaining = exp - datetime.utcnow().timestamp()
                return max(0, int(remaining))
            return None
        except jwt.InvalidTokenError:
            return None


@lru_cache(maxsize=1)
def get_jwt_manager() -> JWTManager:
    """获取 JWT 管理器单例"""
    return JWTManager()


@lru_cache(maxsize=1)
def get_password_manager() -> PasswordManager:
    """获取密码管理器单例"""
    return PasswordManager()
