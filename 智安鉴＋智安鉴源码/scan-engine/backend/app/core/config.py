"""Application configuration"""
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # API Settings
    app_name: str = "Hack Scan"
    debug: bool = False
    api_prefix: str = "/api/v1"
    
    # Database
    postgres_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/vulnscanner"
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db: str = "vulnscanner_raw"
    redis_url: str = "redis://localhost:6379/0"

    # Kali Scanner
    kali_scanner_url: str = "http://kali_scanner:8888"
    
    # Scanning Configuration
    max_concurrent_scans: int = 5
    scan_timeout: int = 3600  # 1 hour
    rate_limit_per_target: int = 10  # requests per second
    scan_temp_dir: str = "/tmp/shelling_scans"  # 扫描结果临时目录
    tools_dir: str = "/app/data/tools"  # 知识库存储目录
    
    # Security & Authentication
    secret_key: str = "change-me-in-production"
    allowed_origins: list[str] = ["http://localhost:3000", "http://0.0.0.0:3000", "*"]
    
    # JWT Configuration
    jwt_secret_key: str = "your-super-secret-jwt-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30  # 30 minutes
    jwt_refresh_token_expire_days: int = 7  # 7 days
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
