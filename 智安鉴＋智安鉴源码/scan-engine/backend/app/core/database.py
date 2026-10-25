from contextlib import asynccontextmanager
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis

from app.core.config import get_settings

settings = get_settings()

# PostgreSQL async engine (for FastAPI context)
pg_engine = create_async_engine(
    settings.postgres_url,
    echo=settings.debug,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    pg_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


def create_celery_session():
    """Create a new session factory for Celery tasks (new event loop)"""
    engine = create_async_engine(
        settings.postgres_url,
        echo=settings.debug,
        pool_size=5,
        max_overflow=10,
    )
    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    return engine, session_factory

# MongoDB client
mongo_client: AsyncIOMotorClient | None = None

# Redis client
redis_client: redis.Redis | None = None


async def init_databases():
    """Initialize database connections"""
    global mongo_client, redis_client
    
    mongo_client = AsyncIOMotorClient(settings.mongodb_url)
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    
    # Ensure PostgreSQL enum types are up-to-date before creating tables
    async with pg_engine.begin() as conn:
        # Add 'PAUSED' to scanstatus enum if it exists but doesn't have this value
        await conn.execute(
            text("""
                DO $$
                BEGIN
                    -- Check if enum type exists
                    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scanstatus') THEN
                        -- Check if 'PAUSED' value exists (uppercase to match existing values)
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_enum 
                            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'scanstatus')
                            AND enumlabel = 'PAUSED'
                        ) THEN
                            -- Add 'PAUSED' to enum
                            ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'PAUSED';
                        END IF;
                    END IF;
                END $$;
            """)
        )
        
        # Add 'SCANNER' to tool type enum, even if the enum name differs from defaults
        await conn.execute(
            text("""
                DO $$
                DECLARE
                    enum_name text;
                BEGIN
                    -- Try to detect enum name from security_tools.tool_type
                    SELECT t.typname INTO enum_name
                    FROM pg_type t
                    JOIN pg_attribute a ON a.atttypid = t.oid
                    JOIN pg_class c ON c.oid = a.attrelid
                    WHERE c.relname = 'security_tools'
                      AND a.attname = 'tool_type'
                      AND t.typtype = 'e'
                    LIMIT 1;

                    -- Fallback to default enum name
                    IF enum_name IS NULL THEN
                        enum_name := 'tooltype';
                    END IF;

                    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = enum_name) THEN
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_enum
                            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = enum_name)
                            AND enumlabel = 'SCANNER'
                        ) THEN
                            EXECUTE format('ALTER TYPE %I ADD VALUE IF NOT EXISTS %L', enum_name, 'SCANNER');
                        END IF;
                    END IF;
                END $$;
            """)
        )

        # Add SubAgent orchestration state column for existing deployments
        await conn.execute(
            text("""
                ALTER TABLE IF EXISTS scan_tasks
                ADD COLUMN IF NOT EXISTS sub_agents JSON DEFAULT '[]'::json;
            """)
        )

        # Add per-agent LLM activation flags for existing deployments
        await conn.execute(
            text("""
                ALTER TABLE IF EXISTS llm_configs
                ADD COLUMN IF NOT EXISTS active_for_main_agent BOOLEAN DEFAULT FALSE;
            """)
        )
        await conn.execute(
            text("""
                ALTER TABLE IF EXISTS llm_configs
                ADD COLUMN IF NOT EXISTS active_for_sub_agent BOOLEAN DEFAULT FALSE;
            """)
        )
        await conn.execute(
            text("""
                DO $$
                BEGIN
                    IF to_regclass('public.llm_configs') IS NOT NULL THEN
                        UPDATE llm_configs
                        SET active_for_main_agent = TRUE,
                            active_for_sub_agent = TRUE,
                            is_active = FALSE
                        WHERE is_active = TRUE
                          AND active_for_main_agent = FALSE
                          AND active_for_sub_agent = FALSE;

                        UPDATE llm_configs
                        SET is_active = FALSE
                        WHERE is_active = TRUE;
                    END IF;
                END $$;
            """)
        )
    
    # Create PostgreSQL tables
    from app.models.database import Base
    async with pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create default admin user if it doesn't exist
    from app.models.database import User, UserRole
    from app.core.security import get_password_manager
    from sqlalchemy import select
    from loguru import logger
    
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(User).where(User.role == UserRole.ADMIN)
            )
            
            if not result.scalars().first():
                import uuid
                password_manager = get_password_manager()
                admin = User(
                    id=str(uuid.uuid4()),
                    username="admin",
                    email="admin@hackscan.local",
                    password_hash=password_manager.hash_password("admin123456"),
                    role=UserRole.ADMIN,
                    is_active=True
                )
                session.add(admin)
                await session.commit()
                logger.info("✅ Created default admin user: admin/admin123456")
            else:
                logger.info("✅ Admin user already exists")
    except Exception as e:
        logger.error(f"⚠️ Failed to create/verify admin user: {e}")
    
    logger.info("✅ Database initialization complete")


async def close_databases():
    """Close database connections"""
    global mongo_client, redis_client
    
    if mongo_client:
        mongo_client.close()
    if redis_client:
        await redis_client.close()
    await pg_engine.dispose()


async def get_db() -> AsyncSession:
    """FastAPI dependency for database session"""
    async with AsyncSessionLocal() as session:
        yield session


def get_mongo_db():
    """Get MongoDB database instance"""
    return mongo_client[settings.mongodb_db]


def get_redis():
    """Get Redis client"""
    return redis_client
