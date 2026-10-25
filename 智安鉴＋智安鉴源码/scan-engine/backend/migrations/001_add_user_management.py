"""
Migration script to create admin user and handle existing data
Run this after deploying the new code with user management system
"""
import asyncio
import uuid
from sqlalchemy import text
from app.core.database import AsyncSessionLocal, pg_engine
from app.core.security import get_password_manager
from app.models.database import Base, User, UserRole


async def migrate():
    """Execute migration"""
    
    # Create all tables first
    async with pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create default admin user if it doesn't exist
    async with AsyncSessionLocal() as session:
        password_manager = get_password_manager()
        
        # Check if admin already exists
        from sqlalchemy import select
        result = await session.execute(
            select(User).where(User.role == UserRole.ADMIN)
        )
        
        if not result.scalars().first():
            admin = User(
                id=str(uuid.uuid4()),
                username="admin",
                email="admin@hackscan.local",
                password_hash=password_manager.hash_password("admin123456"),  # Change this in production!
                role=UserRole.ADMIN,
                is_active=True
            )
            session.add(admin)
            await session.commit()
            print("✅ Created default admin user:")
            print("   Username: admin")
            print("   Password: admin123456")
            print("   ⚠️  IMPORTANT: Change the default password immediately!")
        else:
            print("✅ Admin user already exists")
        
        # Handle existing scan_tasks without user_id
        # This assigns them to the admin user
        await session.execute(
            text("""
                UPDATE scan_tasks 
                SET user_id = (SELECT id FROM users WHERE role = 'admin' LIMIT 1)
                WHERE user_id IS NULL
            """)
        )
        await session.commit()
        print("✅ Assigned existing scans to admin user")
        
        # Handle existing tools/configs without user_id (keep them as system-wide)
        print("✅ Existing tools and configurations remain as system-wide")


if __name__ == "__main__":
    asyncio.run(migrate())
    print("\n✅ Migration completed successfully!")
