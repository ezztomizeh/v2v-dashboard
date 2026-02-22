import asyncio
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.append(str(Path(__file__).parent.parent))

from config.settings import settings
from config.database import connect_to_mongodb, close_mongodb_connection, db
from core.security import get_password_hash


async def create_default_admin():
    print("🔧 Checking for existing users...")
    
    await connect_to_mongodb()
    
    user_count = await db.database.users.count_documents({})
    
    if user_count > 0:
        print(f"✅ Found {user_count} existing users. Skipping admin creation.")
        await close_mongodb_connection()
        return
    
    print("📝 No users found. Creating default admin...")
    
    admin_permissions = [
        "vehicle:create", "vehicle:read", "vehicle:update", "vehicle:delete",
        "certificate:issue", "certificate:revoke", "certificate:verify",
        "certificate:mark_stolen", "certificate:check_revocation",
        "users:manage", "audit:view", "api_keys:manage"
    ]
    
    admin_user = {
        "username": settings.default_admin_username,
        "email": settings.default_admin_email,
        "full_name": settings.default_admin_full_name,
        "password_hash": get_password_hash(settings.default_admin_password),
        "role": "admin",
        "permissions": admin_permissions,
        "department": "IT",
        "phone": "",
        "is_active": True,
        "failed_login_attempts": 0,
        "locked_until": None,
        "password_changed_at": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "created_by": None,  # System created
        "updated_at": datetime.now(timezone.utc)
    }
    
    result = await db.database.users.insert_one(admin_user)
    
    print(f"✅ Default admin created with ID: {result.inserted_id}")
    print(f"   Username: {settings.default_admin_username}")
    print(f"   Password: {settings.default_admin_password}")
    print("\n⚠️  IMPORTANT: Change this password on first login!")
    
    await close_mongodb_connection()


if __name__ == "__main__":
    asyncio.run(create_default_admin())