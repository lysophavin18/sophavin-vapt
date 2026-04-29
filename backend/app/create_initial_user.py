import asyncio
import sys
from pathlib import Path

from sqlalchemy import select

# Support direct execution: `python app/create_initial_user.py`
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models.models import User, UserRole


DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_EMAIL = "admin@example.com"
DEFAULT_ADMIN_PASSWORD = "ChangeMe123!"


async def create_initial_user() -> None:
    """Create default admin user if it does not already exist."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == DEFAULT_ADMIN_USERNAME))
        existing_user = result.scalar_one_or_none()

        if existing_user:
            print("Admin user already exists.")
            return

        admin_user = User(
            email=DEFAULT_ADMIN_EMAIL,
            username=DEFAULT_ADMIN_USERNAME,
            hashed_password=hash_password(DEFAULT_ADMIN_PASSWORD),
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True,
            full_name="Admin User",
        )
        db.add(admin_user)
        await db.commit()
        print(f"Admin user '{DEFAULT_ADMIN_USERNAME}' created successfully.")


if __name__ == "__main__":
    asyncio.run(create_initial_user())
