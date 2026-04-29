"""Health check endpoints"""

from fastapi import APIRouter
from app.core.database import engine

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "noovastack-vapt-backend"}
