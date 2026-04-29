"""Admin endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import require_role
from app.models.models import User, UserRole, Target, ApprovalStatus
from app.schemas.schemas import UserResponse, TargetApprovalRequest, UserRoleUpdateRequest

router = APIRouter()


@router.get("/users", response_model=list[UserResponse])
async def admin_list_users(db: AsyncSession = Depends(get_db), _=Depends(require_role(UserRole.ADMIN))):
    result = await db.execute(select(User))
    return result.scalars().all()


@router.post("/users/role")
async def update_user_role(
    body: UserRoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    result = await db.execute(select(User).where(User.id == body.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = body.role
    await db.commit()
    return {"success": True}


@router.post("/targets/approve")
async def approve_target(
    body: TargetApprovalRequest,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    result = await db.execute(select(Target).where(Target.id == body.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.approval_status = ApprovalStatus.APPROVED if body.approved else ApprovalStatus.REJECTED
    await db.commit()
    return {"success": True}
