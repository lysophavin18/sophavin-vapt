"""Reports endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Scan, ScanStatus

router = APIRouter()


@router.get("/")
async def list_reports(db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    result = await db.execute(
        select(Scan).where(
            Scan.user_id == current_user.id,
            Scan.status == ScanStatus.COMPLETED,
        )
    )
    scans = result.scalars().all()
    return [{"scan_id": s.scan_id, "target": s.target.value if s.target else None, "completed_at": s.completed_at} for s in scans]


@router.get("/{scan_id}")
async def get_report(scan_id: str, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id, Scan.user_id == current_user.id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"scan_id": scan.scan_id, "status": scan.status, "report_path": scan.report_path}
