"""
Dashboard API Endpoints
Aggregated statistics for the dashboard view
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
import structlog

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User, Scan, Finding, ScanStatus, Severity
from app.schemas.schemas import DashboardStats, ScanListResponse

logger = structlog.get_logger()
router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return aggregated statistics for the authenticated user's dashboard."""

    user_id = current_user.id
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=now.weekday())

    # --- Scan counts ---
    total_scans_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == user_id)
    )
    total_scans = total_scans_result.scalar() or 0

    scans_today_result = await db.execute(
        select(func.count(Scan.id)).where(
            and_(Scan.user_id == user_id, Scan.created_at >= today_start)
        )
    )
    scans_today = scans_today_result.scalar() or 0

    scans_this_week_result = await db.execute(
        select(func.count(Scan.id)).where(
            and_(Scan.user_id == user_id, Scan.created_at >= week_start)
        )
    )
    scans_this_week = scans_this_week_result.scalar() or 0

    active_scans_result = await db.execute(
        select(func.count(Scan.id)).where(
            and_(
                Scan.user_id == user_id,
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED, ScanStatus.PENDING]),
            )
        )
    )
    active_scans = active_scans_result.scalar() or 0

    # --- Findings counts (via sub-query joining through scans the user owns) ---
    user_scan_ids = select(Scan.id).where(Scan.user_id == user_id).scalar_subquery()

    def _finding_count(severity: Severity):
        return select(func.count(Finding.id)).where(
            and_(Finding.scan_id.in_(user_scan_ids), Finding.severity == severity)
        )

    total_findings_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.scan_id.in_(user_scan_ids))
    )
    total_findings = total_findings_result.scalar() or 0

    critical_result = await db.execute(_finding_count(Severity.CRITICAL))
    high_result = await db.execute(_finding_count(Severity.HIGH))
    medium_result = await db.execute(_finding_count(Severity.MEDIUM))
    low_result = await db.execute(_finding_count(Severity.LOW))
    info_result = await db.execute(_finding_count(Severity.INFO))

    # --- Recent scans (last 10, ordered by newest first) ---
    recent_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    recent_scans_orm = recent_result.scalars().all()

    # Eagerly load target values in a second pass to avoid lazy-load errors
    from sqlalchemy.orm import selectinload
    from app.models.models import Target

    target_ids = [s.target_id for s in recent_scans_orm]
    targets_result = await db.execute(
        select(Target).where(Target.id.in_(target_ids))
    )
    targets_by_id = {t.id: t for t in targets_result.scalars().all()}

    recent_scans = [
        ScanListResponse(
            id=s.id,
            scan_id=s.scan_id,
            target_value=targets_by_id[s.target_id].value if s.target_id in targets_by_id else "",
            scan_type=s.scan_type,
            status=s.status,
            progress=s.progress,
            total_findings=s.total_findings,
            critical_count=s.critical_count,
            high_count=s.high_count,
            created_at=s.created_at,
            completed_at=s.completed_at,
        )
        for s in recent_scans_orm
    ]

    return DashboardStats(
        total_scans=total_scans,
        scans_today=scans_today,
        scans_this_week=scans_this_week,
        active_scans=active_scans,
        total_findings=total_findings,
        critical_findings=critical_result.scalar() or 0,
        high_findings=high_result.scalar() or 0,
        medium_findings=medium_result.scalar() or 0,
        low_findings=low_result.scalar() or 0,
        info_findings=info_result.scalar() or 0,
        recent_scans=recent_scans,
    )
