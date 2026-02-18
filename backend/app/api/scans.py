"""
Noovastack-VAPT Scan API Endpoints
Core scanning functionality
"""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload
import structlog
import redis.asyncio as redis

from app.core.database import get_db
from app.core.config import settings
from app.core.security import get_current_user, require_role
from app.models.models import (
    User, Scan, Target, Finding, ToolResult,
    ScanStatus, ScanType, TargetType, ApprovalStatus, UserRole
)
from app.schemas.schemas import (
    ScanCreate, ScanResponse, ScanListResponse, ScanProgressResponse,
    FindingResponse, PaginatedResponse, BaseResponse
)
from app.services.target_validator import TargetValidator
from app.tasks.scan_tasks import execute_scan

logger = structlog.get_logger()
router = APIRouter()


async def get_redis():
    """Get Redis connection"""
    return await redis.from_url(settings.REDIS_URL)


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new vulnerability scan.
    
    - Validates target format (IP/domain/URL)
    - Checks rate limits
    - Requires approval for external targets
    - Queues scan for execution
    """
    logger.info("Scan creation requested", user_id=current_user.id, target=scan_request.target)
    
    # Rate limiting check
    redis_client = await get_redis()
    rate_key = f"scan_rate:{current_user.id}"
    scan_count = await redis_client.get(rate_key)
    
    if scan_count and int(scan_count) >= settings.RATE_LIMIT_SCANS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {settings.RATE_LIMIT_SCANS} scans per hour."
        )
    
    # Validate and classify target
    validator = TargetValidator()
    target_info = validator.validate(scan_request.target)
    
    if not target_info['valid']:
        raise HTTPException(status_code=400, detail=target_info['error'])
    
    # Check if target exists
    existing_target = await db.execute(
        select(Target).where(Target.value == target_info['normalized'])
    )
    target = existing_target.scalar_one_or_none()
    
    if not target:
        # Create new target
        target = Target(
            value=target_info['normalized'],
            target_type=TargetType(target_info['type']),
            is_external=target_info['is_external']
        )
        db.add(target)
        await db.flush()
    
    # Check approval for external targets
    if target.is_external and target.approval_status != ApprovalStatus.APPROVED:
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=403,
                detail="External targets require admin approval before scanning"
            )
        # Admin can auto-approve
        target.approval_status = ApprovalStatus.APPROVED
        target.approved_by = current_user.id
        target.approved_at = datetime.utcnow()
    
    # Create scan record
    scan_id = str(uuid4())
    scan = Scan(
        scan_id=scan_id,
        user_id=current_user.id,
        target_id=target.id,
        scan_type=scan_request.scan_type,
        priority=scan_request.priority,
        status=ScanStatus.PENDING,
        scheduled_at=scan_request.scheduled_at
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Update rate limit counter
    await redis_client.incr(rate_key)
    await redis_client.expire(rate_key, settings.RATE_LIMIT_WINDOW)
    
    # Queue scan execution
    execute_scan.delay(scan_id)
    
    # Update status to queued
    scan.status = ScanStatus.QUEUED
    await db.commit()
    
    logger.info("Scan created and queued", scan_id=scan_id, target=target.value)
    
    # Build response
    return ScanResponse(
        id=scan.id,
        scan_id=scan.scan_id,
        target=target,
        scan_type=scan.scan_type,
        status=scan.status,
        priority=scan.priority,
        progress=scan.progress,
        current_phase=scan.current_phase,
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        report_path=scan.report_path,
        error_message=scan.error_message
    )


@router.get("/", response_model=PaginatedResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[ScanStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List user's scans with pagination and filtering"""
    
    # Build query
    query = select(Scan).where(Scan.user_id == current_user.id)
    
    if status:
        query = query.where(Scan.status == status)
    
    # Get total count
    count_query = select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    if status:
        count_query = count_query.where(Scan.status == status)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Paginate
    query = query.options(selectinload(Scan.target))
    query = query.order_by(Scan.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    # Transform to list response
    items = [
        ScanListResponse(
            id=s.id,
            scan_id=s.scan_id,
            target_value=s.target.value,
            scan_type=s.scan_type,
            status=s.status,
            progress=s.progress,
            total_findings=s.total_findings,
            critical_count=s.critical_count,
            high_count=s.high_count,
            created_at=s.created_at,
            completed_at=s.completed_at
        )
        for s in scans
    ]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed scan information"""
    
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.target))
        .where(
            and_(
                Scan.scan_id == scan_id,
                Scan.user_id == current_user.id
            )
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanResponse(
        id=scan.id,
        scan_id=scan.scan_id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        priority=scan.priority,
        progress=scan.progress,
        current_phase=scan.current_phase,
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        report_path=scan.report_path,
        error_message=scan.error_message
    )


@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get real-time scan progress"""
    
    result = await db.execute(
        select(Scan).where(
            and_(
                Scan.scan_id == scan_id,
                Scan.user_id == current_user.id
            )
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    elapsed = 0
    if scan.started_at:
        end_time = scan.completed_at or datetime.utcnow()
        elapsed = int((end_time - scan.started_at).total_seconds())
    
    return ScanProgressResponse(
        scan_id=scan.scan_id,
        status=scan.status,
        progress=scan.progress,
        current_phase=scan.current_phase,
        findings_so_far=scan.total_findings,
        elapsed_seconds=elapsed
    )


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all findings for a scan"""
    
    # Verify scan ownership
    scan_result = await db.execute(
        select(Scan).where(
            and_(
                Scan.scan_id == scan_id,
                Scan.user_id == current_user.id
            )
        )
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get findings
    query = select(Finding).where(Finding.scan_id == scan.id)
    
    if severity:
        query = query.where(Finding.severity == severity)
    
    query = query.order_by(Finding.severity, Finding.discovered_at)
    
    result = await db.execute(query)
    findings = result.scalars().all()
    
    return [
        FindingResponse(
            id=f.id,
            title=f.title,
            description=f.description,
            severity=f.severity,
            cve_id=f.cve_id,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            affected_component=f.affected_component,
            affected_port=f.affected_port,
            affected_service=f.affected_service,
            affected_url=f.affected_url,
            evidence=f.evidence,
            solution=f.solution,
            references=f.references,
            tool_name=f.tool_name,
            discovered_at=f.discovered_at
        )
        for f in findings
    ]


@router.post("/{scan_id}/cancel", response_model=BaseResponse)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Cancel a running or queued scan"""
    
    result = await db.execute(
        select(Scan).where(
            and_(
                Scan.scan_id == scan_id,
                Scan.user_id == current_user.id
            )
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status not in [ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan in {scan.status} status"
        )
    
    # Update status
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    await db.commit()
    
    # TODO: Actually stop running tasks via Celery revoke
    
    logger.info("Scan cancelled", scan_id=scan_id, user_id=current_user.id)
    
    return BaseResponse(success=True, message="Scan cancelled successfully")


@router.delete("/{scan_id}", response_model=BaseResponse)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a scan and its findings"""
    
    result = await db.execute(
        select(Scan).where(
            and_(
                Scan.scan_id == scan_id,
                Scan.user_id == current_user.id
            )
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a running scan. Cancel it first."
        )
    
    await db.delete(scan)
    await db.commit()
    
    logger.info("Scan deleted", scan_id=scan_id, user_id=current_user.id)
    
    return BaseResponse(success=True, message="Scan deleted successfully")
