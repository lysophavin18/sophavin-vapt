"""
Noovastack-VAPT Batch Scan API Endpoints
Multi-target batch scanning with optimization strategies
"""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
import structlog

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.models import (
    User, Target, Scan, BatchScan as BatchScanModel, BatchScanTarget,
    RecurringSchedule as RecurringScheduleModel, ScanType, ScanStatus,
    TargetType, ApprovalStatus, UserRole, BatchScheduleStrategy as BatchStrategyEnum
)
from app.schemas.schemas import (
    BatchScanCreate, BatchScanResponse, BatchScanListResponse,
    BatchScanTargetResponse, RecurringScheduleCreate, RecurringScheduleResponse,
    BatchScheduleStrategy
)
from app.services.target_validator import TargetValidator
from app.tasks.scan_tasks import execute_batch_scan

logger = structlog.get_logger()
router = APIRouter()


@router.post("/", response_model=BatchScanResponse, status_code=201)
async def create_batch_scan(
    batch_request: BatchScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new batch scan for multiple targets.
    
    Supports 5 scheduling strategies:
    - SEQUENTIAL: Scan one target at a time
    - PARALLEL: Scan all targets simultaneously (up to max_concurrent)
    - STAGGERED: Start new scan every N minutes
    - RESOURCE_AWARE: Dynamic scheduling based on system load
    - TOOL_OPTIMIZED: Run same tool across all targets before next tool
    """
    logger.info("Batch scan creation requested", 
                user_id=current_user.id, 
                targets=len(batch_request.targets))
    
    validator = TargetValidator()
    batch_id = str(uuid4())
    
    # Create batch scan record
    batch = BatchScanModel(
        batch_id=batch_id,
        user_id=current_user.id,
        name=batch_request.name,
        description=batch_request.description,
        scan_type=batch_request.scan_type,
        schedule_strategy=BatchStrategyEnum(batch_request.schedule_strategy.value),
        max_concurrent=batch_request.max_concurrent,
        stagger_minutes=batch_request.stagger_minutes,
        priority=batch_request.priority,
        scheduled_at=batch_request.scheduled_at,
        status='pending',
        total_targets=len(batch_request.targets),
        completed_targets=0,
        failed_targets=0
    )
    db.add(batch)
    await db.flush()
    
    # Process each target
    batch_targets = []
    for i, target_req in enumerate(batch_request.targets):
        # Validate target
        target_info = validator.validate(target_req.target)
        if not target_info['valid']:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid target '{target_req.target}': {target_info['error']}"
            )
        
        # Check if target exists
        existing_target = await db.execute(
            select(Target).where(Target.value == target_info['normalized'])
        )
        target = existing_target.scalar_one_or_none()
        
        if not target:
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
                    detail=f"External target '{target.value}' requires admin approval"
                )
            target.approval_status = ApprovalStatus.APPROVED
            target.approved_by = current_user.id
            target.approved_at = datetime.utcnow()
        
        # Create batch target entry
        batch_target = BatchScanTarget(
            batch_scan_id=batch.id,
            target_id=target.id,
            execution_order=i + 1,
            status='pending'
        )
        db.add(batch_target)
        batch_targets.append(batch_target)
    
    await db.commit()
    await db.refresh(batch)
    
    # Queue batch scan execution
    if batch_request.scheduled_at and batch_request.scheduled_at > datetime.utcnow():
        # Schedule for later
        eta = batch_request.scheduled_at
        execute_batch_scan.apply_async(args=[batch_id], eta=eta)
        batch.status = 'scheduled'
    else:
        # Execute immediately
        execute_batch_scan.delay(batch_id)
        batch.status = 'queued'
    
    await db.commit()
    
    logger.info("Batch scan created", batch_id=batch_id, targets=len(batch_targets))
    
    return BatchScanResponse(
        id=batch.id,
        batch_id=batch.batch_id,
        name=batch.name,
        description=batch.description,
        scan_type=batch.scan_type,
        schedule_strategy=BatchScheduleStrategy(batch.schedule_strategy.value),
        status=batch.status,
        total_targets=batch.total_targets,
        completed_targets=batch.completed_targets,
        failed_targets=batch.failed_targets,
        total_findings=batch.total_findings,
        critical_count=batch.critical_count,
        high_count=batch.high_count,
        medium_count=batch.medium_count,
        low_count=batch.low_count,
        info_count=batch.info_count,
        max_concurrent=batch.max_concurrent,
        stagger_minutes=batch.stagger_minutes,
        scheduled_at=batch.scheduled_at,
        started_at=batch.started_at,
        completed_at=batch.completed_at,
        created_at=batch.created_at
    )


@router.get("/", response_model=BatchScanListResponse)
async def list_batch_scans(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List batch scans for the current user"""
    
    query = select(BatchScanModel).where(BatchScanModel.user_id == current_user.id)
    
    if status:
        query = query.where(BatchScanModel.status == status)
    
    # Get total count
    count_query = select(func.count()).select_from(BatchScanModel).where(
        BatchScanModel.user_id == current_user.id
    )
    if status:
        count_query = count_query.where(BatchScanModel.status == status)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Get paginated results
    query = query.order_by(BatchScanModel.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)
    
    result = await db.execute(query)
    batches = result.scalars().all()
    
    batch_responses = [
        BatchScanResponse(
            id=b.id,
            batch_id=b.batch_id,
            name=b.name,
            description=b.description,
            scan_type=b.scan_type,
            schedule_strategy=BatchScheduleStrategy(b.schedule_strategy.value),
            status=b.status,
            total_targets=b.total_targets,
            completed_targets=b.completed_targets,
            failed_targets=b.failed_targets,
            total_findings=b.total_findings,
            critical_count=b.critical_count,
            high_count=b.high_count,
            medium_count=b.medium_count,
            low_count=b.low_count,
            info_count=b.info_count,
            max_concurrent=b.max_concurrent,
            stagger_minutes=b.stagger_minutes,
            scheduled_at=b.scheduled_at,
            started_at=b.started_at,
            completed_at=b.completed_at,
            created_at=b.created_at
        ) for b in batches
    ]
    
    return BatchScanListResponse(
        batches=batch_responses,
        total=total,
        page=page,
        per_page=per_page
    )


@router.get("/{batch_id}", response_model=BatchScanResponse)
async def get_batch_scan(
    batch_id: str,
    include_targets: bool = Query(default=True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get batch scan details with target status"""
    
    query = select(BatchScanModel).where(BatchScanModel.batch_id == batch_id)
    
    if include_targets:
        query = query.options(selectinload(BatchScanModel.targets))
    
    result = await db.execute(query)
    batch = result.scalar_one_or_none()
    
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")
    
    if batch.user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    targets_response = None
    if include_targets and batch.targets:
        targets_response = []
        for t in batch.targets:
            # Get target value
            target_result = await db.execute(
                select(Target).where(Target.id == t.target_id)
            )
            target = target_result.scalar_one_or_none()
            
            targets_response.append(BatchScanTargetResponse(
                id=t.id,
                target_value=target.value if target else "Unknown",
                execution_order=t.execution_order,
                status=t.status,
                started_at=t.started_at,
                completed_at=t.completed_at,
                findings_count=t.findings_count,
                error_message=t.error_message
            ))
    
    return BatchScanResponse(
        id=batch.id,
        batch_id=batch.batch_id,
        name=batch.name,
        description=batch.description,
        scan_type=batch.scan_type,
        schedule_strategy=BatchScheduleStrategy(batch.schedule_strategy.value),
        status=batch.status,
        total_targets=batch.total_targets,
        completed_targets=batch.completed_targets,
        failed_targets=batch.failed_targets,
        total_findings=batch.total_findings,
        critical_count=batch.critical_count,
        high_count=batch.high_count,
        medium_count=batch.medium_count,
        low_count=batch.low_count,
        info_count=batch.info_count,
        max_concurrent=batch.max_concurrent,
        stagger_minutes=batch.stagger_minutes,
        scheduled_at=batch.scheduled_at,
        started_at=batch.started_at,
        completed_at=batch.completed_at,
        created_at=batch.created_at,
        targets=targets_response
    )


@router.delete("/{batch_id}")
async def cancel_batch_scan(
    batch_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Cancel a pending or running batch scan"""
    
    result = await db.execute(
        select(BatchScanModel).where(BatchScanModel.batch_id == batch_id)
    )
    batch = result.scalar_one_or_none()
    
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")
    
    if batch.user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if batch.status in ['completed', 'failed', 'cancelled']:
        raise HTTPException(status_code=400, detail=f"Cannot cancel batch in {batch.status} state")
    
    batch.status = 'cancelled'
    batch.completed_at = datetime.utcnow()
    await db.commit()
    
    logger.info("Batch scan cancelled", batch_id=batch_id, user_id=current_user.id)
    
    return {"status": "cancelled", "batch_id": batch_id}


@router.get("/strategies/info")
async def get_strategy_info():
    """Get information about available scheduling strategies"""
    return {
        "strategies": [
            {
                "name": "sequential",
                "title": "Sequential",
                "description": "Scan one target at a time, in order. Best for limited resources.",
                "recommended_for": "Low-resource environments, avoiding detection"
            },
            {
                "name": "parallel",
                "title": "Parallel",
                "description": "Scan all targets simultaneously up to max_concurrent limit.",
                "recommended_for": "Fast completion when resources allow"
            },
            {
                "name": "staggered",
                "title": "Staggered",
                "description": "Start a new scan every N minutes. Spreads load over time.",
                "recommended_for": "Avoiding rate limits, scheduled windows"
            },
            {
                "name": "resource_aware",
                "title": "Resource-Aware",
                "description": "Dynamically adjust concurrency based on system load.",
                "recommended_for": "Optimal resource utilization (recommended)"
            },
            {
                "name": "tool_optimized",
                "title": "Tool-Optimized",
                "description": "Run the same tool across all targets before moving to next tool.",
                "recommended_for": "Tool-level deduplication, shared connections"
            }
        ]
    }


# =============================================================================
# RECURRING SCHEDULES
# =============================================================================
@router.post("/schedules/", response_model=RecurringScheduleResponse, status_code=201)
async def create_recurring_schedule(
    schedule_request: RecurringScheduleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a recurring scan schedule"""
    
    schedule_id = str(uuid4())
    
    schedule = RecurringScheduleModel(
        schedule_id=schedule_id,
        user_id=current_user.id,
        name=schedule_request.name,
        description=schedule_request.description,
        cron_expression=schedule_request.cron_expression,
        timezone=schedule_request.timezone,
        scan_type=schedule_request.scan_type,
        target_ids=schedule_request.target_ids,
        is_active=True,
        run_count=0
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    
    logger.info("Recurring schedule created", 
                schedule_id=schedule_id, 
                cron=schedule_request.cron_expression)
    
    return RecurringScheduleResponse(
        id=schedule.id,
        schedule_id=schedule.schedule_id,
        name=schedule.name,
        description=schedule.description,
        cron_expression=schedule.cron_expression,
        timezone=schedule.timezone,
        scan_type=schedule.scan_type,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        run_count=schedule.run_count,
        created_at=schedule.created_at
    )


@router.get("/schedules/", response_model=List[RecurringScheduleResponse])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List recurring schedules for the current user"""
    
    result = await db.execute(
        select(RecurringScheduleModel)
        .where(RecurringScheduleModel.user_id == current_user.id)
        .order_by(RecurringScheduleModel.created_at.desc())
    )
    schedules = result.scalars().all()
    
    return [
        RecurringScheduleResponse(
            id=s.id,
            schedule_id=s.schedule_id,
            name=s.name,
            description=s.description,
            cron_expression=s.cron_expression,
            timezone=s.timezone,
            scan_type=s.scan_type,
            is_active=s.is_active,
            last_run=s.last_run,
            next_run=s.next_run,
            run_count=s.run_count,
            created_at=s.created_at
        ) for s in schedules
    ]


@router.patch("/schedules/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Toggle a recurring schedule on/off"""
    
    result = await db.execute(
        select(RecurringScheduleModel)
        .where(RecurringScheduleModel.schedule_id == schedule_id)
    )
    schedule = result.scalar_one_or_none()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if schedule.user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    schedule.is_active = not schedule.is_active
    await db.commit()
    
    return {"schedule_id": schedule_id, "is_active": schedule.is_active}


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a recurring schedule"""
    
    result = await db.execute(
        select(RecurringScheduleModel)
        .where(RecurringScheduleModel.schedule_id == schedule_id)
    )
    schedule = result.scalar_one_or_none()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if schedule.user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    await db.delete(schedule)
    await db.commit()
    
    logger.info("Schedule deleted", schedule_id=schedule_id, user_id=current_user.id)
    
    return {"status": "deleted", "schedule_id": schedule_id}
