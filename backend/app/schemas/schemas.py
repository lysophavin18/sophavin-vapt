"""
Kouprey Security Pydantic Schemas
Request/Response validation models
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr, validator
import re

from app.models.models import UserRole, ScanStatus, ScanType, TargetType, Severity, ApprovalStatus


# =============================================================================
# BASE SCHEMAS
# =============================================================================
class BaseResponse(BaseModel):
    """Base response model"""
    success: bool = True
    message: str = ""


class PaginatedResponse(BaseModel):
    """Paginated response model"""
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int


# =============================================================================
# AUTH SCHEMAS
# =============================================================================
class TokenData(BaseModel):
    """JWT token payload"""
    user_id: int
    email: str
    role: UserRole


class TokenResponse(BaseModel):
    """Authentication token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginRequest(BaseModel):
    """Login request schema"""
    email: str
    password: str = Field(..., min_length=8)


class RegisterRequest(BaseModel):
    """User registration request"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_]+$')
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = Field(None, max_length=255)
    organization: Optional[str] = Field(None, max_length=255)


class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: str
    new_password: str = Field(..., min_length=8)


# =============================================================================
# USER SCHEMAS
# =============================================================================
class UserBase(BaseModel):
    """Base user schema"""
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    organization: Optional[str] = None


class UserCreate(UserBase):
    """User creation schema"""
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.USER


class UserUpdate(BaseModel):
    """User update schema"""
    full_name: Optional[str] = None
    organization: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """User response schema"""
    id: int
    role: UserRole
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


# =============================================================================
# TARGET SCHEMAS
# =============================================================================
class TargetCreate(BaseModel):
    """Target creation schema"""
    value: str = Field(..., max_length=500)
    notes: Optional[str] = None
    
    @validator('value')
    def validate_target(cls, v):
        """Validate target format (IP, domain, or URL)"""
        v = v.strip().lower()
        
        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Domain pattern
        domain_pattern = r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'
        # URL pattern
        url_pattern = r'^https?://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(/.*)?$'
        
        if re.match(ip_pattern, v):
            # Validate IP octets
            octets = v.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise ValueError('Invalid IP address')
            return v
        elif re.match(domain_pattern, v):
            return v
        elif re.match(url_pattern, v):
            return v
        else:
            raise ValueError('Target must be a valid IP address, domain, or URL')


class TargetResponse(BaseModel):
    """Target response schema"""
    id: int
    value: str
    target_type: TargetType
    is_external: bool
    approval_status: ApprovalStatus
    notes: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# =============================================================================
# SCAN SCHEMAS
# =============================================================================
class ScanCreate(BaseModel):
    """Scan creation request"""
    target: str = Field(..., description="IP address, domain, or URL to scan")
    scan_type: ScanType = Field(default=ScanType.FULL)
    priority: int = Field(default=5, ge=1, le=10)
    scheduled_at: Optional[datetime] = None
    notes: Optional[str] = None
    
    @validator('target')
    def validate_target(cls, v):
        """Validate target format"""
        v = v.strip()
        
        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Domain pattern  
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        # URL pattern
        url_pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(/.*)?$'
        
        if re.match(ip_pattern, v):
            octets = v.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise ValueError('Invalid IP address')
            return v
        elif re.match(domain_pattern, v):
            return v.lower()
        elif re.match(url_pattern, v):
            return v
        else:
            raise ValueError('Target must be a valid IP address, domain, or URL')


class ScanResponse(BaseModel):
    """Scan response schema"""
    id: int
    scan_id: str
    target: TargetResponse
    scan_type: ScanType
    status: ScanStatus
    priority: int
    progress: int
    current_phase: Optional[str] = None
    
    # Results summary
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Timing
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Report
    report_path: Optional[str] = None
    
    # Error
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Scan list item (minimal data)"""
    id: int
    scan_id: str
    target_value: str
    scan_type: ScanType
    status: ScanStatus
    progress: int
    total_findings: int
    critical_count: int
    high_count: int
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanProgressResponse(BaseModel):
    """Real-time scan progress"""
    scan_id: str
    status: ScanStatus
    progress: int
    current_phase: Optional[str]
    findings_so_far: int = 0
    elapsed_seconds: int = 0


# =============================================================================
# FINDING SCHEMAS
# =============================================================================
class FindingResponse(BaseModel):
    """Vulnerability finding response"""
    id: int
    title: str
    description: Optional[str] = None
    severity: Severity
    
    # CVE info
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    # Affected component
    affected_component: Optional[str] = None
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    affected_url: Optional[str] = None
    
    # Evidence
    evidence: Optional[str] = None
    
    # Remediation
    solution: Optional[str] = None
    references: Optional[List[str]] = None
    
    # Source
    tool_name: Optional[str] = None
    discovered_at: datetime

    class Config:
        from_attributes = True


class FindingSummary(BaseModel):
    """Finding summary for dashboard"""
    severity: Severity
    count: int


# =============================================================================
# REPORT SCHEMAS
# =============================================================================
class ReportRequest(BaseModel):
    """Report generation request"""
    scan_id: str
    format: str = Field(default="pdf", pattern=r'^(pdf|html|json)$')
    include_evidence: bool = True
    include_remediation: bool = True


class ReportResponse(BaseModel):
    """Report response"""
    scan_id: str
    report_url: str
    format: str
    generated_at: datetime
    file_size_bytes: int


# =============================================================================
# DASHBOARD SCHEMAS
# =============================================================================
class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_scans: int
    scans_today: int
    scans_this_week: int
    active_scans: int
    
    # Findings breakdown
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    
    # Recent activity
    recent_scans: List[ScanListResponse]


class SystemStatus(BaseModel):
    """System health status"""
    status: str
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    openvas_status: str
    zap_status: str
    queue_length: int
    active_workers: int


# =============================================================================
# ADMIN SCHEMAS
# =============================================================================
class TargetApprovalRequest(BaseModel):
    """Target approval request"""
    target_id: int
    approved: bool
    notes: Optional[str] = None


class UserRoleUpdateRequest(BaseModel):
    """User role update request"""
    user_id: int
    role: UserRole


class AuditLogResponse(BaseModel):
    """Audit log entry response"""
    id: int
    user_id: Optional[int]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    status: Optional[str]
    details: Optional[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True


# =============================================================================
# BATCH SCAN SCHEMAS
# =============================================================================
class BatchScheduleStrategy(str, Enum):
    """Scheduling strategies for batch scans"""
    SEQUENTIAL = "sequential"      # One target at a time, in order
    PARALLEL = "parallel"          # All targets simultaneously (up to max_concurrent)
    STAGGERED = "staggered"        # Start new scan every N minutes
    RESOURCE_AWARE = "resource_aware"  # Dynamic scheduling based on system load
    TOOL_OPTIMIZED = "tool_optimized"  # Run same tool across all targets, then next


class BatchScanTargetCreate(BaseModel):
    """Individual target in a batch scan"""
    target: str = Field(..., description="IP address, domain, or URL")
    priority: Optional[int] = Field(default=5, ge=1, le=10)
    
    @validator('target')
    def validate_target(cls, v):
        v = v.strip()
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        url_pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(/.*)?$'
        
        if re.match(ip_pattern, v) or re.match(domain_pattern, v) or re.match(url_pattern, v):
            return v
        raise ValueError('Invalid target format')


class BatchScanCreate(BaseModel):
    """Batch scan creation request"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    targets: List[BatchScanTargetCreate] = Field(..., min_items=1, max_items=100)
    scan_type: ScanType = Field(default=ScanType.FULL)
    schedule_strategy: BatchScheduleStrategy = Field(default=BatchScheduleStrategy.RESOURCE_AWARE)
    max_concurrent: Optional[int] = Field(default=3, ge=1, le=10)
    stagger_minutes: Optional[int] = Field(default=5, ge=1, le=60)
    priority: int = Field(default=5, ge=1, le=10)
    scheduled_at: Optional[datetime] = None


class BatchScanTargetResponse(BaseModel):
    """Individual target status in batch"""
    id: int
    target_value: str
    execution_order: int
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    findings_count: Optional[int]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class BatchScanResponse(BaseModel):
    """Batch scan response"""
    id: int
    batch_id: str
    name: str
    description: Optional[str]
    scan_type: ScanType
    schedule_strategy: BatchScheduleStrategy
    status: str
    total_targets: int
    completed_targets: int
    failed_targets: int
    total_findings: Optional[int]
    critical_count: Optional[int]
    high_count: Optional[int]
    medium_count: Optional[int]
    low_count: Optional[int]
    info_count: Optional[int]
    max_concurrent: Optional[int]
    stagger_minutes: Optional[int]
    scheduled_at: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    targets: Optional[List[BatchScanTargetResponse]] = None

    class Config:
        from_attributes = True


class BatchScanListResponse(BaseModel):
    """Paginated batch scan list"""
    batches: List[BatchScanResponse]
    total: int
    page: int
    per_page: int


class RecurringScheduleCreate(BaseModel):
    """Recurring schedule creation"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    cron_expression: str = Field(..., description="Cron expression (e.g., '0 2 * * *' for 2 AM daily)")
    timezone: str = Field(default="UTC")
    target_ids: List[int] = Field(..., min_items=1)
    scan_type: ScanType = Field(default=ScanType.FULL)
    
    @validator('cron_expression')
    def validate_cron(cls, v):
        parts = v.split()
        if len(parts) != 5:
            raise ValueError('Cron expression must have 5 parts: minute hour day month weekday')
        return v


class RecurringScheduleResponse(BaseModel):
    """Recurring schedule response"""
    id: int
    schedule_id: str
    name: str
    description: Optional[str]
    cron_expression: str
    timezone: str
    scan_type: ScanType
    is_active: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    run_count: int
    created_at: datetime

    class Config:
        from_attributes = True
