"""
Noovastack-VAPT Database Models
SQLAlchemy ORM Models
"""

from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, 
    ForeignKey, Enum, JSON, Float, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


def enum_values(enum_cls):
    """Persist enum .value strings to match PostgreSQL enum definitions."""
    return [member.value for member in enum_cls]


class UserRole(str, PyEnum):
    """User role enumeration"""
    ADMIN = "admin"
    USER = "user"


class ScanStatus(str, PyEnum):
    """Scan status enumeration"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, PyEnum):
    """Scan type enumeration"""
    FULL = "full"
    QUICK = "quick"
    WEB_ONLY = "web_only"
    NETWORK_ONLY = "network_only"
    CONTAINER_ONLY = "container_only"
    CLOUD_ONLY = "cloud_only"
    IAC_ONLY = "iac_only"
    KUBERNETES_ONLY = "kubernetes_only"
    API_ONLY = "api_only"


class BatchScheduleStrategy(str, PyEnum):
    """Batch scan scheduling strategy"""
    SEQUENTIAL = "sequential"      # One target at a time
    PARALLEL = "parallel"          # All targets simultaneously (resource intensive)
    STAGGERED = "staggered"        # Start new scan every N minutes
    RESOURCE_AWARE = "resource_aware"  # Dynamic based on system load
    TOOL_OPTIMIZED = "tool_optimized"  # Run same tool across all targets, then next tool


class TargetType(str, PyEnum):
    """Target type enumeration"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class Severity(str, PyEnum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ApprovalStatus(str, PyEnum):
    """External target approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


# =============================================================================
# USER MODEL
# =============================================================================
class User(Base):
    """User account model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(
        Enum(UserRole, name="user_role", values_callable=enum_values),
        default=UserRole.USER,
        nullable=False,
    )
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Profile
    full_name = Column(String(255))
    organization = Column(String(255))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    
    # Relationships
    scans = relationship("Scan", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


# =============================================================================
# TARGET MODEL
# =============================================================================
class Target(Base):
    """Scan target model"""
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(500), nullable=False, index=True)  # IP, domain, or URL
    target_type = Column(
        Enum(TargetType, name="target_type", values_callable=enum_values),
        nullable=False,
    )
    is_external = Column(Boolean, default=False)
    approval_status = Column(
        Enum(ApprovalStatus, name="approval_status", values_callable=enum_values),
        default=ApprovalStatus.PENDING,
    )
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True))
    
    # Metadata
    organization = Column(String(255))
    notes = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scans = relationship("Scan", back_populates="target")


# =============================================================================
# SCAN MODEL
# =============================================================================
class Scan(Base):
    """Vulnerability scan model"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), unique=True, index=True, nullable=False)  # UUID
    
    # Foreign Keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    
    # Scan Configuration
    scan_type = Column(
        Enum(ScanType, name="scan_type", values_callable=enum_values),
        default=ScanType.FULL,
    )
    status = Column(
        Enum(ScanStatus, name="scan_status", values_callable=enum_values),
        default=ScanStatus.PENDING,
        index=True,
    )
    priority = Column(Integer, default=5)  # 1-10, lower = higher priority
    
    # Progress Tracking
    progress = Column(Integer, default=0)  # 0-100
    current_phase = Column(String(100))
    
    # Timing
    scheduled_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Results Summary
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Report
    report_path = Column(String(500))
    
    # Error handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tool_results = relationship("ToolResult", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_scan_user_status', 'user_id', 'status'),
        Index('idx_scan_created', 'created_at'),
    )


# =============================================================================
# FINDING MODEL
# =============================================================================
class Finding(Base):
    """Vulnerability finding model"""
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    
    # Vulnerability Details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(
        Enum(Severity, name="severity", values_callable=enum_values),
        nullable=False,
        index=True,
    )
    
    # CVE Information
    cve_id = Column(String(50), index=True)
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    
    # Technical Details
    affected_component = Column(String(255))
    affected_port = Column(Integer)
    affected_service = Column(String(100))
    affected_url = Column(String(1000))
    
    # Evidence
    evidence = Column(Text)
    request = Column(Text)
    response = Column(Text)
    
    # Remediation
    solution = Column(Text)
    references = Column(JSON)  # List of reference URLs
    
    # Source
    tool_name = Column(String(50))  # nmap, openvas, nuclei, zap, etc.
    raw_output = Column(Text)
    
    # Deduplication
    fingerprint = Column(String(64), index=True)  # SHA256 hash for dedup
    
    # Timestamps
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    
    # Indexes
    __table_args__ = (
        Index('idx_finding_severity', 'severity'),
        Index('idx_finding_cve', 'cve_id'),
    )


# =============================================================================
# TOOL RESULT MODEL
# =============================================================================
class ToolResult(Base):
    """Individual tool execution results"""
    __tablename__ = "tool_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    
    tool_name = Column(String(50), nullable=False)
    status = Column(String(20))  # success, failed, timeout
    
    # Execution Details
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)
    
    # Results
    raw_output = Column(Text)
    parsed_output = Column(JSON)
    findings_count = Column(Integer, default=0)
    
    # Error handling
    error_message = Column(Text)
    exit_code = Column(Integer)
    
    # Relationships
    scan = relationship("Scan", back_populates="tool_results")


# =============================================================================
# AUDIT LOG MODEL
# =============================================================================
class AuditLog(Base):
    """Audit log for security tracking"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Action Details
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))  # user, scan, target, etc.
    resource_id = Column(String(50))
    
    # Request Context
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    request_method = Column(String(10))
    request_path = Column(String(500))
    
    # Details
    details = Column(JSON)
    status = Column(String(20))  # success, failure
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_action', 'action'),
        Index('idx_audit_created', 'created_at'),
    )


# =============================================================================
# SYSTEM SETTINGS MODEL
# =============================================================================
class SystemSettings(Base):
    """System configuration settings"""
    __tablename__ = "system_settings"
    
    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text)
    description = Column(Text)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    updated_by = Column(Integer, ForeignKey("users.id"))


# =============================================================================
# BATCH SCAN MODEL
# =============================================================================
class BatchScan(Base):
    """Batch scan for multiple targets with optimization"""
    __tablename__ = "batch_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(String(36), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    
    # Foreign Keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Configuration
    scan_type = Column(Enum(ScanType), default=ScanType.FULL)
    tools = Column(JSON)  # List of tools to use
    schedule_strategy = Column(Enum(BatchScheduleStrategy), default=BatchScheduleStrategy.RESOURCE_AWARE)
    
    # Scheduling Options
    stagger_minutes = Column(Integer, default=5)  # For staggered strategy
    max_concurrent = Column(Integer, default=3)  # Max parallel scans
    priority = Column(Integer, default=5)  # 1-10, lower = higher priority
    
    # Timing
    scheduled_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Status & Progress
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    total_targets = Column(Integer, default=0)
    completed_targets = Column(Integer, default=0)
    failed_targets = Column(Integer, default=0)
    
    # Results Summary (aggregated from all scans)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User")
    targets = relationship("BatchScanTarget", back_populates="batch_scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_batch_user_status', 'user_id', 'status'),
        Index('idx_batch_created', 'created_at'),
    )


class BatchScanTarget(Base):
    """Individual target within a batch scan"""
    __tablename__ = "batch_scan_targets"
    
    id = Column(Integer, primary_key=True, index=True)
    batch_scan_id = Column(Integer, ForeignKey("batch_scans.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)  # Created when scan starts
    
    # Execution order (for optimized scheduling)
    execution_order = Column(Integer, default=0)
    
    # Status
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    
    # Relationships
    batch_scan = relationship("BatchScan", back_populates="targets")
    target = relationship("Target")
    scan = relationship("Scan")


# =============================================================================
# RECURRING SCHEDULE MODEL
# =============================================================================
class RecurringSchedule(Base):
    """Recurring scan schedule with cron support"""
    __tablename__ = "recurring_schedules"
    
    id = Column(Integer, primary_key=True, index=True)
    schedule_id = Column(String(36), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    
    # Foreign Keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Targets (can be single or batch)
    target_ids = Column(JSON)  # List of target IDs
    is_batch = Column(Boolean, default=False)
    batch_strategy = Column(Enum(BatchScheduleStrategy), default=BatchScheduleStrategy.RESOURCE_AWARE)
    
    # Scan Configuration  
    scan_type = Column(Enum(ScanType), default=ScanType.FULL)
    tools = Column(JSON)  # List of tools to use
    scan_options = Column(JSON)  # Additional scan options
    
    # Cron Schedule
    cron_expression = Column(String(100), nullable=False)  # e.g., "0 2 * * 1" (Monday 2AM)
    timezone = Column(String(50), default="UTC")
    
    # Control
    is_active = Column(Boolean, default=True)
    max_concurrent = Column(Integer, default=3)
    
    # Statistics
    last_run_at = Column(DateTime(timezone=True))
    next_run_at = Column(DateTime(timezone=True))
    run_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User")
    
    # Indexes
    __table_args__ = (
        Index('idx_schedule_active', 'is_active'),
        Index('idx_schedule_next_run', 'next_run_at'),
    )
