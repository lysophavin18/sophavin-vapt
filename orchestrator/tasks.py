"""
S-VAPT Scan Orchestrator
Celery-based scan execution pipeline
"""

import os
import json
import hashlib
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

import psutil
import redis
from celery import Celery, chain, group
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import structlog
import xmltodict

# Initialize Celery
celery_app = Celery(
    'noovastack',
    broker=os.environ.get('REDIS_URL', 'redis://localhost:6379/0'),
    backend=os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=7200,  # 2 hours max
    task_soft_time_limit=6900,  # 1:55 soft limit
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

# Task queues
celery_app.conf.task_routes = {
    'tasks.execute_scan': {'queue': 'scans'},
    'tasks.run_nmap': {'queue': 'scans'},
    'tasks.run_openvas': {'queue': 'scans'},
    'tasks.run_nuclei': {'queue': 'scans'},
    'tasks.run_zap': {'queue': 'scans'},
    'tasks.run_nikto': {'queue': 'scans'},
    'tasks.run_sqlmap': {'queue': 'scans'},
    # API Security Tools
    'tasks.run_arjun': {'queue': 'api_scans'},
    'tasks.run_graphqlmap': {'queue': 'api_scans'},
    'tasks.run_jwt_tool': {'queue': 'api_scans'},
    'tasks.run_wfuzz': {'queue': 'api_scans'},
    'tasks.run_newman': {'queue': 'api_scans'},
    # Dynamic Web Scanning Tools
    'tasks.run_wapiti': {'queue': 'scans'},
    'tasks.run_dalfox': {'queue': 'scans'},
    'tasks.run_feroxbuster': {'queue': 'scans'},
    'tasks.run_commix': {'queue': 'scans'},
    'tasks.run_cmseek': {'queue': 'scans'},
    'tasks.run_sniper': {'queue': 'scans'},
    'tasks.aggregate_results': {'queue': 'high_priority'},
    'tasks.generate_report': {'queue': 'high_priority'},
}

logger = structlog.get_logger()

# Database connection
DATABASE_URL = os.environ.get('DATABASE_URL', '').replace('+asyncpg', '')
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# Configuration
MAX_CPU_PERCENT = int(os.environ.get('MAX_CPU_PERCENT', 80))
MAX_RAM_PERCENT = int(os.environ.get('MAX_RAM_PERCENT', 85))
SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 7200))
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')


# =============================================================================
# TELEGRAM NOTIFICATION
# =============================================================================
def send_telegram_notification(message: str) -> None:
    """Send a Telegram message via Bot API. Errors are suppressed — notification
    failure must never affect scan state persistence."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
    }
    try:
        import httpx
        resp = httpx.post(url, json=payload, timeout=5.0)
        if not resp.is_success:
            logger.warning(
                "Telegram notification failed",
                status_code=resp.status_code,
                response=resp.text[:200],
            )
    except Exception as exc:
        logger.warning("Telegram notification error", error=str(exc))


# =============================================================================
# DATA CLASSES
# =============================================================================
@dataclass
class ScanContext:
    """Scan execution context"""
    scan_id: str
    target: str
    target_type: str
    scan_type: str
    results_dir: str
    discovered_ports: List[int] = None
    discovered_services: Dict[int, str] = None
    web_ports: List[int] = None
    
    def __post_init__(self):
        self.discovered_ports = self.discovered_ports or []
        self.discovered_services = self.discovered_services or {}
        self.web_ports = self.web_ports or []


class ScanPhase(str, Enum):
    """Scan execution phases"""
    INITIALIZING = "Initializing scan"
    DISCOVERY = "Port discovery (Nmap)"
    VULN_SCAN = "Vulnerability scanning (OpenVAS)"
    NUCLEI = "Template scanning (Nuclei)"
    WEB_SCAN = "Web application scanning (ZAP)"
    NIKTO = "Web server scanning (Nikto)"
    SQLMAP = "SQL injection testing (SQLmap)"
    # Dynamic Web Scanning Phases
    WAPITI = "Web vulnerability scanning (Wapiti)"
    DALFOX = "XSS parameter scanning (Dalfox)"
    FEROXBUSTER = "Content discovery (Feroxbuster)"
    COMMIX = "Command injection testing (Commix)"
    CMSEEK = "CMS detection & analysis (CMSeeK)"
    SNIPER = "Automated recon & attack (Sn1per)"
    # API Security Phases
    ARJUN = "Parameter discovery (Arjun)"
    GRAPHQL = "GraphQL security testing (GraphQLmap)"
    JWT_ANALYSIS = "JWT token analysis (jwt_tool)"
    API_FUZZING = "API endpoint fuzzing (wfuzz)"
    API_COLLECTION = "API collection testing (Newman)"
    # Container Security Phases
    DOCKER_BENCH = "Docker CIS benchmark (Docker-Bench)"
    CLAIR = "Container vulnerability analysis (Clair)"
    FALCO = "Runtime security monitoring (Falco)"
    # Cloud Security Phases
    SCOUTSUITE = "Multi-cloud security audit (ScoutSuite)"
    PROWLER = "AWS security assessment (Prowler)"
    # IaC Security Phases
    CHECKOV = "IaC security scanning (Checkov)"
    TERRASCAN = "IaC policy enforcement (Terrascan)"
    # Kubernetes Security Phases
    KUBE_HUNTER = "Kubernetes penetration testing (kube-hunter)"
    KUBE_BENCH = "Kubernetes CIS benchmark (kube-bench)"
    AGGREGATING = "Aggregating results"
    REPORTING = "Generating report"
    COMPLETED = "Scan completed"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def check_system_resources() -> Dict[str, Any]:
    """Check if system has sufficient resources for scanning"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    
    return {
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'can_proceed': cpu_percent < MAX_CPU_PERCENT and memory.percent < MAX_RAM_PERCENT
    }


def update_scan_status(scan_id: str, status: str, progress: int, phase: str = None, error: str = None):
    """Update scan status in database"""
    session = SessionLocal()
    notification_payload = None
    try:
        from app.models.models import Scan, ScanStatus, Target

        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            scan.status = ScanStatus(status)
            scan.progress = progress
            if phase:
                scan.current_phase = phase
            if error:
                scan.error_message = error
            if status == 'running' and not scan.started_at:
                scan.started_at = datetime.utcnow()
            if status in ['completed', 'failed']:
                scan.completed_at = datetime.utcnow()
                # Snapshot notification data before closing session
                target = session.query(Target).filter(Target.id == scan.target_id).first()
                notification_payload = {
                    'scan_id': scan_id,
                    'status': status,
                    'target': target.value if target else 'unknown',
                    'total_findings': scan.total_findings or 0,
                    'critical_count': scan.critical_count or 0,
                    'high_count': scan.high_count or 0,
                    'error': (error or '')[:200],
                    'findings_are_partial': status == 'failed',
                }
            session.commit()
    finally:
        session.close()

    # Send Telegram notification after DB commit so the state is persisted
    if notification_payload:
        _notify_telegram_scan_complete(notification_payload)


def _notify_telegram_scan_complete(payload: dict) -> None:
    """Build and send a Telegram message for scan completion or failure."""
    status = payload['status']
    icon = '✅' if status == 'completed' else '❌'
    lines = [
        f"{icon} <b>Scan {status.upper()}</b>",
        f"🔍 Target: <code>{payload['target']}</code>",
        f"🆔 Scan ID: <code>{payload['scan_id']}</code>",
    ]
    if status == 'completed':
        lines += [
            f"📊 Total Findings: <b>{payload['total_findings']}</b>",
            f"🔴 Critical: {payload['critical_count']}  🟠 High: {payload['high_count']}",
        ]
    elif status == 'failed':
        partial_note = " (partial)" if payload['total_findings'] > 0 else ""
        lines += [
            f"📊 Findings before failure{partial_note}: {payload['total_findings']}",
            f"⚠️ Error: {payload['error'] or 'Unknown error'}",
        ]
    send_telegram_notification('\n'.join(lines))


def run_docker_command(container: str, command: List[str], timeout: int = 600) -> Dict[str, Any]:
    """Execute command in Docker container"""
    full_cmd = ['docker', 'exec', container] + command
    
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exit_code': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'stdout': '',
            'stderr': 'Command timed out',
            'exit_code': -1
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'exit_code': -1
        }


def generate_finding_fingerprint(finding: Dict) -> str:
    """Generate unique fingerprint for deduplication"""
    key_parts = [
        finding.get('title', ''),
        finding.get('cve_id', ''),
        finding.get('affected_component', ''),
        str(finding.get('affected_port', '')),
    ]
    content = '|'.join(key_parts).lower()
    return hashlib.sha256(content.encode()).hexdigest()


# =============================================================================
# BATCH SCAN OPTIMIZATION STRATEGIES
# =============================================================================
class BatchScheduleStrategy:
    """Batch scheduling strategies for multiple targets"""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    STAGGERED = "staggered"
    RESOURCE_AWARE = "resource_aware"
    TOOL_OPTIMIZED = "tool_optimized"


def calculate_optimal_concurrency() -> int:
    """Calculate optimal concurrent scans based on system resources"""
    resources = check_system_resources()
    
    # Base calculation on available resources
    available_cpu = 100 - resources['cpu_percent']
    available_mem = 100 - resources['memory_percent']
    
    # Each scan uses ~20% CPU, 15% memory on average
    cpu_slots = int(available_cpu / 20)
    mem_slots = int(available_mem / 15)
    
    # Use the more restrictive limit, minimum 1, maximum from config
    max_concurrent = int(os.environ.get('MAX_CONCURRENT_SCANS', 5))
    optimal = min(cpu_slots, mem_slots, max_concurrent)
    
    return max(1, optimal)


def optimize_batch_execution_order(target_ids: List[int], scan_type: str, strategy: str) -> List[dict]:
    """
    Optimize execution order for batch scans.
    Returns list of {target_id, priority, estimated_duration}
    """
    session = SessionLocal()
    optimized = []
    
    try:
        from app.models.models import Target
        
        # Scan duration estimates in minutes by scan type
        duration_estimates = {
            'quick': 10,
            'full': 45,
            'web_only': 30,
            'network_only': 20,
            'container_only': 20,
            'cloud_only': 45,
            'iac_only': 15,
            'kubernetes_only': 20,
            'api_only': 25,
        }
        base_duration = duration_estimates.get(scan_type, 30)
        
        for target_id in target_ids:
            target = session.query(Target).filter(Target.id == target_id).first()
            if not target:
                continue
            
            # Calculate priority based on target characteristics
            priority = 5  # Default middle priority
            estimated_duration = base_duration
            
            # Adjust based on target type
            if target.target_type.value == 'ip':
                # Single IPs are faster
                estimated_duration *= 0.8
                priority = 3  # Higher priority (faster first for quick wins)
            elif target.target_type.value == 'domain':
                # Domains may have more hosts
                estimated_duration *= 1.2
                priority = 5
            elif target.target_type.value == 'url':
                # URLs are focused
                estimated_duration *= 0.7
                priority = 2
            
            optimized.append({
                'target_id': target_id,
                'target_value': target.value,
                'target_type': target.target_type.value,
                'priority': priority,
                'estimated_duration': int(estimated_duration)
            })
        
        # Sort by strategy
        if strategy == BatchScheduleStrategy.TOOL_OPTIMIZED:
            # Group similar targets together (all IPs first, then domains, etc.)
            optimized.sort(key=lambda x: (x['target_type'], x['priority']))
        else:
            # Default: shortest first for maximum throughput
            optimized.sort(key=lambda x: (x['priority'], x['estimated_duration']))
        
        # Assign execution order
        for i, item in enumerate(optimized):
            item['execution_order'] = i + 1
        
    finally:
        session.close()
    
    return optimized


@celery_app.task(bind=True, name='tasks.execute_batch_scan')
def execute_batch_scan(self, batch_id: str):
    """
    Batch scan orchestrator with optimization strategies.
    Schedules multiple scans with resource-aware optimization.
    """
    logger.info("Starting batch scan execution", batch_id=batch_id)
    
    session = SessionLocal()
    try:
        from app.models.models import BatchScan, BatchScanTarget, Scan, Target
        
        batch = session.query(BatchScan).filter(BatchScan.batch_id == batch_id).first()
        if not batch:
            logger.error("Batch scan not found", batch_id=batch_id)
            return {'error': 'Batch scan not found'}
        
        # Update status
        batch.status = 'running'
        batch.started_at = datetime.utcnow()
        session.commit()
        
        strategy = batch.schedule_strategy.value if batch.schedule_strategy else 'resource_aware'
        targets = session.query(BatchScanTarget).filter(
            BatchScanTarget.batch_scan_id == batch.id
        ).order_by(BatchScanTarget.execution_order).all()
        
        # Execute based on strategy
        if strategy == BatchScheduleStrategy.SEQUENTIAL:
            # One at a time
            for target in targets:
                _execute_batch_target(batch, target, session)
        
        elif strategy == BatchScheduleStrategy.PARALLEL:
            # All at once (limited by max_concurrent)
            max_concurrent = batch.max_concurrent or 3
            from celery import group
            
            scan_tasks = []
            for target in targets[:max_concurrent]:
                scan_id = _create_scan_for_batch_target(batch, target, session)
                if scan_id:
                    scan_tasks.append(execute_scan.s(scan_id))
                    target.status = 'queued'
            
            session.commit()
            
            if scan_tasks:
                job = group(scan_tasks)
                job.apply_async()
        
        elif strategy == BatchScheduleStrategy.STAGGERED:
            # Start new scan every N minutes
            stagger_minutes = batch.stagger_minutes or 5
            
            for i, target in enumerate(targets):
                scan_id = _create_scan_for_batch_target(batch, target, session)
                if scan_id:
                    # Schedule with countdown
                    execute_scan.apply_async(
                        args=[scan_id],
                        countdown=i * stagger_minutes * 60  # Convert to seconds
                    )
                    target.status = 'queued'
            
            session.commit()
        
        elif strategy == BatchScheduleStrategy.RESOURCE_AWARE:
            # Dynamic scheduling based on system load
            optimal_concurrent = calculate_optimal_concurrency()
            active_scans = 0
            
            for target in targets:
                # Wait for slot if at capacity
                while active_scans >= optimal_concurrent:
                    import time
                    time.sleep(30)
                    # Recheck active scans
                    active_scans = session.query(BatchScanTarget).filter(
                        BatchScanTarget.batch_scan_id == batch.id,
                        BatchScanTarget.status == 'running'
                    ).count()
                    # Recalculate optimal concurrency
                    optimal_concurrent = calculate_optimal_concurrency()
                
                scan_id = _create_scan_for_batch_target(batch, target, session)
                if scan_id:
                    execute_scan.apply_async(args=[scan_id])
                    target.status = 'queued'
                    active_scans += 1
            
            session.commit()
        
        elif strategy == BatchScheduleStrategy.TOOL_OPTIMIZED:
            # Run same tool across all targets before moving to next tool
            # This is handled differently - create all scans but with tool-by-tool execution
            for target in targets:
                scan_id = _create_scan_for_batch_target(batch, target, session)
                if scan_id:
                    execute_scan.apply_async(args=[scan_id])
                    target.status = 'queued'
            session.commit()
        
        logger.info("Batch scan scheduled", batch_id=batch_id, 
                   targets=len(targets), strategy=strategy)
        
        return {'status': 'scheduled', 'batch_id': batch_id, 'targets': len(targets)}
        
    except Exception as e:
        logger.error("Batch scan failed", batch_id=batch_id, error=str(e))
        return {'error': str(e)}
    finally:
        session.close()


def _create_scan_for_batch_target(batch, batch_target, session) -> Optional[str]:
    """Create an individual scan for a batch target"""
    from app.models.models import Scan
    import uuid
    
    scan_id = str(uuid.uuid4())
    
    scan = Scan(
        scan_id=scan_id,
        user_id=batch.user_id,
        target_id=batch_target.target_id,
        scan_type=batch.scan_type,
        status='queued',
        priority=batch.priority,
        scheduled_at=batch.scheduled_at
    )
    session.add(scan)
    session.flush()
    
    batch_target.scan_id = scan.id
    session.commit()
    
    return scan_id


def _execute_batch_target(batch, batch_target, session):
    """Execute a single target in sequential mode"""
    scan_id = _create_scan_for_batch_target(batch, batch_target, session)
    if scan_id:
        batch_target.status = 'running'
        batch_target.started_at = datetime.utcnow()
        session.commit()
        
        # Execute synchronously
        result = execute_scan(scan_id)
        
        if result.get('error'):
            batch_target.status = 'failed'
            batch_target.error_message = result['error']
        else:
            batch_target.status = 'completed'
        
        batch_target.completed_at = datetime.utcnow()
        session.commit()


@celery_app.task(name='tasks.check_batch_completion')
def check_batch_completion(batch_id: str):
    """Check if all targets in a batch are complete and update summary"""
    session = SessionLocal()
    try:
        from app.models.models import BatchScan, BatchScanTarget, Scan
        
        batch = session.query(BatchScan).filter(BatchScan.batch_id == batch_id).first()
        if not batch:
            return
        
        targets = session.query(BatchScanTarget).filter(
            BatchScanTarget.batch_scan_id == batch.id
        ).all()
        
        completed = sum(1 for t in targets if t.status in ['completed', 'failed'])
        failed = sum(1 for t in targets if t.status == 'failed')
        
        batch.completed_targets = completed
        batch.failed_targets = failed
        
        # Aggregate findings from all scans
        total_findings = 0
        critical = high = medium = low = info = 0
        
        for target in targets:
            if target.scan:
                total_findings += target.scan.total_findings or 0
                critical += target.scan.critical_count or 0
                high += target.scan.high_count or 0
                medium += target.scan.medium_count or 0
                low += target.scan.low_count or 0
                info += target.scan.info_count or 0
        
        batch.total_findings = total_findings
        batch.critical_count = critical
        batch.high_count = high
        batch.medium_count = medium
        batch.low_count = low
        batch.info_count = info
        
        # Check if all complete
        if completed == batch.total_targets:
            batch.status = 'completed' if failed == 0 else 'failed'
            batch.completed_at = datetime.utcnow()
        
        session.commit()
        
    finally:
        session.close()


# =============================================================================
# MAIN SCAN ORCHESTRATOR
# =============================================================================
@celery_app.task(bind=True, name='tasks.execute_scan')
def execute_scan(self, scan_id: str):
    """
    Main scan orchestrator task.
    Coordinates all scanning tools in sequence.
    """
    logger.info("Starting scan execution", scan_id=scan_id)
    
    # Check system resources
    resources = check_system_resources()
    if not resources['can_proceed']:
        logger.warning(
            "System resources insufficient, requeueing",
            scan_id=scan_id,
            cpu=resources['cpu_percent'],
            memory=resources['memory_percent']
        )
        # Retry in 60 seconds
        self.retry(countdown=60, max_retries=10)
    
    # Get scan details from database
    session = SessionLocal()
    try:
        from app.models.models import Scan, Target
        
        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            logger.error("Scan not found", scan_id=scan_id)
            return {'error': 'Scan not found'}
        
        target = session.query(Target).filter(Target.id == scan.target_id).first()
        
        # Initialize context
        context = ScanContext(
            scan_id=scan_id,
            target=target.value,
            target_type=target.target_type.value,
            scan_type=scan.scan_type.value,
            results_dir=f"/app/results/{scan_id}"
        )
        
        # Create results directory
        os.makedirs(context.results_dir, exist_ok=True)
        
    finally:
        session.close()
    
    try:
        # Update status to running
        update_scan_status(scan_id, 'running', 5, ScanPhase.INITIALIZING.value)
        
        # Phase 1: Port Discovery (Nmap)
        update_scan_status(scan_id, 'running', 10, ScanPhase.DISCOVERY.value)
        nmap_results = run_nmap_scan(context)
        
        if nmap_results.get('error'):
            raise Exception(f"Nmap scan failed: {nmap_results['error']}")
        
        # Extract discovered information
        context.discovered_ports = nmap_results.get('open_ports', [])
        context.discovered_services = nmap_results.get('services', {})
        context.web_ports = [p for p, s in context.discovered_services.items() 
                           if 'http' in s.lower() or 'web' in s.lower()]
        
        # Phase 2: Vulnerability Scanning (OpenVAS) - if enabled
        if context.scan_type in ['full', 'network_only']:
            update_scan_status(scan_id, 'running', 25, ScanPhase.VULN_SCAN.value)
            openvas_results = run_openvas_scan(context)
            save_tool_result(scan_id, 'openvas', openvas_results)
        
        # Phase 3: Template Scanning (Nuclei)
        update_scan_status(scan_id, 'running', 45, ScanPhase.NUCLEI.value)
        nuclei_results = run_nuclei_scan(context)
        save_tool_result(scan_id, 'nuclei', nuclei_results)
        
        # Phase 4-6: Web Scanning (if web ports found)
        if context.web_ports and context.scan_type in ['full', 'web_only']:
            # ZAP
            update_scan_status(scan_id, 'running', 60, ScanPhase.WEB_SCAN.value)
            zap_results = run_zap_scan(context)
            save_tool_result(scan_id, 'zap', zap_results)
            
            # Nikto
            update_scan_status(scan_id, 'running', 65, ScanPhase.NIKTO.value)
            nikto_results = run_nikto_scan(context)
            save_tool_result(scan_id, 'nikto', nikto_results)
            
            # Wapiti - web vulnerability scanner
            update_scan_status(scan_id, 'running', 68, ScanPhase.WAPITI.value)
            wapiti_results = run_wapiti_scan(context)
            save_tool_result(scan_id, 'wapiti', wapiti_results)
            
            # Feroxbuster - content discovery
            update_scan_status(scan_id, 'running', 71, ScanPhase.FEROXBUSTER.value)
            feroxbuster_results = run_feroxbuster_scan(context)
            save_tool_result(scan_id, 'feroxbuster', feroxbuster_results)
            
            # Dalfox - XSS parameter scanning
            update_scan_status(scan_id, 'running', 74, ScanPhase.DALFOX.value)
            dalfox_results = run_dalfox_scan(context)
            save_tool_result(scan_id, 'dalfox', dalfox_results)
            
            # CMSeeK - CMS detection
            update_scan_status(scan_id, 'running', 77, ScanPhase.CMSEEK.value)
            cmseek_results = run_cmseek_scan(context)
            save_tool_result(scan_id, 'cmseek', cmseek_results)
            
            # SQLmap (conservative)
            update_scan_status(scan_id, 'running', 80, ScanPhase.SQLMAP.value)
            sqlmap_results = run_sqlmap_scan(context)
            save_tool_result(scan_id, 'sqlmap', sqlmap_results)
            
            # Commix - command injection testing
            update_scan_status(scan_id, 'running', 83, ScanPhase.COMMIX.value)
            commix_results = run_commix_scan(context)
            save_tool_result(scan_id, 'commix', commix_results)
        
        # Dynamic / Full Pentest (Sn1per runs on full scans with web targets)
        if context.web_ports and context.scan_type == 'full':
            update_scan_status(scan_id, 'running', 86, ScanPhase.SNIPER.value)
            sniper_results = run_sniper_scan(context)
            save_tool_result(scan_id, 'sniper', sniper_results)
        
        # Container Security Scanning
        if context.scan_type in ['full', 'container_only']:
            update_scan_status(scan_id, 'running', 55, ScanPhase.DOCKER_BENCH.value)
            docker_bench_results = run_docker_bench_scan(context)
            save_tool_result(scan_id, 'docker_bench', docker_bench_results)
            
            # Clair - Vulnerability analysis
            update_scan_status(scan_id, 'running', 60, ScanPhase.CLAIR.value)
            clair_results = run_clair_scan(context)
            save_tool_result(scan_id, 'clair', clair_results)
            
            # Falco - Runtime security
            update_scan_status(scan_id, 'running', 65, ScanPhase.FALCO.value)
            falco_results = run_falco_scan(context)
            save_tool_result(scan_id, 'falco', falco_results)
        
        # Cloud Security Scanning
        if context.scan_type in ['full', 'cloud_only']:
            # ScoutSuite - Multi-cloud audit
            update_scan_status(scan_id, 'running', 50, ScanPhase.SCOUTSUITE.value)
            scoutsuite_results = run_scoutsuite_scan(context)
            save_tool_result(scan_id, 'scoutsuite', scoutsuite_results)
            
            # Prowler - AWS security assessment
            update_scan_status(scan_id, 'running', 60, ScanPhase.PROWLER.value)
            prowler_results = run_prowler_scan(context)
            save_tool_result(scan_id, 'prowler', prowler_results)
        
        # IaC Security Scanning
        if context.scan_type in ['full', 'iac_only']:
            # Checkov - IaC scanning
            update_scan_status(scan_id, 'running', 50, ScanPhase.CHECKOV.value)
            checkov_results = run_checkov_scan(context)
            save_tool_result(scan_id, 'checkov', checkov_results)
            
            # Terrascan - IaC policy enforcement
            update_scan_status(scan_id, 'running', 60, ScanPhase.TERRASCAN.value)
            terrascan_results = run_terrascan_scan(context)
            save_tool_result(scan_id, 'terrascan', terrascan_results)
        
        # Kubernetes Security Scanning
        if context.scan_type in ['full', 'kubernetes_only']:
            # Kube-hunter - K8s penetration testing
            update_scan_status(scan_id, 'running', 50, ScanPhase.KUBE_HUNTER.value)
            kube_hunter_results = run_kube_hunter_scan(context)
            save_tool_result(scan_id, 'kube_hunter', kube_hunter_results)
            
            # Kube-bench - CIS K8s benchmark
            update_scan_status(scan_id, 'running', 60, ScanPhase.KUBE_BENCH.value)
            kube_bench_results = run_kube_bench_scan(context)
            save_tool_result(scan_id, 'kube_bench', kube_bench_results)
        
        # API Security Scanning
        if context.scan_type in ['full', 'api_only']:
            # Arjun - Parameter discovery
            update_scan_status(scan_id, 'running', 50, ScanPhase.ARJUN.value)
            arjun_results = run_arjun_scan(context)
            save_tool_result(scan_id, 'arjun', arjun_results)
            
            # GraphQLmap - GraphQL security testing
            update_scan_status(scan_id, 'running', 60, ScanPhase.GRAPHQL.value)
            graphql_results = run_graphqlmap_scan(context)
            save_tool_result(scan_id, 'graphqlmap', graphql_results)
            
            # JWT_Tool - JWT analysis
            update_scan_status(scan_id, 'running', 70, ScanPhase.JWT_ANALYSIS.value)
            jwt_results = run_jwt_tool_scan(context)
            save_tool_result(scan_id, 'jwt_tool', jwt_results)
            
            # wfuzz - API fuzzing
            update_scan_status(scan_id, 'running', 80, ScanPhase.API_FUZZING.value)
            wfuzz_results = run_wfuzz_scan(context)
            save_tool_result(scan_id, 'wfuzz', wfuzz_results)
            
            # Newman - API collection testing
            update_scan_status(scan_id, 'running', 85, ScanPhase.API_COLLECTION.value)
            newman_results = run_newman_scan(context)
            save_tool_result(scan_id, 'newman', newman_results)
        
        # Phase 7: Aggregate Results
        update_scan_status(scan_id, 'running', 90, ScanPhase.AGGREGATING.value)
        aggregate_results(scan_id, context)
        
        # Phase 8: Generate Report
        update_scan_status(scan_id, 'running', 95, ScanPhase.REPORTING.value)
        generate_report(scan_id)
        
        # Complete
        update_scan_status(scan_id, 'completed', 100, ScanPhase.COMPLETED.value)
        logger.info("Scan completed successfully", scan_id=scan_id)
        
        return {'status': 'completed', 'scan_id': scan_id}
        
    except SoftTimeLimitExceeded:
        logger.error("Scan timed out", scan_id=scan_id)
        update_scan_status(scan_id, 'failed', 0, error="Scan timed out")
        return {'error': 'Scan timed out'}
        
    except Exception as e:
        logger.error("Scan failed", scan_id=scan_id, error=str(e))
        update_scan_status(scan_id, 'failed', 0, error=str(e))
        return {'error': str(e)}


# =============================================================================
# TOOL EXECUTION FUNCTIONS
# =============================================================================
def run_nmap_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Nmap port and service discovery"""
    logger.info("Running Nmap scan", target=context.target)
    
    output_file = f"{context.results_dir}/nmap.xml"
    
    # Nmap command - service version detection, default scripts, top 1000 ports
    nmap_cmd = [
        'nmap', '-sV', '-sC', '--top-ports', '1000',
        '-oX', output_file,
        '--max-retries', '2',
        '--host-timeout', '600s',
        context.target
    ]
    
    result = run_docker_command('noovastack-nmap', nmap_cmd, timeout=900)
    
    if not result['success']:
        return {'error': result['stderr']}
    
    # Parse Nmap XML output
    try:
        with open(output_file, 'r') as f:
            nmap_data = xmltodict.parse(f.read())
        
        open_ports = []
        services = {}
        
        host = nmap_data.get('nmaprun', {}).get('host', {})
        ports_data = host.get('ports', {}).get('port', [])
        
        if isinstance(ports_data, dict):
            ports_data = [ports_data]
        
        for port in ports_data:
            if port.get('state', {}).get('@state') == 'open':
                port_num = int(port.get('@portid'))
                open_ports.append(port_num)
                service = port.get('service', {})
                services[port_num] = service.get('@name', 'unknown')
        
        return {
            'open_ports': open_ports,
            'services': services,
            'raw_output': result['stdout']
        }
        
    except Exception as e:
        return {'error': f'Failed to parse Nmap output: {str(e)}'}


def run_openvas_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute OpenVAS vulnerability scan"""
    logger.info("Running OpenVAS scan", target=context.target)
    
    # OpenVAS is complex - using GVM-tools for API interaction
    # This is simplified; production would use gvm-tools Python library
    
    try:
        from gvm.connections import UnixSocketConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform
        
        # Connect to OpenVAS
        connection = UnixSocketConnection(path='/var/run/gvmd/gvmd.sock')
        transform = EtreeTransform()
        
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(
                os.environ.get('OPENVAS_USER', 'admin'),
                os.environ.get('OPENVAS_PASSWORD', 'admin')
            )
            
            # Create target
            target_id = gmp.create_target(
                name=f"noovastack-{context.scan_id}",
                hosts=[context.target],
                port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # All IANA assigned TCP
            )
            
            # Get "Full and Fast" scan config
            config_id = "daba56c8-73ec-11df-a475-002264764cea"
            
            # Create and start task
            task_id = gmp.create_task(
                name=f"scan-{context.scan_id}",
                config_id=config_id,
                target_id=target_id,
                scanner_id="08b69003-5fc2-4037-a479-93b440211c73"
            )
            
            gmp.start_task(task_id)
            
            # Poll for completion (with timeout)
            timeout = 3600  # 1 hour max for OpenVAS
            start = time.time()
            
            while time.time() - start < timeout:
                task = gmp.get_task(task_id)
                status = task.find('.//status').text
                
                if status == 'Done':
                    break
                elif status in ['Stop Requested', 'Stopped']:
                    return {'error': 'OpenVAS scan stopped'}
                
                time.sleep(30)
            
            # Get results
            report_id = task.find('.//last_report/report').get('id')
            report = gmp.get_report(report_id)
            
            # Parse findings
            findings = []
            for result in report.findall('.//result'):
                severity = float(result.find('severity').text or 0)
                
                findings.append({
                    'title': result.find('name').text,
                    'description': result.find('description').text,
                    'severity': categorize_cvss(severity),
                    'cvss_score': severity,
                    'affected_port': result.find('port').text,
                    'solution': result.find('solution').text,
                    'cve_id': extract_cve(result.find('nvt/cve').text),
                    'tool_name': 'openvas'
                })
            
            return {'findings': findings}
            
    except Exception as e:
        logger.error("OpenVAS scan failed", error=str(e))
        return {'error': str(e), 'findings': []}


def run_nuclei_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Nuclei template-based vulnerability scan"""
    logger.info("Running Nuclei scan", target=context.target)
    
    output_file = f"{context.results_dir}/nuclei.json"
    
    # Build target URL if needed
    target = context.target
    if context.target_type == 'ip' and context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target = f"{scheme}://{context.target}:{port}"
    elif context.target_type == 'domain':
        target = f"https://{context.target}"
    
    nuclei_cmd = [
        'nuclei',
        '-u', target,
        '-severity', 'critical,high,medium',  # Skip low/info by default
        '-exclude-severity', 'info',
        '-json-export', output_file,
        '-silent',
        '-no-interactsh',  # No external callbacks for safety
        '-timeout', '10',
        '-retries', '2',
        '-rate-limit', '100',
    ]
    
    result = run_docker_command('noovastack-nuclei', nuclei_cmd, timeout=1800)
    
    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        findings.append({
                            'title': data.get('info', {}).get('name', 'Unknown'),
                            'description': data.get('info', {}).get('description', ''),
                            'severity': data.get('info', {}).get('severity', 'medium'),
                            'affected_url': data.get('matched-at', ''),
                            'cve_id': extract_cve_from_list(data.get('info', {}).get('classification', {}).get('cve-id', [])),
                            'cvss_score': data.get('info', {}).get('classification', {}).get('cvss-score'),
                            'solution': data.get('info', {}).get('remediation', ''),
                            'references': data.get('info', {}).get('reference', []),
                            'tool_name': 'nuclei',
                            'evidence': data.get('extracted-results', [])
                        })
    except Exception as e:
        logger.error("Failed to parse Nuclei output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_zap_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute OWASP ZAP web application scan"""
    logger.info("Running ZAP scan", target=context.target)
    
    try:
        from zapv2 import ZAPv2
        
        zap = ZAPv2(
            apikey=os.environ.get('ZAP_API_KEY', ''),
            proxies={
                'http': f"http://{os.environ.get('ZAP_HOST', 'zap')}:{os.environ.get('ZAP_PORT', '8080')}",
                'https': f"http://{os.environ.get('ZAP_HOST', 'zap')}:{os.environ.get('ZAP_PORT', '8080')}"
            }
        )
        
        # Build target URL
        if context.target_type == 'url':
            target_url = context.target
        elif context.web_ports:
            port = context.web_ports[0]
            scheme = 'https' if port == 443 else 'http'
            target_url = f"{scheme}://{context.target}"
        else:
            target_url = f"http://{context.target}"
        
        # Spider the target (limited depth)
        zap.spider.scan(target_url, maxchildren=10, recurse=True, subtreeonly=True)
        
        # Wait for spider to complete
        while int(zap.spider.status()) < 100:
            time.sleep(5)
        
        # Active scan
        scan_id = zap.ascan.scan(target_url, recurse=True, inscopeonly=True)
        
        # Wait for active scan (with timeout)
        timeout = 1800  # 30 minutes
        start = time.time()
        
        while int(zap.ascan.status(scan_id)) < 100:
            if time.time() - start > timeout:
                zap.ascan.stop(scan_id)
                break
            time.sleep(10)
        
        # Get alerts
        alerts = zap.core.alerts(baseurl=target_url)
        
        findings = []
        for alert in alerts:
            findings.append({
                'title': alert.get('name', ''),
                'description': alert.get('description', ''),
                'severity': map_zap_risk(alert.get('risk', '')),
                'affected_url': alert.get('url', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'references': [alert.get('reference', '')] if alert.get('reference') else [],
                'cve_id': extract_cve(alert.get('reference', '')),
                'tool_name': 'zap'
            })
        
        return {'findings': findings}
        
    except Exception as e:
        logger.error("ZAP scan failed", error=str(e))
        return {'error': str(e), 'findings': []}


def run_nikto_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Nikto web server scan"""
    logger.info("Running Nikto scan", target=context.target)
    
    output_file = f"{context.results_dir}/nikto.json"
    
    # Build target
    if context.web_ports:
        port = context.web_ports[0]
        target = f"{context.target}:{port}"
    else:
        target = context.target
    
    nikto_cmd = [
        'nikto',
        '-h', target,
        '-Format', 'json',
        '-output', output_file,
        '-Tuning', '123457',  # Skip DOS, heavy tests
        '-timeout', '10',
        '-maxtime', '900s'
    ]
    
    result = run_docker_command('noovastack-nikto', nikto_cmd, timeout=1200)
    
    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                nikto_data = json.load(f)
            
            for vuln in nikto_data.get('vulnerabilities', []):
                findings.append({
                    'title': vuln.get('msg', 'Unknown'),
                    'description': vuln.get('msg', ''),
                    'severity': map_osvdb_severity(vuln.get('OSVDB', '')),
                    'affected_url': vuln.get('url', ''),
                    'tool_name': 'nikto',
                    'references': [f"OSVDB-{vuln.get('OSVDB', '')}"] if vuln.get('OSVDB') else []
                })
    except Exception as e:
        logger.error("Failed to parse Nikto output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_sqlmap_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute SQLmap SQL injection scan (conservative mode)"""
    logger.info("Running SQLmap scan", target=context.target)
    
    output_dir = f"{context.results_dir}/sqlmap"
    os.makedirs(output_dir, exist_ok=True)
    
    # Build target URL
    if context.target_type == 'url':
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}"
    else:
        return {'findings': [], 'message': 'No web target for SQLmap'}
    
    sqlmap_cmd = [
        'sqlmap',
        '-u', target_url,
        '--batch',  # Non-interactive
        '--level=1',  # Low intrusiveness
        '--risk=1',  # Low risk
        '--crawl=2',  # Limited crawling
        '--forms',  # Test forms
        '--output-dir', output_dir,
        '--timeout=10',
        '--retries=1',
        '--smart',  # Smart mode
    ]
    
    result = run_docker_command('noovastack-sqlmap', sqlmap_cmd, timeout=1800)
    
    findings = []
    
    # Parse SQLmap output for findings
    if 'is vulnerable' in result.get('stdout', '').lower():
        findings.append({
            'title': 'SQL Injection Vulnerability',
            'description': 'SQLmap detected a potential SQL injection vulnerability.',
            'severity': 'critical',
            'affected_url': target_url,
            'tool_name': 'sqlmap',
            'evidence': result.get('stdout', '')[-2000:]  # Last 2000 chars
        })
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


# =============================================================================
# DYNAMIC WEB SCANNING TOOL FUNCTIONS
# =============================================================================

def run_wapiti_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Wapiti web application vulnerability scan"""
    logger.info("Running Wapiti scan", target=context.target)

    if context.target.startswith('http'):
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}:{port}"
    else:
        return {'findings': [], 'message': 'No web target for Wapiti'}

    output_file = f"{context.results_dir}/wapiti.json"

    wapiti_cmd = [
        'wapiti',
        '-u', target_url,
        '-f', 'json',
        '-o', output_file,
        '--scope', 'domain',
        '--max-links-per-page', '50',
        '--max-scan-time', '600',
        '--flush-session',
    ]

    result = run_docker_command('noovastack-wapiti', wapiti_cmd, timeout=720)

    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                wapiti_data = json.load(f)
            vuln_map = {
                'Blind SQL Injection': ('critical', 'sqli'),
                'SQL Injection': ('critical', 'sqli'),
                'Cross Site Scripting': ('high', 'xss'),
                'Reflected Cross Site Scripting': ('high', 'xss'),
                'Stored Cross Site Scripting': ('high', 'xss'),
                'Command execution': ('critical', 'cmdi'),
                'Path Traversal': ('high', 'path_traversal'),
                'Open Redirect': ('medium', 'redirect'),
                'CSRF': ('medium', 'csrf'),
                'SSRF': ('high', 'ssrf'),
                'XXE': ('high', 'xxe'),
                'HTTP Header Injection': ('medium', 'header_injection'),
                'Backup file': ('low', 'info_disclosure'),
            }
            for vuln_name, vuln_list in wapiti_data.get('vulnerabilities', {}).items():
                severity, category = vuln_map.get(vuln_name, ('medium', 'web'))
                for vuln in vuln_list:
                    findings.append({
                        'title': vuln_name,
                        'description': vuln.get('info', vuln_name),
                        'severity': severity,
                        'affected_url': vuln.get('path', target_url),
                        'tool_name': 'wapiti',
                        'evidence': vuln.get('curl_command', ''),
                        'category': category,
                    })
    except Exception as e:
        logger.error("Failed to parse Wapiti output", error=str(e))

    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_dalfox_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Dalfox XSS parameter scanning"""
    logger.info("Running Dalfox scan", target=context.target)

    if context.target.startswith('http'):
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}:{port}"
    else:
        return {'findings': [], 'message': 'No web target for Dalfox'}

    output_file = f"{context.results_dir}/dalfox.json"

    dalfox_cmd = [
        'dalfox', 'url', target_url,
        '--format', 'json',
        '--output', output_file,
        '--silence',
        '--timeout', '30',
        '--delay', '200',
        '--follow-redirects',
    ]

    result = run_docker_command('noovastack-dalfox', dalfox_cmd, timeout=600)

    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        findings.append({
                            'title': 'Cross-Site Scripting (XSS)',
                            'description': item.get('message', 'Dalfox detected an XSS vulnerability.'),
                            'severity': 'high',
                            'affected_url': item.get('data', target_url),
                            'tool_name': 'dalfox',
                            'evidence': item.get('param', ''),
                            'category': 'xss',
                        })
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        logger.error("Failed to parse Dalfox output", error=str(e))

    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_feroxbuster_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Feroxbuster content discovery scan"""
    logger.info("Running Feroxbuster scan", target=context.target)

    if context.target.startswith('http'):
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}:{port}"
    else:
        return {'findings': [], 'message': 'No web target for Feroxbuster'}

    output_file = f"{context.results_dir}/feroxbuster.json"

    feroxbuster_cmd = [
        'feroxbuster',
        '--url', target_url,
        '--wordlist', '/wordlists/api-endpoints.txt',
        '--output', output_file,
        '--json',
        '--silent',
        '--timeout', '10',
        '--rate-limit', '50',
        '--depth', '2',
        '--threads', '10',
        '--no-recursion',
    ]

    result = run_docker_command('noovastack-feroxbuster', feroxbuster_cmd, timeout=600)

    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        if item.get('type') == 'response':
                            status = item.get('status', 0)
                            url = item.get('url', '')
                            # Flag sensitive endpoints
                            sensitive_patterns = [
                                'admin', 'backup', 'config', '.env', 'debug',
                                'swagger', 'api-docs', 'phpinfo', 'actuator',
                            ]
                            if any(p in url.lower() for p in sensitive_patterns):
                                findings.append({
                                    'title': f'Sensitive Endpoint Discovered: {url}',
                                    'description': f'Feroxbuster found an accessible endpoint that may expose sensitive functionality. HTTP {status}.',
                                    'severity': 'medium' if status == 200 else 'low',
                                    'affected_url': url,
                                    'tool_name': 'feroxbuster',
                                    'evidence': f'HTTP {status} - {url}',
                                    'category': 'info_disclosure',
                                })
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        logger.error("Failed to parse Feroxbuster output", error=str(e))

    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_commix_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Commix OS command injection testing"""
    logger.info("Running Commix scan", target=context.target)

    if context.target.startswith('http'):
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}:{port}"
    else:
        return {'findings': [], 'message': 'No web target for Commix'}

    output_file = f"{context.results_dir}/commix.log"

    commix_cmd = [
        'python3', '/opt/commix/commix.py',
        '--url', target_url,
        '--batch',
        '--crawl=1',
        '--output-dir', context.results_dir,
        '--timeout=15',
        '--retries=1',
    ]

    result = run_docker_command('noovastack-commix', commix_cmd, timeout=600)

    findings = []
    stdout = result.get('stdout', '')
    if 'is vulnerable' in stdout.lower() or 'backdoor' in stdout.lower():
        findings.append({
            'title': 'OS Command Injection Vulnerability',
            'description': 'Commix detected a potential OS command injection vulnerability. An attacker may be able to execute arbitrary system commands.',
            'severity': 'critical',
            'affected_url': target_url,
            'tool_name': 'commix',
            'evidence': stdout[-2000:],
            'category': 'cmdi',
        })

    return {'findings': findings, 'raw_output': stdout}


def run_cmseek_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute CMSeeK CMS detection and vulnerability analysis"""
    logger.info("Running CMSeeK scan", target=context.target)

    if context.target.startswith('http'):
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}:{port}"
    else:
        return {'findings': [], 'message': 'No web target for CMSeeK'}

    results_dir = f"{context.results_dir}/cmseek"

    cmseek_cmd = [
        'python3', '/opt/cmseek/cmseek.py',
        '-u', target_url,
        '--batch',
        '--follow-redirect',
        '--output-json', results_dir,
    ]

    result = run_docker_command('noovastack-cmseek', cmseek_cmd, timeout=300)

    findings = []
    try:
        result_file = os.path.join(results_dir, 'cms.json')
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                cms_data = json.load(f)

            cms_id = cms_data.get('cms_id', 'unknown')
            cms_name = cms_data.get('cms_name', cms_id)

            if cms_id and cms_id != 'unknown':
                findings.append({
                    'title': f'CMS Detected: {cms_name}',
                    'description': f'CMSeeK identified {cms_name} as the content management system. Version: {cms_data.get("cms_version", "unknown")}.',
                    'severity': 'info',
                    'affected_url': target_url,
                    'tool_name': 'cmseek',
                    'evidence': json.dumps(cms_data, indent=2)[:1000],
                    'category': 'info_disclosure',
                })

            for vuln in cms_data.get('vulnerabilities', []):
                findings.append({
                    'title': vuln.get('name', 'CMS Vulnerability'),
                    'description': vuln.get('description', ''),
                    'severity': vuln.get('severity', 'medium').lower(),
                    'affected_url': target_url,
                    'tool_name': 'cmseek',
                    'cve_id': vuln.get('cve'),
                    'category': 'cms_vuln',
                })
    except Exception as e:
        logger.error("Failed to parse CMSeeK output", error=str(e))

    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_sniper_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Sn1per automated recon and attack framework"""
    logger.info("Running Sn1per scan", target=context.target)

    # Determine target (hostname/IP only, no scheme)
    target = context.target
    if target.startswith('http://') or target.startswith('https://'):
        from urllib.parse import urlparse
        target = urlparse(target).hostname or context.target

    output_dir = f"{context.results_dir}/sniper"

    sniper_cmd = [
        'sniper',
        '-t', target,
        '-m', 'web',       # Web mode — web-focused recon
        '-o', '-x',        # Output to file, non-interactive
    ]

    result = run_docker_command('noovastack-sniper', sniper_cmd, timeout=900)

    findings = []
    stdout = result.get('stdout', '')

    # Parse key finding indicators from Sn1per output
    import re
    vuln_patterns = [
        (r'\[VULN\]\s+(.+)', 'high', 'vulnerability'),
        (r'\[HIGH\]\s+(.+)', 'high', 'vulnerability'),
        (r'\[MEDIUM\]\s+(.+)', 'medium', 'vulnerability'),
        (r'\[LOW\]\s+(.+)', 'low', 'vulnerability'),
        (r'CVE-\d{4}-\d+', 'medium', 'cve'),
    ]
    for pattern, severity, category in vuln_patterns:
        for match in re.finditer(pattern, stdout, re.IGNORECASE):
            findings.append({
                'title': f'Sn1per Finding: {match.group(0)[:120]}',
                'description': match.group(0),
                'severity': severity,
                'affected_url': target,
                'tool_name': 'sniper',
                'evidence': match.group(0),
                'category': category,
            })

    return {'findings': findings, 'raw_output': stdout}


# =============================================================================
# CONTAINER SECURITY TOOL FUNCTIONS
# =============================================================================
def run_docker_bench_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Docker Bench Security CIS benchmark"""
    logger.info("Running Docker Bench scan")
    
    output_file = f"{context.results_dir}/docker_bench.json"
    
    docker_bench_cmd = [
        'docker-bench-security.sh',
        '-b',  # Batch mode
        '-l', output_file
    ]
    
    result = run_docker_command('noovastack-docker-bench', docker_bench_cmd, timeout=600)
    
    findings = []
    try:
        # Parse Docker Bench output (typically log format)
        output = result.get('stdout', '')
        
        # Extract WARN and FAIL checks
        import re
        warn_pattern = r'\[WARN\] ([\d\.]+) - (.+)'
        fail_pattern = r'\[FAIL\] ([\d\.]+) - (.+)'
        
        for match in re.finditer(warn_pattern, output):
            findings.append({
                'title': f"Docker CIS {match.group(1)}: {match.group(2)[:100]}",
                'description': match.group(2),
                'severity': 'medium',
                'affected_component': 'Docker Host',
                'tool_name': 'docker_bench',
                'evidence': match.group(0)
            })
        
        for match in re.finditer(fail_pattern, output):
            findings.append({
                'title': f"Docker CIS {match.group(1)}: {match.group(2)[:100]}",
                'description': match.group(2),
                'severity': 'high',
                'affected_component': 'Docker Host',
                'tool_name': 'docker_bench',
                'evidence': match.group(0)
            })
            
    except Exception as e:
        logger.error("Failed to parse Docker Bench output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_clair_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Clair container vulnerability analysis"""
    logger.info("Running Clair scan", target=context.target)
    
    output_file = f"{context.results_dir}/clair.json"
    
    # Using clairctl for Clair v4
    clair_cmd = [
        'clairctl', 'report',
        '--host', os.environ.get('CLAIR_HOST', 'clair:6060'),
        '--out', 'json',
        context.target
    ]
    
    result = run_docker_command('noovastack-clair', clair_cmd, timeout=600)
    
    findings = []
    try:
        if result.get('stdout'):
            clair_data = json.loads(result.get('stdout', '{}'))
            
            for vuln in clair_data.get('vulnerabilities', []):
                findings.append({
                    'title': f"{vuln.get('name', 'Unknown')}: {vuln.get('package', '')}",
                    'description': vuln.get('description', ''),
                    'severity': vuln.get('severity', 'medium').lower(),
                    'cve_id': vuln.get('name'),
                    'affected_component': vuln.get('package', ''),
                    'solution': vuln.get('fixedby', 'No fix available'),
                    'references': [vuln.get('link', '')] if vuln.get('link') else [],
                    'tool_name': 'clair'
                })
    except Exception as e:
        logger.error("Failed to parse Clair output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_falco_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Falco runtime security monitoring (collect events)"""
    logger.info("Running Falco monitoring")
    
    # Falco runs as a daemon; this collects recent events
    falco_cmd = [
        'falco',
        '--dry-run',  # Validation mode
        '-o', 'json_output=true',
        '-o', 'stdout_output.enabled=true'
    ]
    
    result = run_docker_command('noovastack-falco', falco_cmd, timeout=120)
    
    findings = []
    try:
        # Parse Falco JSON events
        for line in result.get('stdout', '').split('\n'):
            if line.strip():
                try:
                    event = json.loads(line)
                    priority = event.get('priority', 'warning').lower()
                    severity_map = {'emergency': 'critical', 'alert': 'critical', 
                                   'critical': 'critical', 'error': 'high',
                                   'warning': 'medium', 'notice': 'low', 
                                   'info': 'info', 'debug': 'info'}
                    
                    findings.append({
                        'title': event.get('rule', 'Unknown Rule'),
                        'description': event.get('output', ''),
                        'severity': severity_map.get(priority, 'medium'),
                        'affected_component': event.get('output_fields', {}).get('container.name', ''),
                        'tool_name': 'falco',
                        'evidence': json.dumps(event.get('output_fields', {}))
                    })
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error("Failed to parse Falco output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


# =============================================================================
# CLOUD SECURITY TOOL FUNCTIONS
# =============================================================================
def run_scoutsuite_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute ScoutSuite multi-cloud security audit"""
    logger.info("Running ScoutSuite scan", target=context.target)
    
    output_dir = f"{context.results_dir}/scoutsuite"
    os.makedirs(output_dir, exist_ok=True)
    
    # Determine cloud provider from target or scan config
    provider = context.target.lower() if context.target in ['aws', 'azure', 'gcp'] else 'aws'
    
    scoutsuite_cmd = [
        'scout', provider,
        '--report-dir', output_dir,
        '--no-browser',
        '--result-format', 'json'
    ]
    
    result = run_docker_command('noovastack-scoutsuite', scoutsuite_cmd, timeout=3600)
    
    findings = []
    try:
        # Parse ScoutSuite JSON report
        report_file = f"{output_dir}/scoutsuite_results_{provider}.json"
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                scout_data = json.load(f)
            
            services = scout_data.get('services', {})
            for service_name, service_data in services.items():
                for finding_group, finding_items in service_data.get('findings', {}).items():
                    for item_id, item_data in finding_items.get('items', {}).items():
                        level = item_data.get('level', 'warning')
                        severity_map = {'danger': 'high', 'warning': 'medium'}
                        
                        findings.append({
                            'title': f"{service_name.upper()}: {finding_group}",
                            'description': item_data.get('description', ''),
                            'severity': severity_map.get(level, 'medium'),
                            'affected_component': f"{provider.upper()}:{service_name}:{item_id}",
                            'tool_name': 'scoutsuite',
                            'references': [item_data.get('rationale', '')]
                        })
    except Exception as e:
        logger.error("Failed to parse ScoutSuite output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_prowler_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Prowler AWS security assessment"""
    logger.info("Running Prowler scan")
    
    output_file = f"{context.results_dir}/prowler.json"
    
    prowler_cmd = [
        'prowler', 'aws',
        '-M', 'json',
        '-o', context.results_dir,
        '-F', 'prowler',
        '--severity', 'critical,high,medium'
    ]
    
    result = run_docker_command('noovastack-prowler', prowler_cmd, timeout=3600)
    
    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        finding = json.loads(line)
                        if finding.get('Status') == 'FAIL':
                            findings.append({
                                'title': finding.get('CheckTitle', 'Unknown'),
                                'description': finding.get('StatusExtended', ''),
                                'severity': finding.get('Severity', 'medium').lower(),
                                'affected_component': finding.get('ResourceId', ''),
                                'solution': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                                'references': [finding.get('Remediation', {}).get('Recommendation', {}).get('Url', '')],
                                'tool_name': 'prowler',
                                'evidence': f"Region: {finding.get('Region', 'N/A')}, Account: {finding.get('AccountId', 'N/A')}"
                            })
    except Exception as e:
        logger.error("Failed to parse Prowler output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_checkov_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Checkov Infrastructure as Code scanning"""
    logger.info("Running Checkov scan", target=context.target)
    
    output_file = f"{context.results_dir}/checkov.json"
    
    checkov_cmd = [
        'checkov',
        '-d', context.target,  # Directory with IaC files
        '-o', 'json',
        '--output-file-path', context.results_dir,
        '--compact'
    ]
    
    result = run_docker_command('noovastack-checkov', checkov_cmd, timeout=1800)
    
    findings = []
    try:
        checkov_file = f"{context.results_dir}/results_json.json"
        if os.path.exists(checkov_file):
            with open(checkov_file, 'r') as f:
                checkov_data = json.load(f)
            
            for check_type in checkov_data.get('results', {}).get('failed_checks', []):
                severity_map = {'CRITICAL': 'critical', 'HIGH': 'high', 
                               'MEDIUM': 'medium', 'LOW': 'low'}
                
                findings.append({
                    'title': f"{check_type.get('check_id', 'Unknown')}: {check_type.get('check_name', '')}",
                    'description': check_type.get('description', check_type.get('check_name', '')),
                    'severity': severity_map.get(check_type.get('severity', 'MEDIUM'), 'medium'),
                    'affected_component': f"{check_type.get('file_path', '')}:{check_type.get('resource', '')}",
                    'solution': check_type.get('guideline', ''),
                    'tool_name': 'checkov',
                    'evidence': f"Line: {check_type.get('file_line_range', [])}"
                })
    except Exception as e:
        logger.error("Failed to parse Checkov output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_terrascan_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Terrascan IaC policy enforcement"""
    logger.info("Running Terrascan scan", target=context.target)
    
    output_file = f"{context.results_dir}/terrascan.json"
    
    terrascan_cmd = [
        'terrascan', 'scan',
        '-d', context.target,
        '-o', 'json',
        '--output', output_file
    ]
    
    result = run_docker_command('noovastack-terrascan', terrascan_cmd, timeout=1800)
    
    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                terrascan_data = json.load(f)
            
            for violation in terrascan_data.get('results', {}).get('violations', []):
                severity_map = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
                
                findings.append({
                    'title': f"{violation.get('rule_id', 'Unknown')}: {violation.get('rule_name', '')}",
                    'description': violation.get('description', ''),
                    'severity': severity_map.get(violation.get('severity', 'MEDIUM'), 'medium'),
                    'affected_component': f"{violation.get('file', '')}:{violation.get('resource_name', '')}",
                    'solution': violation.get('remediation', ''),
                    'references': [violation.get('reference_id', '')],
                    'tool_name': 'terrascan'
                })
    except Exception as e:
        logger.error("Failed to parse Terrascan output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


# =============================================================================
# KUBERNETES SECURITY TOOL FUNCTIONS
# =============================================================================
def run_kube_hunter_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Kube-hunter Kubernetes penetration testing"""
    logger.info("Running Kube-hunter scan", target=context.target)
    
    output_file = f"{context.results_dir}/kube_hunter.json"
    
    kube_hunter_cmd = [
        'kube-hunter',
        '--remote', context.target,
        '--report', 'json',
        '--log', 'none'
    ]
    
    result = run_docker_command('noovastack-kube-hunter', kube_hunter_cmd, timeout=900)
    
    findings = []
    try:
        if result.get('stdout'):
            kh_data = json.loads(result.get('stdout', '{}'))
            
            for vuln in kh_data.get('vulnerabilities', []):
                severity_map = {'critical': 'critical', 'high': 'high', 
                               'medium': 'medium', 'low': 'low'}
                
                findings.append({
                    'title': vuln.get('vulnerability', 'Unknown'),
                    'description': vuln.get('description', ''),
                    'severity': severity_map.get(vuln.get('severity', 'medium').lower(), 'medium'),
                    'affected_component': vuln.get('location', ''),
                    'evidence': vuln.get('evidence', ''),
                    'tool_name': 'kube_hunter',
                    'references': [vuln.get('reference', '')] if vuln.get('reference') else []
                })
    except Exception as e:
        logger.error("Failed to parse Kube-hunter output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_kube_bench_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Kube-bench CIS Kubernetes benchmark"""
    logger.info("Running Kube-bench scan")
    
    kube_bench_cmd = [
        'kube-bench', 'run',
        '--json'
    ]
    
    result = run_docker_command('noovastack-kube-bench', kube_bench_cmd, timeout=600)
    
    findings = []
    try:
        if result.get('stdout'):
            kb_data = json.loads(result.get('stdout', '{}'))
            
            for control in kb_data.get('Controls', []):
                for test in control.get('tests', []):
                    for result_item in test.get('results', []):
                        if result_item.get('status') in ['FAIL', 'WARN']:
                            severity = 'high' if result_item.get('status') == 'FAIL' else 'medium'
                            
                            findings.append({
                                'title': f"CIS K8s {result_item.get('test_number', '')}: {result_item.get('test_desc', '')[:100]}",
                                'description': result_item.get('test_desc', ''),
                                'severity': severity,
                                'affected_component': f"{control.get('node_type', '')} - {test.get('section', '')}",
                                'solution': result_item.get('remediation', ''),
                                'tool_name': 'kube_bench',
                                'evidence': f"Reason: {result_item.get('reason', 'N/A')}"
                            })
    except Exception as e:
        logger.error("Failed to parse Kube-bench output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


# =============================================================================
# API SECURITY TOOL FUNCTIONS
# =============================================================================
def run_arjun_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Arjun HTTP parameter discovery"""
    logger.info("Running Arjun scan", target=context.target)
    
    output_file = f"{context.results_dir}/arjun.json"
    
    # Build target URL
    if context.target_type == 'url':
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}"
    else:
        target_url = f"http://{context.target}"
    
    arjun_cmd = [
        'arjun',
        '-u', target_url,
        '-oJ', output_file,
        '-t', '10',  # threads
        '--stable',
    ]
    
    result = run_docker_command('noovastack-arjun', arjun_cmd, timeout=900)
    
    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                arjun_data = json.load(f)
            
            for url, params in arjun_data.items():
                if params:
                    findings.append({
                        'title': f'Hidden Parameters Discovered: {len(params)} parameters',
                        'description': f'Arjun discovered {len(params)} hidden HTTP parameters: {', '.join(params[:10])}{'...' if len(params) > 10 else ''}',
                        'severity': 'info',
                        'affected_url': url,
                        'tool_name': 'arjun',
                        'evidence': json.dumps(params)
                    })
    except Exception as e:
        logger.error("Failed to parse Arjun output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_graphqlmap_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute GraphQLmap GraphQL security testing"""
    logger.info("Running GraphQLmap scan", target=context.target)
    
    output_file = f"{context.results_dir}/graphqlmap.txt"
    
    # Build target URL (expects GraphQL endpoint)
    if context.target_type == 'url':
        target_url = context.target
    else:
        target_url = f"http://{context.target}/graphql"
    
    graphql_cmd = [
        'python3', '/opt/GraphQLmap/graphqlmap.py',
        '-u', target_url,
        '--method', 'POST',
        '--dump'
    ]
    
    result = run_docker_command('noovastack-graphqlmap', graphql_cmd, timeout=600)
    
    findings = []
    output = result.get('stdout', '')
    
    # Parse GraphQLmap output for security issues
    if 'introspection' in output.lower():
        findings.append({
            'title': 'GraphQL Introspection Enabled',
            'description': 'GraphQL introspection is enabled, exposing the full API schema.',
            'severity': 'medium',
            'affected_url': target_url,
            'tool_name': 'graphqlmap',
            'solution': 'Disable introspection in production environments.'
        })
    
    if 'mutation' in output.lower() and 'create' in output.lower():
        findings.append({
            'title': 'GraphQL Mutations Exposed',
            'description': 'Potentially sensitive mutations are exposed via GraphQL schema.',
            'severity': 'medium',
            'affected_url': target_url,
            'tool_name': 'graphqlmap'
        })
    
    if 'error' not in output.lower() and 'data' in output.lower():
        findings.append({
            'title': 'GraphQL Endpoint Accessible',
            'description': 'GraphQL endpoint is accessible and responding to queries.',
            'severity': 'info',
            'affected_url': target_url,
            'tool_name': 'graphqlmap'
        })
    
    return {'findings': findings, 'raw_output': output}


def run_jwt_tool_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute JWT_Tool JWT analysis"""
    logger.info("Running JWT_Tool scan")
    
    # JWT token should be provided in context or extracted from target
    jwt_token = context.discovered_services.get('jwt_token', '')
    
    if not jwt_token:
        return {'findings': [], 'message': 'No JWT token provided for analysis'}
    
    jwt_cmd = [
        'python3', '/opt/jwt_tool/jwt_tool.py',
        jwt_token,
        '-a',  # All tests
        '-X', 'n',  # No exploit attempts (safe mode)
    ]
    
    result = run_docker_command('noovastack-jwt-tool', jwt_cmd, timeout=300)
    
    findings = []
    output = result.get('stdout', '')
    
    # Parse JWT_Tool output
    if 'alg' in output.lower() and 'none' in output.lower():
        findings.append({
            'title': 'JWT Algorithm None Attack Possible',
            'description': 'JWT token may be vulnerable to algorithm none attack.',
            'severity': 'critical',
            'tool_name': 'jwt_tool',
            'evidence': 'Algorithm: none detected in JWT header'
        })
    
    if 'expired' not in output.lower() and 'exp' in output.lower():
        findings.append({
            'title': 'JWT Token Expiration Analysis',
            'description': 'JWT token expiration claims analyzed.',
            'severity': 'info',
            'tool_name': 'jwt_tool'
        })
    
    if 'weak' in output.lower() or 'crack' in output.lower():
        findings.append({
            'title': 'Potential Weak JWT Secret',
            'description': 'JWT secret may be weak and susceptible to brute-force attacks.',
            'severity': 'high',
            'tool_name': 'jwt_tool'
        })
    
    return {'findings': findings, 'raw_output': output}


def run_wfuzz_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute wfuzz API endpoint fuzzing"""
    logger.info("Running wfuzz scan", target=context.target)
    
    output_file = f"{context.results_dir}/wfuzz.json"
    
    # Build target URL
    if context.target_type == 'url':
        target_url = context.target
    elif context.web_ports:
        port = context.web_ports[0]
        scheme = 'https' if port == 443 else 'http'
        target_url = f"{scheme}://{context.target}/FUZZ"
    else:
        target_url = f"http://{context.target}/FUZZ"
    
    wfuzz_cmd = [
        'wfuzz',
        '-c',  # Color output
        '-z', 'file,/wordlists/api-endpoints.txt',
        '--hc', '404,403',  # Hide 404/403
        '-f', f'{output_file},json',
        target_url
    ]
    
    result = run_docker_command('noovastack-wfuzz', wfuzz_cmd, timeout=1200)
    
    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                wfuzz_data = json.load(f)
            
            for item in wfuzz_data:
                if item.get('code', 0) in [200, 201, 301, 302]:
                    findings.append({
                        'title': f"API Endpoint Discovered: {item.get('payload', '')}",
                        'description': f"Discovered endpoint responding with HTTP {item.get('code')}. Response size: {item.get('chars', 0)} chars.",
                        'severity': 'info',
                        'affected_url': target_url.replace('FUZZ', item.get('payload', '')),
                        'tool_name': 'wfuzz',
                        'evidence': f"Status: {item.get('code')}, Words: {item.get('words')}, Lines: {item.get('lines')}"
                    })
    except Exception as e:
        logger.error("Failed to parse wfuzz output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


def run_newman_scan(context: ScanContext) -> Dict[str, Any]:
    """Execute Newman API collection testing"""
    logger.info("Running Newman scan")
    
    output_file = f"{context.results_dir}/newman.json"
    collection_file = context.discovered_services.get('api_collection', '/collections/default.json')
    
    newman_cmd = [
        'newman', 'run',
        collection_file,
        '--reporters', 'json',
        '--reporter-json-export', output_file,
        '--timeout-request', '10000'
    ]
    
    # Add environment if specified
    env_file = context.discovered_services.get('api_environment')
    if env_file:
        newman_cmd.extend(['-e', env_file])
    
    result = run_docker_command('noovastack-newman', newman_cmd, timeout=900)
    
    findings = []
    try:
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                newman_data = json.load(f)
            
            run_data = newman_data.get('run', {})
            stats = run_data.get('stats', {})
            
            # Report on failed assertions
            failures = run_data.get('failures', [])
            for failure in failures:
                findings.append({
                    'title': f"API Test Failed: {failure.get('source', {}).get('name', 'Unknown')}",
                    'description': failure.get('error', {}).get('message', 'Test assertion failed'),
                    'severity': 'medium',
                    'affected_url': failure.get('source', {}).get('request', {}).get('url', {}).get('raw', ''),
                    'tool_name': 'newman',
                    'evidence': json.dumps(failure.get('error', {}))
                })
            
            # Summary finding
            if stats:
                findings.append({
                    'title': 'API Collection Test Summary',
                    'description': f"Executed {stats.get('requests', {}).get('total', 0)} requests. Passed: {stats.get('assertions', {}).get('passed', 0)}, Failed: {stats.get('assertions', {}).get('failed', 0)}",
                    'severity': 'info',
                    'tool_name': 'newman'
                })
    except Exception as e:
        logger.error("Failed to parse Newman output", error=str(e))
    
    return {'findings': findings, 'raw_output': result.get('stdout', '')}


# =============================================================================
# RESULT AGGREGATION
# =============================================================================
def save_tool_result(scan_id: str, tool_name: str, results: Dict[str, Any]):
    """Save tool execution results to database"""
    session = SessionLocal()
    try:
        from app.models.models import Scan, ToolResult
        
        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return
        
        tool_result = ToolResult(
            scan_id=scan.id,
            tool_name=tool_name,
            status='success' if not results.get('error') else 'failed',
            raw_output=results.get('raw_output', ''),
            parsed_output=results,
            findings_count=len(results.get('findings', [])),
            error_message=results.get('error'),
            completed_at=datetime.utcnow()
        )
        session.add(tool_result)
        session.commit()
        
    finally:
        session.close()


def aggregate_results(scan_id: str, context: ScanContext):
    """Aggregate and deduplicate findings from all tools"""
    session = SessionLocal()
    try:
        from app.models.models import Scan, ToolResult, Finding, Severity
        
        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return
        
        # Get all tool results
        tool_results = session.query(ToolResult).filter(ToolResult.scan_id == scan.id).all()
        
        # Collect all findings
        all_findings = []
        seen_fingerprints = set()
        
        for result in tool_results:
            if result.parsed_output and 'findings' in result.parsed_output:
                for finding_data in result.parsed_output['findings']:
                    fingerprint = generate_finding_fingerprint(finding_data)
                    
                    # Deduplicate
                    if fingerprint in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fingerprint)
                    
                    # Normalize severity
                    severity_str = str(finding_data.get('severity', 'info')).lower()
                    if severity_str in ['critical', 'high', 'medium', 'low', 'info']:
                        severity = Severity(severity_str)
                    else:
                        severity = Severity.INFO
                    
                    finding = Finding(
                        scan_id=scan.id,
                        title=finding_data.get('title', 'Unknown')[:500],
                        description=finding_data.get('description'),
                        severity=severity,
                        cve_id=finding_data.get('cve_id'),
                        cvss_score=finding_data.get('cvss_score'),
                        cvss_vector=finding_data.get('cvss_vector'),
                        affected_component=finding_data.get('affected_component'),
                        affected_port=finding_data.get('affected_port'),
                        affected_service=finding_data.get('affected_service'),
                        affected_url=finding_data.get('affected_url'),
                        evidence=str(finding_data.get('evidence', ''))[:5000],
                        solution=finding_data.get('solution'),
                        references=finding_data.get('references'),
                        tool_name=finding_data.get('tool_name'),
                        fingerprint=fingerprint
                    )
                    session.add(finding)
                    all_findings.append(finding)
        
        session.flush()
        
        # Update scan summary
        scan.total_findings = len(all_findings)
        scan.critical_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        scan.high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        scan.medium_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        scan.low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)
        scan.info_count = sum(1 for f in all_findings if f.severity == Severity.INFO)
        
        session.commit()
        
        logger.info(
            "Results aggregated",
            scan_id=scan_id,
            total=scan.total_findings,
            critical=scan.critical_count,
            high=scan.high_count
        )
        
    finally:
        session.close()


def generate_report(scan_id: str):
    """Generate PDF report for scan"""
    # This would use WeasyPrint or similar to generate PDF
    # Simplified implementation
    
    session = SessionLocal()
    try:
        from app.models.models import Scan
        
        scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            report_path = f"/app/reports/{scan_id}.pdf"
            scan.report_path = report_path
            session.commit()
            
            # TODO: Actual PDF generation with WeasyPrint
            logger.info("Report generated", scan_id=scan_id, path=report_path)
            
    finally:
        session.close()


# =============================================================================
# HELPER MAPPING FUNCTIONS
# =============================================================================
def categorize_cvss(score: float) -> str:
    """Map CVSS score to severity category"""
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    elif score >= 0.1:
        return 'low'
    return 'info'


def map_zap_risk(risk: str) -> str:
    """Map ZAP risk level to severity"""
    mapping = {
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low',
        'Informational': 'info'
    }
    return mapping.get(risk, 'info')


def map_osvdb_severity(osvdb: str) -> str:
    """Estimate severity from OSVDB reference"""
    # Simplified - in production, would query OSVDB/NVD
    return 'medium'


def extract_cve(text: str) -> Optional[str]:
    """Extract CVE ID from text"""
    import re
    if not text:
        return None
    match = re.search(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def extract_cve_from_list(cve_list: List[str]) -> Optional[str]:
    """Get first CVE from list"""
    if cve_list and len(cve_list) > 0:
        return cve_list[0]
    return None
