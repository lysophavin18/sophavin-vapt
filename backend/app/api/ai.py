"""
sophavin-VAPT AI API Endpoints
AI-powered analysis, chat, and assistance
"""

from typing import Dict, List, Optional, Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, Field
import structlog
import json

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User, Scan, Finding
from app.services.ai_service import ai_service, AIResponse

logger = structlog.get_logger()
router = APIRouter()


# =============================================================================
# SCHEMAS
# =============================================================================
class ChatMessage(BaseModel):
    """Chat message"""
    role: str = Field(..., pattern="^(user|assistant)$")
    content: str


class ChatRequest(BaseModel):
    """Chat request with history"""
    message: str = Field(..., min_length=1, max_length=10000)
    history: Optional[List[ChatMessage]] = None
    scan_id: Optional[str] = None  # Optional scan context
    provider: Optional[str] = None


class ChatResponse(BaseModel):
    """Chat response"""
    content: str
    model: str
    provider: str
    tokens_used: Optional[int] = None


class AnalyzeScanRequest(BaseModel):
    """Scan analysis request"""
    analysis_type: str = Field(default="scan_analysis")
    provider: Optional[str] = None


class RemediationRequest(BaseModel):
    """Remediation request"""
    finding_id: int
    context: Optional[str] = None
    provider: Optional[str] = None


class ReportSectionRequest(BaseModel):
    """Report section generation request"""
    scan_id: str
    section: str = Field(..., pattern="^(executive_summary|technical_details|risk_assessment|remediation_plan|compliance)$")
    provider: Optional[str] = None


class ThreatIntelRequest(BaseModel):
    """Threat intel analysis request"""
    scan_id: str
    provider: Optional[str] = None


class ProviderInfo(BaseModel):
    """AI provider info"""
    id: str
    name: str
    configured: bool
    default: bool


# =============================================================================
# ENDPOINTS
# =============================================================================
@router.get("/providers", response_model=List[ProviderInfo])
async def get_providers(current_user: User = Depends(get_current_user)):
    """Get available AI providers"""
    return ai_service.get_available_providers()


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Chat with AI assistant.
    Optionally provide scan_id for contextual assistance.
    """
    logger.info("AI chat request", user_id=current_user.id)
    
    context = None
    
    # Load scan context if provided
    if request.scan_id:
        result = await db.execute(
            select(Scan)
            .where(Scan.scan_id == request.scan_id)
            .options(selectinload(Scan.findings))
        )
        scan = result.scalar_one_or_none()
        
        if scan and (scan.user_id == current_user.id or current_user.role.value == "admin"):
            context = {
                "scan_id": scan.scan_id,
                "target": scan.target.value if scan.target else "Unknown",
                "scan_type": scan.scan_type.value,
                "status": scan.status.value,
                "total_findings": scan.total_findings,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "findings_sample": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "cve_id": f.cve_id
                    }
                    for f in (scan.findings or [])[:10]
                ]
            }
    
    try:
        history = [{"role": m.role, "content": m.content} for m in (request.history or [])]
        
        response = await ai_service.chat(
            user_message=request.message,
            history=history,
            context=context,
            provider=request.provider
        )
        
        return ChatResponse(
            content=response.content,
            model=response.model,
            provider=response.provider,
            tokens_used=response.tokens_used
        )
    except Exception as e:
        logger.error("AI chat failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"AI service error: {str(e)}")


@router.post("/chat/stream")
async def chat_stream(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Stream chat response from AI assistant.
    Returns Server-Sent Events (SSE).
    """
    logger.info("AI stream chat request", user_id=current_user.id)
    
    context = None
    if request.scan_id:
        result = await db.execute(
            select(Scan)
            .where(Scan.scan_id == request.scan_id)
            .options(selectinload(Scan.findings))
        )
        scan = result.scalar_one_or_none()
        
        if scan and (scan.user_id == current_user.id or current_user.role.value == "admin"):
            context = {
                "scan_id": scan.scan_id,
                "scan_type": scan.scan_type.value,
                "total_findings": scan.total_findings,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
            }
    
    async def generate():
        try:
            history = [{"role": m.role, "content": m.content} for m in (request.history or [])]
            
            async for chunk in ai_service.stream_chat(
                user_message=request.message,
                history=history,
                context=context,
                provider=request.provider
            ):
                yield f"data: {json.dumps({'content': chunk})}\n\n"
            
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )


@router.post("/analyze/{scan_id}", response_model=ChatResponse)
async def analyze_scan(
    scan_id: str,
    request: AnalyzeScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    AI-powered analysis of scan results.
    
    Analysis types:
    - scan_analysis: General vulnerability analysis (default)
    - remediation: Focus on fixes
    - threat_intel: Threat actor & ATT&CK mapping
    - report: Executive reporting style
    """
    logger.info("AI scan analysis", scan_id=scan_id, type=request.analysis_type)
    
    # Load scan with findings
    result = await db.execute(
        select(Scan)
        .where(Scan.scan_id == scan_id)
        .options(selectinload(Scan.findings), selectinload(Scan.target))
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_id != current_user.id and current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Prepare scan data
    scan_data = {
        "scan_id": scan.scan_id,
        "target": scan.target.value if scan.target else "Unknown",
        "scan_type": scan.scan_type.value,
        "status": scan.status.value,
        "completed_at": str(scan.completed_at) if scan.completed_at else None,
        "critical_count": scan.critical_count or 0,
        "high_count": scan.high_count or 0,
        "medium_count": scan.medium_count or 0,
        "low_count": scan.low_count or 0,
        "info_count": scan.info_count or 0,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "affected_component": f.affected_component,
                "description": f.description[:500] if f.description else None
            }
            for f in (scan.findings or [])
        ]
    }
    
    try:
        response = await ai_service.analyze_scan(
            scan_data=scan_data,
            analysis_type=request.analysis_type,
            provider=request.provider
        )
        
        return ChatResponse(
            content=response.content,
            model=response.model,
            provider=response.provider,
            tokens_used=response.tokens_used
        )
    except Exception as e:
        logger.error("AI analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"AI service error: {str(e)}")


@router.post("/remediation", response_model=ChatResponse)
async def get_remediation(
    request: RemediationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get AI-powered remediation guidance for a specific finding"""
    logger.info("AI remediation request", finding_id=request.finding_id)
    
    # Load finding
    result = await db.execute(
        select(Finding)
        .where(Finding.id == request.finding_id)
        .options(selectinload(Finding.scan))
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if finding.scan.user_id != current_user.id and current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    finding_data = {
        "title": finding.title,
        "severity": finding.severity.value,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "affected_component": finding.affected_component,
        "description": finding.description,
        "evidence": finding.evidence,
        "references": finding.references
    }
    
    try:
        response = await ai_service.get_remediation(
            finding=finding_data,
            context=request.context,
            provider=request.provider
        )
        
        return ChatResponse(
            content=response.content,
            model=response.model,
            provider=response.provider,
            tokens_used=response.tokens_used
        )
    except Exception as e:
        logger.error("AI remediation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"AI service error: {str(e)}")


@router.post("/report-section", response_model=ChatResponse)
async def generate_report_section(
    request: ReportSectionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate AI-powered report section"""
    logger.info("AI report section", scan_id=request.scan_id, section=request.section)
    
    # Load scan
    result = await db.execute(
        select(Scan)
        .where(Scan.scan_id == request.scan_id)
        .options(selectinload(Scan.findings), selectinload(Scan.target))
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_id != current_user.id and current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    scan_data = {
        "target": scan.target.value if scan.target else "Unknown",
        "scan_type": scan.scan_type.value,
        "completed_at": str(scan.completed_at) if scan.completed_at else None,
        "critical_count": scan.critical_count or 0,
        "high_count": scan.high_count or 0,
        "medium_count": scan.medium_count or 0,
        "low_count": scan.low_count or 0,
        "info_count": scan.info_count or 0,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "affected_component": f.affected_component
            }
            for f in (scan.findings or [])[:30]
        ]
    }
    
    try:
        response = await ai_service.generate_report_section(
            scan_data=scan_data,
            section=request.section,
            provider=request.provider
        )
        
        return ChatResponse(
            content=response.content,
            model=response.model,
            provider=response.provider,
            tokens_used=response.tokens_used
        )
    except Exception as e:
        logger.error("AI report generation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"AI service error: {str(e)}")


@router.post("/threat-intel", response_model=ChatResponse)
async def analyze_threat_intel(
    request: ThreatIntelRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get AI-powered threat intelligence analysis"""
    logger.info("AI threat intel", scan_id=request.scan_id)
    
    # Load findings
    result = await db.execute(
        select(Scan)
        .where(Scan.scan_id == request.scan_id)
        .options(selectinload(Scan.findings))
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_id != current_user.id and current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    findings_data = [
        {
            "title": f.title,
            "severity": f.severity.value,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "affected_component": f.affected_component
        }
        for f in (scan.findings or [])
        if f.severity.value in ['critical', 'high']
    ]
    
    try:
        response = await ai_service.analyze_threat_intel(
            findings=findings_data,
            provider=request.provider
        )
        
        return ChatResponse(
            content=response.content,
            model=response.model,
            provider=response.provider,
            tokens_used=response.tokens_used
        )
    except Exception as e:
        logger.error("AI threat intel failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"AI service error: {str(e)}")


@router.get("/quick-insights/{scan_id}")
async def get_quick_insights(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get quick AI-generated insights for a scan.
    Returns bullet-point summary without full analysis.
    """
    result = await db.execute(
        select(Scan)
        .where(Scan.scan_id == scan_id)
        .options(selectinload(Scan.findings), selectinload(Scan.target))
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_id != current_user.id and current_user.role.value != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Generate rule-based quick insights (no AI call for speed)
    insights = []
    
    critical = scan.critical_count or 0
    high = scan.high_count or 0
    medium = scan.medium_count or 0
    total = scan.total_findings or 0
    
    # Risk level
    if critical > 5:
        insights.append({"type": "critical", "text": f"Critical risk: {critical} critical vulnerabilities require immediate attention"})
    elif critical > 0:
        insights.append({"type": "high", "text": f"High risk: {critical} critical issue(s) found"})
    elif high > 10:
        insights.append({"type": "high", "text": f"Elevated risk: {high} high-severity vulnerabilities detected"})
    elif high > 0:
        insights.append({"type": "medium", "text": f"Moderate risk: {high} high-severity issue(s) found"})
    else:
        insights.append({"type": "low", "text": "Low risk: No critical or high-severity issues detected"})
    
    # Top concerns
    if scan.findings:
        cve_findings = [f for f in scan.findings if f.cve_id]
        if cve_findings:
            insights.append({
                "type": "info", 
                "text": f"{len(cve_findings)} findings have associated CVEs"
            })
        
        # Group by component
        components = {}
        for f in scan.findings:
            comp = f.affected_component or "Unknown"
            components[comp] = components.get(comp, 0) + 1
        
        if components:
            top_comp = max(components, key=components.get)
            insights.append({
                "type": "info",
                "text": f"Most affected component: {top_comp} ({components[top_comp]} findings)"
            })
    
    # Recommendations
    if critical + high > 0:
        insights.append({
            "type": "action",
            "text": "Use AI Analysis to get detailed remediation guidance"
        })
    
    return {
        "scan_id": scan_id,
        "target": scan.target.value if scan.target else "Unknown",
        "insights": insights,
        "summary": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium
        }
    }
