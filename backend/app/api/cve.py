"""
Noovastack-VAPT CVE API Endpoints
CVE lookup, enrichment, and threat intelligence
"""

from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import structlog

from app.core.security import get_current_user
from app.models.models import User
from app.services.cve_service import cve_service, CVEInfo

logger = structlog.get_logger()
router = APIRouter()


# =============================================================================
# SCHEMAS
# =============================================================================
class CVEResponse(BaseModel):
    """CVE information response"""
    cve_id: str
    description: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    severity: Optional[str] = None
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    references: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    affected_products: Optional[List[str]] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    is_known_exploited: bool = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[str] = None  # Human-readable percentile


class CVEBatchRequest(BaseModel):
    """Batch CVE lookup request"""
    cve_ids: List[str] = Field(..., max_length=50)


class CVESearchRequest(BaseModel):
    """CVE search request"""
    keyword: Optional[str] = None
    cpe_name: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    days_back: Optional[int] = Field(None, ge=1, le=365)
    limit: int = Field(default=20, ge=1, le=100)


class KEVEntry(BaseModel):
    """Known Exploited Vulnerability entry"""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def cve_to_response(cve: CVEInfo) -> CVEResponse:
    """Convert CVEInfo to API response"""
    epss_percentile = None
    if cve.epss_score:
        if cve.epss_score >= 0.9:
            epss_percentile = "Top 10% most likely to be exploited"
        elif cve.epss_score >= 0.7:
            epss_percentile = "Top 30% most likely to be exploited"
        elif cve.epss_score >= 0.5:
            epss_percentile = "Above average exploitation likelihood"
        elif cve.epss_score >= 0.1:
            epss_percentile = "Below average exploitation likelihood"
        else:
            epss_percentile = "Low exploitation likelihood"
    
    return CVEResponse(
        cve_id=cve.cve_id,
        description=cve.description,
        cvss_v3_score=cve.cvss_v3_score,
        cvss_v3_vector=cve.cvss_v3_vector,
        cvss_v2_score=cve.cvss_v2_score,
        severity=cve.severity,
        published_date=cve.published_date,
        last_modified=cve.last_modified,
        references=cve.references,
        cwe_ids=cve.cwe_ids,
        affected_products=cve.affected_products,
        exploitability_score=cve.exploitability_score,
        impact_score=cve.impact_score,
        is_known_exploited=cve.is_known_exploited,
        epss_score=cve.epss_score,
        epss_percentile=epss_percentile
    )


# =============================================================================
# ENDPOINTS
# =============================================================================
@router.get("/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed CVE information
    
    Returns:
    - CVSS scores (v2 and v3)
    - Description and references
    - Affected products (CPE)
    - CWE mappings
    - CISA KEV status (is it actively exploited?)
    - EPSS score (exploitation probability)
    """
    logger.info("CVE lookup", cve_id=cve_id, user_id=current_user.id)
    
    cve_info = await cve_service.get_cve(cve_id)
    
    if not cve_info:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    return cve_to_response(cve_info)


@router.post("/batch", response_model=List[CVEResponse])
async def get_cves_batch(
    request: CVEBatchRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Get multiple CVEs in a single request
    
    Limited to 50 CVEs per request due to NVD rate limits.
    """
    logger.info("Batch CVE lookup", count=len(request.cve_ids), user_id=current_user.id)
    
    results = await cve_service.get_cves_batch(request.cve_ids)
    
    return [cve_to_response(cve) for cve in results.values()]


@router.post("/search", response_model=List[CVEResponse])
async def search_cves(
    request: CVESearchRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Search for CVEs by keyword, product, or severity
    """
    logger.info("CVE search", keyword=request.keyword, user_id=current_user.id)
    
    pub_start = None
    pub_end = None
    if request.days_back:
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")
        pub_start = (datetime.utcnow() - timedelta(days=request.days_back)).strftime("%Y-%m-%dT00:00:00.000")
    
    results = await cve_service.search_cves(
        keyword=request.keyword,
        cpe_name=request.cpe_name,
        cvss_v3_severity=request.severity,
        pub_start_date=pub_start,
        pub_end_date=pub_end,
        results_per_page=request.limit
    )
    
    return [cve_to_response(cve) for cve in results]


@router.get("/kev/check/{cve_id}")
async def check_kev(
    cve_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog
    
    CVEs in KEV are actively being exploited in the wild and should be 
    prioritized for patching.
    """
    is_exploited = await cve_service.is_known_exploited(cve_id)
    
    return {
        "cve_id": cve_id.upper(),
        "is_known_exploited": is_exploited,
        "recommendation": "IMMEDIATE PATCHING REQUIRED" if is_exploited else "Follow standard patching schedule"
    }


@router.get("/kev/list")
async def get_kev_list(
    limit: int = Query(default=100, ge=1, le=1000),
    current_user: User = Depends(get_current_user)
):
    """
    Get CISA Known Exploited Vulnerabilities list
    
    These are vulnerabilities actively being exploited and should be
    top priority for remediation.
    """
    kev_list = await cve_service.get_kev_list()
    
    return {
        "total": len(kev_list),
        "vulnerabilities": kev_list[:limit]
    }


@router.get("/epss/{cve_id}")
async def get_epss(
    cve_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get EPSS (Exploit Prediction Scoring System) score
    
    EPSS predicts the probability that a CVE will be exploited
    in the next 30 days. Higher score = higher priority.
    """
    epss_score = await cve_service.get_epss_score(cve_id)
    
    if epss_score is None:
        raise HTTPException(status_code=404, detail=f"EPSS score not available for {cve_id}")
    
    return {
        "cve_id": cve_id.upper(),
        "epss_score": epss_score,
        "probability_percent": f"{epss_score * 100:.2f}%",
        "interpretation": (
            "Very High" if epss_score >= 0.9 else
            "High" if epss_score >= 0.7 else
            "Medium" if epss_score >= 0.3 else
            "Low" if epss_score >= 0.1 else
            "Very Low"
        )
    }


@router.get("/recent/critical")
async def get_recent_critical(
    days: int = Query(default=7, ge=1, le=30),
    current_user: User = Depends(get_current_user)
):
    """
    Get recently published CRITICAL severity CVEs
    
    Useful for staying updated on new critical vulnerabilities.
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    results = await cve_service.search_cves(
        cvss_v3_severity="CRITICAL",
        pub_start_date=start_date.strftime("%Y-%m-%dT00:00:00.000"),
        pub_end_date=end_date.strftime("%Y-%m-%dT23:59:59.999"),
        results_per_page=50
    )
    
    return {
        "period": f"Last {days} days",
        "count": len(results),
        "cves": [cve_to_response(cve) for cve in results]
    }


@router.get("/stats")
async def get_cve_stats(
    current_user: User = Depends(get_current_user)
):
    """
    Get CVE statistics and service status
    """
    # Get KEV count
    kev_list = await cve_service.get_kev_list()
    
    return {
        "sources": {
            "nvd": {
                "name": "National Vulnerability Database",
                "url": "https://nvd.nist.gov",
                "api_key_configured": bool(cve_service.nvd_api_key)
            },
            "kev": {
                "name": "CISA Known Exploited Vulnerabilities",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "total_vulnerabilities": len(kev_list)
            },
            "epss": {
                "name": "Exploit Prediction Scoring System",
                "url": "https://www.first.org/epss"
            }
        },
        "cache_ttl_hours": cve_service.CVE_CACHE_TTL // 3600,
        "rate_limits": {
            "with_api_key": "50 requests / 30 seconds",
            "without_api_key": "5 requests / 30 seconds"
        }
    }
