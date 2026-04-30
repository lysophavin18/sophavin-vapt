"""
Kouprey Security CVE Service
CVE database integration for vulnerability enrichment
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import json
import structlog
import httpx
import redis.asyncio as redis

from app.core.config import settings

logger = structlog.get_logger()


@dataclass
class CVEInfo:
    """CVE information structure"""
    cve_id: str
    description: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    severity: Optional[str] = None
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    references: List[str] = None
    cwe_ids: List[str] = None
    affected_products: List[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    is_known_exploited: bool = False
    epss_score: Optional[float] = None  # Exploit Prediction Scoring System


class CVEService:
    """
    CVE Database Service
    
    Sources:
    - NVD (National Vulnerability Database) API 2.0
    - CISA KEV (Known Exploited Vulnerabilities)
    - EPSS (Exploit Prediction Scoring System)
    - VulnCheck (optional commercial)
    """
    
    # API endpoints
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    
    # Cache TTL (from config or default)
    CVE_CACHE_TTL = getattr(settings, 'CVE_CACHE_TTL', 86400)  # 24 hours
    KEV_CACHE_TTL = 3600   # 1 hour
    
    def __init__(self):
        self.nvd_api_key = getattr(settings, 'NVD_API_KEY', None)
        self._kev_cache: Dict[str, bool] = {}
        self._kev_last_update: Optional[datetime] = None
    
    async def _get_redis(self) -> redis.Redis:
        """Get Redis connection for caching"""
        return await redis.from_url(settings.REDIS_URL)
    
    async def get_cve(self, cve_id: str, use_cache: bool = True) -> Optional[CVEInfo]:
        """
        Get CVE information from NVD
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            use_cache: Whether to use Redis cache
            
        Returns:
            CVEInfo object or None if not found
        """
        if not cve_id or not cve_id.upper().startswith('CVE-'):
            return None
        
        cve_id = cve_id.upper()
        
        # Check cache first
        if use_cache:
            cached = await self._get_cached_cve(cve_id)
            if cached:
                return cached
        
        # Fetch from NVD
        try:
            cve_info = await self._fetch_from_nvd(cve_id)
            
            if cve_info:
                # Enrich with additional data
                cve_info = await self._enrich_cve(cve_info)
                
                # Cache the result
                await self._cache_cve(cve_id, cve_info)
            
            return cve_info
            
        except Exception as e:
            logger.error("Failed to fetch CVE", cve_id=cve_id, error=str(e))
            return None
    
    async def get_cves_batch(self, cve_ids: List[str]) -> Dict[str, CVEInfo]:
        """
        Get multiple CVEs in batch
        
        Args:
            cve_ids: List of CVE identifiers
            
        Returns:
            Dict mapping CVE ID to CVEInfo
        """
        results = {}
        uncached = []
        
        # Check cache for all CVEs first
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            cached = await self._get_cached_cve(cve_id)
            if cached:
                results[cve_id] = cached
            else:
                uncached.append(cve_id)
        
        # Fetch uncached CVEs (with rate limiting for NVD)
        for cve_id in uncached:
            cve_info = await self.get_cve(cve_id, use_cache=False)
            if cve_info:
                results[cve_id] = cve_info
            
            # NVD rate limit: 5 requests per 30 seconds without API key
            if not self.nvd_api_key:
                await asyncio.sleep(6)
            else:
                await asyncio.sleep(0.6)  # 50 requests per 30 sec with key
        
        return results
    
    async def _fetch_from_nvd(self, cve_id: str) -> Optional[CVEInfo]:
        """Fetch CVE from NVD API 2.0"""
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        
        cve_data = vulnerabilities[0].get("cve", {})
        
        # Extract CVSS scores
        metrics = cve_data.get("metrics", {})
        cvss_v3 = None
        cvss_v2 = None
        
        # CVSS v3.1 or v3.0
        cvss_v31 = metrics.get("cvssMetricV31", [])
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v31:
            cvss_v3 = cvss_v31[0].get("cvssData", {})
        elif cvss_v30:
            cvss_v3 = cvss_v30[0].get("cvssData", {})
        
        # CVSS v2
        cvss_v2_data = metrics.get("cvssMetricV2", [])
        if cvss_v2_data:
            cvss_v2 = cvss_v2_data[0].get("cvssData", {})
        
        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extract CWEs
        cwe_ids = []
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])
        
        # Extract references
        references = [
            ref.get("url") 
            for ref in cve_data.get("references", [])
            if ref.get("url")
        ]
        
        # Extract affected products (CPE)
        affected_products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        affected_products.append(cpe.get("criteria", ""))
        
        # Determine severity from CVSS
        severity = None
        cvss_score = None
        if cvss_v3:
            cvss_score = cvss_v3.get("baseScore")
            severity = cvss_v3.get("baseSeverity", "").lower()
        elif cvss_v2:
            cvss_score = cvss_v2.get("baseScore")
            if cvss_score:
                if cvss_score >= 7.0:
                    severity = "high"
                elif cvss_score >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"
        
        # Get exploitability and impact scores
        exploitability = None
        impact = None
        if cvss_v31:
            exploitability = cvss_v31[0].get("exploitabilityScore")
            impact = cvss_v31[0].get("impactScore")
        
        return CVEInfo(
            cve_id=cve_id,
            description=description,
            cvss_v3_score=cvss_v3.get("baseScore") if cvss_v3 else None,
            cvss_v3_vector=cvss_v3.get("vectorString") if cvss_v3 else None,
            cvss_v2_score=cvss_v2.get("baseScore") if cvss_v2 else None,
            severity=severity,
            published_date=cve_data.get("published"),
            last_modified=cve_data.get("lastModified"),
            references=references[:10],  # Limit to 10
            cwe_ids=cwe_ids,
            affected_products=affected_products[:20],  # Limit to 20
            exploitability_score=exploitability,
            impact_score=impact
        )
    
    async def _enrich_cve(self, cve_info: CVEInfo) -> CVEInfo:
        """Enrich CVE with additional data sources"""
        
        # Check if known exploited (CISA KEV)
        cve_info.is_known_exploited = await self.is_known_exploited(cve_info.cve_id)
        
        # Get EPSS score
        epss = await self.get_epss_score(cve_info.cve_id)
        if epss:
            cve_info.epss_score = epss
        
        return cve_info
    
    async def is_known_exploited(self, cve_id: str) -> bool:
        """
        Check if CVE is in CISA Known Exploited Vulnerabilities catalog
        """
        # Refresh KEV cache if needed
        if (not self._kev_cache or 
            not self._kev_last_update or 
            datetime.utcnow() - self._kev_last_update > timedelta(hours=1)):
            await self._refresh_kev_cache()
        
        return cve_id.upper() in self._kev_cache
    
    async def _refresh_kev_cache(self):
        """Refresh CISA KEV cache"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.CISA_KEV_URL, timeout=30.0)
                response.raise_for_status()
                data = response.json()
            
            self._kev_cache = {
                vuln["cveID"]: True 
                for vuln in data.get("vulnerabilities", [])
            }
            self._kev_last_update = datetime.utcnow()
            
            logger.info("KEV cache refreshed", count=len(self._kev_cache))
            
        except Exception as e:
            logger.error("Failed to refresh KEV cache", error=str(e))
    
    async def get_epss_score(self, cve_id: str) -> Optional[float]:
        """
        Get EPSS (Exploit Prediction Scoring System) score for a CVE
        
        EPSS provides a probability (0-1) that a CVE will be exploited
        in the next 30 days.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.EPSS_API_URL,
                    params={"cve": cve_id},
                    timeout=10.0
                )
                
                if response.status_code != 200:
                    return None
                
                data = response.json()
                epss_data = data.get("data", [])
                
                if epss_data:
                    return float(epss_data[0].get("epss", 0))
                
        except Exception as e:
            logger.debug("Failed to get EPSS score", cve_id=cve_id, error=str(e))
        
        return None
    
    async def _get_cached_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """Get CVE from Redis cache"""
        try:
            r = await self._get_redis()
            cached = await r.get(f"cve:{cve_id}")
            
            if cached:
                data = json.loads(cached)
                return CVEInfo(**data)
                
        except Exception as e:
            logger.debug("Cache miss", cve_id=cve_id, error=str(e))
        
        return None
    
    async def _cache_cve(self, cve_id: str, cve_info: CVEInfo):
        """Cache CVE in Redis"""
        try:
            r = await self._get_redis()
            data = {
                "cve_id": cve_info.cve_id,
                "description": cve_info.description,
                "cvss_v3_score": cve_info.cvss_v3_score,
                "cvss_v3_vector": cve_info.cvss_v3_vector,
                "cvss_v2_score": cve_info.cvss_v2_score,
                "severity": cve_info.severity,
                "published_date": cve_info.published_date,
                "last_modified": cve_info.last_modified,
                "references": cve_info.references,
                "cwe_ids": cve_info.cwe_ids,
                "affected_products": cve_info.affected_products,
                "exploitability_score": cve_info.exploitability_score,
                "impact_score": cve_info.impact_score,
                "is_known_exploited": cve_info.is_known_exploited,
                "epss_score": cve_info.epss_score,
            }
            await r.setex(
                f"cve:{cve_id}",
                self.CVE_CACHE_TTL,
                json.dumps(data)
            )
        except Exception as e:
            logger.debug("Failed to cache CVE", cve_id=cve_id, error=str(e))
    
    async def search_cves(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        results_per_page: int = 20
    ) -> List[CVEInfo]:
        """
        Search NVD for CVEs matching criteria
        """
        params = {"resultsPerPage": results_per_page}
        
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
            
            results = []
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")
                if cve_id:
                    # Get full CVE info
                    cve_info = await self.get_cve(cve_id)
                    if cve_info:
                        results.append(cve_info)
            
            return results
            
        except Exception as e:
            logger.error("CVE search failed", error=str(e))
            return []
    
    async def get_recently_published(self, days: int = 7, limit: int = 50) -> List[CVEInfo]:
        """Get recently published CVEs"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        return await self.search_cves(
            pub_start_date=start_date.strftime("%Y-%m-%dT00:00:00.000"),
            pub_end_date=end_date.strftime("%Y-%m-%dT23:59:59.999"),
            results_per_page=limit
        )
    
    async def get_kev_list(self) -> List[Dict[str, Any]]:
        """Get full CISA Known Exploited Vulnerabilities list"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.CISA_KEV_URL, timeout=30.0)
                response.raise_for_status()
                data = response.json()
            
            return data.get("vulnerabilities", [])
            
        except Exception as e:
            logger.error("Failed to fetch KEV list", error=str(e))
            return []


# Singleton instance
cve_service = CVEService()
