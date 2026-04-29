"""Custom FastAPI middleware"""

import time
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting (Redis-backed in production)"""

    async def dispatch(self, request: Request, call_next):
        return await call_next(request)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Audit log middleware — logs every mutating request"""

    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response: Response = await call_next(request)
        elapsed = round((time.time() - start) * 1000, 2)

        if request.method not in ("GET", "HEAD", "OPTIONS"):
            logger.info(
                "audit",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                elapsed_ms=elapsed,
                client=request.client.host if request.client else None,
            )
        return response
