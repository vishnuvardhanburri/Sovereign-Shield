"""
Sovereign Shield Enterprise — Zero-Trust API Shield

FastAPI middleware for service-to-service mTLS enforcement, rate limiting, and
cost controls. In production, terminate TLS at Envoy/Nginx and forward verified
client certificate metadata in locked-down headers.
"""
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import unquote

from fastapi import Request
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


@dataclass
class BudgetState:
    window_started: float
    requests: int = 0
    estimated_cost_usd: float = 0.0


class InMemoryRateCostLimiter:
    def __init__(self, max_requests: int = 120, window_seconds: int = 60, max_cost_usd: float = 5.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_cost_usd = max_cost_usd
        self._buckets: Dict[str, BudgetState] = {}

    def check(self, actor_key: str, estimated_cost_usd: float = 0.0) -> Tuple[bool, str]:
        now = time.time()
        bucket = self._buckets.get(actor_key)
        if not bucket or now - bucket.window_started > self.window_seconds:
            bucket = BudgetState(window_started=now)
            self._buckets[actor_key] = bucket

        if bucket.requests + 1 > self.max_requests:
            return False, "RATE_LIMIT_EXCEEDED"
        if bucket.estimated_cost_usd + estimated_cost_usd > self.max_cost_usd:
            return False, "COST_BUDGET_EXCEEDED"

        bucket.requests += 1
        bucket.estimated_cost_usd += estimated_cost_usd
        return True, "OK"


class ZeroTrustAPIShieldMiddleware(BaseHTTPMiddleware):
    """
    Enforces mTLS metadata and request budget controls.

    Expected headers from trusted TLS terminator:
      x-ssl-client-verify: SUCCESS
      x-ssl-client-fingerprint: <sha256 cert fingerprint>
    """

    def __init__(
        self,
        app,
        limiter: Optional[InMemoryRateCostLimiter] = None,
        enforce_mtls: Optional[bool] = None,
    ):
        super().__init__(app)
        self.limiter = limiter or InMemoryRateCostLimiter(
            max_requests=int(os.getenv("API_SHIELD_MAX_REQUESTS", "120")),
            window_seconds=int(os.getenv("API_SHIELD_WINDOW_SECONDS", "60")),
            max_cost_usd=float(os.getenv("API_SHIELD_MAX_COST_USD", "5.0")),
        )
        self.enforce_mtls = (
            os.getenv("API_SHIELD_ENFORCE_MTLS", "false").lower() == "true"
            if enforce_mtls is None
            else enforce_mtls
        )
        default_protected = (
            "/ask,/api/v2/auth,/api/v2/chat,/api/v2/proxy,/api/v2/audit,"
            "/audit,/export-audit,/integrations,/license,/shadow-ai"
        )
        self.protected_prefixes = tuple(
            prefix.strip()
            for prefix in os.getenv("API_SHIELD_PROTECTED_PREFIXES", default_protected).split(",")
            if prefix.strip()
        )
        self.max_body_bytes = int(os.getenv("API_SHIELD_MAX_BODY_BYTES", str(512 * 1024)))
        self.blocked_path_fragments = tuple(
            fragment.strip().lower()
            for fragment in os.getenv(
                "API_SHIELD_BLOCKED_PATH_FRAGMENTS",
                "../,/.env,/wp-admin,/phpmyadmin,/actuator,/server-status",
            ).split(",")
            if fragment.strip()
        )

    async def dispatch(self, request: Request, call_next):
        path = unquote(request.url.path).lower()
        if self._is_suspicious_path(path):
            return self._deny(404, "NOT_FOUND")

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_body_bytes:
                    return self._deny(413, "REQUEST_TOO_LARGE")
            except ValueError:
                return self._deny(400, "INVALID_CONTENT_LENGTH")

        if not request.url.path.startswith(self.protected_prefixes):
            response = await call_next(request)
            self._apply_security_headers(response.headers)
            return response

        cert_fingerprint = self._require_mtls(request)
        if cert_fingerprint == "__DENY__":
            return self._deny(401, "MTLS_CLIENT_CERT_REQUIRED")
        actor_key = cert_fingerprint or request.headers.get("authorization", request.client.host if request.client else "unknown")
        estimated_cost = self._estimate_request_cost(request)
        allowed, reason = self.limiter.check(actor_key=actor_key, estimated_cost_usd=estimated_cost)
        if not allowed:
            return self._deny(429, reason)

        response = await call_next(request)
        self._apply_security_headers(response.headers)
        return response

    def _require_mtls(self, request: Request) -> Optional[str]:
        verified = request.headers.get("x-ssl-client-verify", "")
        fingerprint = request.headers.get("x-ssl-client-fingerprint")
        if self.enforce_mtls and (verified.upper() != "SUCCESS" or not fingerprint):
            return "__DENY__"
        return fingerprint

    def _is_suspicious_path(self, path: str) -> bool:
        return any(fragment in path for fragment in self.blocked_path_fragments)

    @staticmethod
    def _deny(status_code: int, detail: str) -> JSONResponse:
        response = JSONResponse(status_code=status_code, content={"detail": detail})
        ZeroTrustAPIShieldMiddleware._apply_security_headers(response.headers)
        return response

    @staticmethod
    def _apply_security_headers(headers: MutableHeaders):
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        headers.setdefault("Cache-Control", "no-store")
        headers.setdefault(
            "Content-Security-Policy",
            os.getenv(
                "API_SHIELD_CSP",
                "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
            ),
        )
        if os.getenv("API_SHIELD_ENABLE_HSTS", "true").lower() == "true":
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    @staticmethod
    def _estimate_request_cost(request: Request) -> float:
        token_header = request.headers.get("x-estimated-tokens")
        try:
            tokens = max(0, int(token_header or "0"))
        except ValueError:
            tokens = 0
        return (tokens / 1000.0) * float(os.getenv("API_SHIELD_COST_PER_1K_TOKENS", "0.01"))
