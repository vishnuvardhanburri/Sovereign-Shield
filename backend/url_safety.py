"""Outbound URL validation helpers for webhook/SIEM integrations."""
import ipaddress
import os
import socket
from urllib.parse import urlparse

from fastapi import HTTPException


def _allow_private_targets() -> bool:
    return os.getenv("ALLOW_PRIVATE_WEBHOOK_TARGETS", "false").strip().lower() in {"1", "true", "yes", "on"}


def validate_outbound_http_url(url: str, *, allow_private: bool | None = None) -> str:
    """Validate an operator-configured webhook URL before server-side delivery."""
    candidate = (url or "").strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="OUTBOUND_URL_INVALID")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="OUTBOUND_URL_CREDENTIALS_FORBIDDEN")
    if parsed.scheme != "https" and os.getenv("ALLOW_HTTP_WEBHOOK_TARGETS", "false").lower() != "true":
        raise HTTPException(status_code=400, detail="OUTBOUND_URL_HTTPS_REQUIRED")

    allow_private = _allow_private_targets() if allow_private is None else allow_private
    host = parsed.hostname
    try:
        resolved = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail=f"OUTBOUND_URL_DNS_FAILED: {exc}") from exc

    if not allow_private:
        for _, _, _, _, sockaddr in resolved:
            ip = ipaddress.ip_address(sockaddr[0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise HTTPException(status_code=400, detail="OUTBOUND_URL_PRIVATE_NETWORK_FORBIDDEN")

    return candidate
