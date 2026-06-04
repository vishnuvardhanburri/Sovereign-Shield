"""
Sovereign Shield v2 — Shadow AI Detection Engine
Monitors DNS queries and network activity for unauthorized AI tool usage.
Alerts when staff access ChatGPT, Gemini, Claude, Copilot, etc. directly.
Optionally blocks via local DNS override.
"""
import os
import json
import time
import socket
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends
try:
    from auth.jwt_handler import TokenPayload, get_current_user
    from auth.rbac_engine import Permission, rbac
    from db.models import User
    from db.session import get_db
    from job_queue import async_job_queue
except ImportError:
    from ..auth.jwt_handler import TokenPayload, get_current_user
    from ..auth.rbac_engine import Permission, rbac
    from ..db.models import User
    from ..db.session import get_db
    from ..job_queue import async_job_queue

logger = logging.getLogger("sentinel.shadow_ai")
router = APIRouter(prefix="/shadow-ai", tags=["Shadow AI"])

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
SHADOW_LOG = os.path.join(BASE_DIR, "logs", "shadow_ai_detections.jsonl")

# ── AI Domain Blocklist ───────────────────────────────────────────────────────

AI_DOMAINS: Dict[str, Dict[str, str]] = {
    # OpenAI
    "chat.openai.com":      {"name": "ChatGPT",        "vendor": "OpenAI",     "risk": "HIGH"},
    "api.openai.com":       {"name": "OpenAI API",     "vendor": "OpenAI",     "risk": "HIGH"},
    "chatgpt.com":          {"name": "ChatGPT",        "vendor": "OpenAI",     "risk": "HIGH"},
    # Google
    "gemini.google.com":    {"name": "Gemini",         "vendor": "Google",     "risk": "HIGH"},
    "bard.google.com":      {"name": "Bard",           "vendor": "Google",     "risk": "HIGH"},
    "generativelanguage.googleapis.com": {"name": "Gemini API", "vendor": "Google", "risk": "HIGH"},
    # Anthropic
    "claude.ai":            {"name": "Claude",         "vendor": "Anthropic",  "risk": "HIGH"},
    "api.anthropic.com":    {"name": "Claude API",     "vendor": "Anthropic",  "risk": "HIGH"},
    # Microsoft
    "copilot.microsoft.com":{"name": "Copilot",        "vendor": "Microsoft",  "risk": "MEDIUM"},
    "bing.com":             {"name": "Bing Chat",      "vendor": "Microsoft",  "risk": "MEDIUM"},
    "copilot.github.com":   {"name": "GitHub Copilot", "vendor": "Microsoft",  "risk": "MEDIUM"},
    # Others
    "poe.com":              {"name": "Poe AI",         "vendor": "Quora",      "risk": "MEDIUM"},
    "character.ai":         {"name": "Character.AI",   "vendor": "C.AI",       "risk": "MEDIUM"},
    "perplexity.ai":        {"name": "Perplexity",     "vendor": "Perplexity", "risk": "MEDIUM"},
    "you.com":              {"name": "You.com AI",     "vendor": "You",        "risk": "LOW"},
    "pi.ai":                {"name": "Pi",             "vendor": "Inflection",  "risk": "LOW"},
    "huggingface.co":       {"name": "HuggingFace",   "vendor": "HF",         "risk": "LOW"},
    "replicate.com":        {"name": "Replicate",      "vendor": "Replicate",  "risk": "MEDIUM"},
    "mistral.ai":           {"name": "Mistral",        "vendor": "Mistral",    "risk": "MEDIUM"},
    "cohere.com":           {"name": "Cohere",         "vendor": "Cohere",     "risk": "MEDIUM"},
    "writesonic.com":       {"name": "Writesonic",     "vendor": "Writesonic", "risk": "LOW"},
    "jasper.ai":            {"name": "Jasper AI",      "vendor": "Jasper",     "risk": "LOW"},
    "grok.x.ai":            {"name": "Grok",           "vendor": "xAI",        "risk": "HIGH"},
}


class ShadowAIDetector:
    """
    Passive DNS probe: resolves known AI domains and logs detected access attempts.
    In production, pair with a local DNS server (dnsmasq/bind) for real interception.
    Active monitoring polls every `interval` seconds.
    """

    def __init__(self):
        os.makedirs(os.path.dirname(SHADOW_LOG), exist_ok=True)
        self._detections: List[Dict[str, Any]] = self._load_detections()
        self._monitoring = False
        self._thread: Optional[threading.Thread] = None

    def _load_detections(self) -> List[Dict[str, Any]]:
        if not os.path.exists(SHADOW_LOG):
            return []
        with open(SHADOW_LOG) as f:
            return [json.loads(l) for l in f if l.strip()]

    def _log_detection(self, domain: str, info: Dict, user_hint: str = "SYSTEM"):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "tool_name": info.get("name"),
            "vendor": info.get("vendor"),
            "risk": info.get("risk", "MEDIUM"),
            "detected_by": user_hint,
            "action": "ALERT",
        }
        self._detections.append(entry)
        with open(SHADOW_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        logger.warning(f"Shadow AI detected: {info.get('name')} ({domain}) — Risk: {info.get('risk')}")
        return entry

    def probe_domain(self, domain: str) -> bool:
        """Attempt DNS resolution — returns True if reachable (usage detected)."""
        try:
            socket.setdefaulttimeout(2)
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.timeout):
            return False

    def scan_once(self, user_hint: str = "SYSTEM") -> List[Dict[str, Any]]:
        """Probe all known AI domains once and log detections."""
        new_detections = []
        for domain, info in AI_DOMAINS.items():
            if self.probe_domain(domain):
                entry = self._log_detection(domain, info, user_hint)
                new_detections.append(entry)
        return new_detections

    def start_monitoring(self, interval_seconds: int = 300):
        """Start background monitoring thread."""
        if self._monitoring:
            return
        self._monitoring = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True,
            name="ShadowAI-Monitor"
        )
        self._thread.start()
        logger.info(f"Shadow AI monitoring started (interval={interval_seconds}s)")

    def stop_monitoring(self):
        self._monitoring = False

    def _monitor_loop(self, interval: int):
        while self._monitoring:
            self.scan_once(user_hint="MONITOR_DAEMON")
            time.sleep(interval)

    def get_detections(
        self,
        risk_filter: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return detections, newest first."""
        results = list(reversed(self._detections))
        if risk_filter:
            results = [d for d in results if d.get("risk") == risk_filter.upper()]
        return results[:limit]

    def get_summary(self) -> Dict[str, Any]:
        detections = self._detections
        by_vendor: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        for d in detections:
            v = d.get("vendor", "Unknown")
            r = d.get("risk", "MEDIUM")
            by_vendor[v] = by_vendor.get(v, 0) + 1
            by_risk[r] = by_risk.get(r, 0) + 1
        return {
            "total_detections": len(detections),
            "high_risk": by_risk.get("HIGH", 0),
            "medium_risk": by_risk.get("MEDIUM", 0),
            "by_vendor": by_vendor,
            "monitoring_active": self._monitoring,
            "domains_monitored": len(AI_DOMAINS),
        }

    def get_domain_list(self) -> List[Dict[str, str]]:
        return [{"domain": k, **v} for k, v in AI_DOMAINS.items()]


# Singleton
shadow_detector = ShadowAIDetector()


def _require_active_user(current_user: TokenPayload, db) -> TokenPayload:
    user = db.query(User).filter(User.email == current_user.sub).first()
    if not user or not user.is_active:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="USER_DISABLED_OR_NOT_FOUND")
    return current_user


def require_shadow_reader(current_user: TokenPayload = Depends(get_current_user), db=Depends(get_db)) -> TokenPayload:
    _require_active_user(current_user, db)
    rbac.enforce(current_user.role, Permission.VIEW_AUDIT_LOG)
    return current_user


def require_shadow_admin(current_user: TokenPayload = Depends(get_current_user), db=Depends(get_db)) -> TokenPayload:
    _require_active_user(current_user, db)
    rbac.enforce(current_user.role, Permission.MANAGE_USERS)
    return current_user


# ── FastAPI Routes ────────────────────────────────────────────────────────────

@router.get("/detections")
def get_detections(
    limit: int = 100,
    risk: Optional[str] = None,
    current_user: TokenPayload = Depends(require_shadow_reader),
):
    """List Shadow AI detection events."""
    _ = current_user
    return {
        "detections": shadow_detector.get_detections(risk_filter=risk, limit=limit),
        "summary": shadow_detector.get_summary(),
    }

@router.get("/domains")
def list_monitored_domains(current_user: TokenPayload = Depends(require_shadow_reader)):
    """Return the full AI domain watchlist."""
    _ = current_user
    return {"domains": shadow_detector.get_domain_list(), "total": len(AI_DOMAINS)}

@router.post("/scan", status_code=202)
def trigger_scan(current_user: TokenPayload = Depends(require_shadow_admin)):
    """Accept a one-shot Shadow AI scan job."""
    actor = current_user.model_dump() if hasattr(current_user, "model_dump") else current_user.dict()
    job = async_job_queue.enqueue(
        "shadow_ai.scan",
        {"user_hint": current_user.sub},
        actor=actor,
        timeout_seconds=int(os.getenv("SHADOW_AI_SCAN_JOB_TIMEOUT_SECONDS", "45")),
        max_retries=0,
    )
    return async_job_queue.acceptance_payload(job)

@router.post("/monitor/start")
def start_monitoring(interval: int = 300, current_user: TokenPayload = Depends(require_shadow_admin)):
    """Start continuous background Shadow AI monitoring."""
    _ = current_user
    shadow_detector.start_monitoring(interval_seconds=interval)
    return {"status": "started", "interval_seconds": interval}

@router.post("/monitor/stop")
def stop_monitoring(current_user: TokenPayload = Depends(require_shadow_admin)):
    """Stop Shadow AI monitoring."""
    _ = current_user
    shadow_detector.stop_monitoring()
    return {"status": "stopped"}

@router.get("/summary")
def get_summary(current_user: TokenPayload = Depends(require_shadow_reader)):
    """Dashboard summary of Shadow AI activity."""
    _ = current_user
    return shadow_detector.get_summary()
