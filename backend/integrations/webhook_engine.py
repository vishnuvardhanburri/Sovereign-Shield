"""
Sovereign Shield v2 — Webhook & Integration Layer
REST API hooks and connectors for EMR, CRM, Slack/Teams, and Zapier.
All traffic routed through Sentinel's scan → redact → govern pipeline.
"""
import os
import json
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks, Depends
from pydantic import BaseModel
import requests
try:
    from auth.jwt_handler import TokenPayload, get_current_user
    from auth.rbac_engine import Permission, rbac
    from db.models import User
    from db.session import get_db
    from url_safety import validate_outbound_http_url
except ImportError:
    from ..auth.jwt_handler import TokenPayload, get_current_user
    from ..auth.rbac_engine import Permission, rbac
    from ..db.models import User
    from ..db.session import get_db
    from ..url_safety import validate_outbound_http_url

logger = logging.getLogger("sentinel.integrations")

router = APIRouter(prefix="/integrations", tags=["Integrations"])

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")


def _outbound_timeout_seconds() -> float:
    try:
        return max(0.2, min(float(os.getenv("OUTBOUND_HTTP_TIMEOUT_SECONDS", "2.0")), 8.0))
    except ValueError:
        return 2.0


def _webhook_retry_batch_size() -> int:
    try:
        return max(1, min(int(os.getenv("WEBHOOK_RETRY_BATCH_SIZE", "25")), 250))
    except ValueError:
        return 25


# ── Schemas ───────────────────────────────────────────────────────────────────

class WebhookPayload(BaseModel):
    event_type: str          # DOCUMENT_INGESTED | POLICY_TRIGGERED | HIGH_RISK_BLOCKED | AUDIT_EXPORT
    tenant_id: str = "default"
    payload: Dict[str, Any] = {}
    timestamp: Optional[str] = None

class SlackAlertRequest(BaseModel):
    webhook_url: str
    message: str
    severity: str = "info"   # info | warning | critical

class OutboundWebhook(BaseModel):
    target_url: str
    event_types: List[str]   # Which events to forward
    secret: Optional[str] = None
    tenant_id: str = "default"


# ── HMAC Signature Verification ───────────────────────────────────────────────

def verify_webhook_signature(payload_bytes: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature from incoming webhooks (e.g. Epic, Practo)."""
    expected = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


# ── Outbound Webhook Dispatcher ───────────────────────────────────────────────

class WebhookDispatcher:
    """Dispatches governed Sentinel events to registered external systems."""

    def __init__(self):
        self._registry: List[Dict[str, Any]] = []
        self._load_registry()

    def _registry_path(self) -> str:
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../logs"))
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, "webhook_registry.json")

    def _queue_path(self) -> str:
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../logs"))
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, "webhook_delivery_queue.jsonl")

    def _load_registry(self):
        path = self._registry_path()
        if os.path.exists(path):
            with open(path) as f:
                self._registry = json.load(f)

    def _save_registry(self):
        with open(self._registry_path(), "w") as f:
            json.dump(self._registry, f, indent=2)

    def register(self, hook: OutboundWebhook) -> str:
        target_url = validate_outbound_http_url(hook.target_url)
        hook_id = hashlib.sha256(f"{hook.target_url}{hook.tenant_id}".encode()).hexdigest()[:12]
        entry = {
            "hook_id": hook_id,
            "target_url": target_url,
            "event_types": hook.event_types,
            "secret": hook.secret or "",
            "tenant_id": hook.tenant_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active": True,
        }
        self._registry = [r for r in self._registry if r.get("hook_id") != hook_id]
        self._registry.append(entry)
        self._save_registry()
        return hook_id

    def deregister(self, hook_id: str) -> bool:
        before = len(self._registry)
        self._registry = [r for r in self._registry if r.get("hook_id") != hook_id]
        self._save_registry()
        return len(self._registry) < before

    def dispatch(self, event: WebhookPayload):
        """Fire-and-forget dispatch to all matching registered hooks."""
        for hook in self._registry:
            if not hook.get("active"):
                continue
            if event.tenant_id != hook.get("tenant_id", "default"):
                continue
            if event.event_type not in hook.get("event_types", []):
                continue
            try:
                body = json.dumps({
                    "sentinel_event": event.event_type,
                    "tenant_id": event.tenant_id,
                    "timestamp": event.timestamp or datetime.now(timezone.utc).isoformat(),
                    "payload": event.payload,
                })
                headers = {"Content-Type": "application/json", "X-Sentinel-Version": "2.0"}
                if hook.get("secret"):
                    sig = hmac.new(hook["secret"].encode(), body.encode(), hashlib.sha256).hexdigest()
                    headers["X-Sentinel-Signature"] = f"sha256={sig}"

                target_url = validate_outbound_http_url(hook["target_url"])
                resp = requests.post(  # nosec B113
                    target_url,
                    data=body,
                    headers=headers,
                    timeout=_outbound_timeout_seconds(),
                )
                logger.info(f"Webhook {hook['hook_id']} -> {target_url} [{resp.status_code}]")
                if not (200 <= resp.status_code < 300):
                    self._queue_delivery(hook, body, headers, f"HTTP_{resp.status_code}")
            except Exception as e:
                logger.warning(f"Webhook dispatch failed for {hook.get('hook_id')}: {e}")
                self._queue_delivery(hook, body, headers, str(e))

    def list_hooks(self, tenant_id: str = "default") -> List[Dict[str, Any]]:
        hooks = []
        for hook in self._registry:
            if hook.get("tenant_id") == tenant_id:
                public = dict(hook)
                public["secret_configured"] = bool(public.get("secret"))
                public.pop("secret", None)
                hooks.append(public)
        return hooks

    def _queue_delivery(self, hook: Dict[str, Any], body: str, headers: Dict[str, str], reason: str):
        entry = {
            "hook_id": hook.get("hook_id"),
            "target_url": hook.get("target_url"),
            "body": body,
            "headers": headers,
            "reason": reason,
            "attempts": 0,
            "queued_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(self._queue_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def queued_deliveries(self) -> List[Dict[str, Any]]:
        path = self._queue_path()
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def retry_queue(self) -> Dict[str, Any]:
        queued = self.queued_deliveries()
        remaining = []
        delivered = 0
        batch_size = _webhook_retry_batch_size()
        for entry in queued[:batch_size]:
            try:
                resp = requests.post(  # nosec B113
                    validate_outbound_http_url(entry["target_url"]),
                    data=entry["body"],
                    headers=entry["headers"],
                    timeout=_outbound_timeout_seconds(),
                )
                if 200 <= resp.status_code < 300:
                    delivered += 1
                    continue
                entry["reason"] = f"HTTP_{resp.status_code}"
            except Exception as exc:
                entry["reason"] = str(exc)
            entry["attempts"] = int(entry.get("attempts", 0)) + 1
            remaining.append(entry)
        remaining.extend(queued[batch_size:])
        with open(self._queue_path(), "w", encoding="utf-8") as f:
            for entry in remaining:
                f.write(json.dumps(entry) + "\n")
        return {"delivered": delivered, "remaining": len(remaining), "processed": min(len(queued), batch_size)}


dispatcher = WebhookDispatcher()


def require_webhook_admin(current_user: TokenPayload = Depends(get_current_user), db=Depends(get_db)) -> TokenPayload:
    user = db.query(User).filter(User.email == current_user.sub).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="USER_DISABLED_OR_NOT_FOUND")
    rbac.enforce(current_user.role, Permission.MANAGE_USERS)
    return current_user


# ── Slack/Teams Alert ─────────────────────────────────────────────────────────

def send_slack_alert(webhook_url: str, message: str, severity: str = "info") -> bool:
    """Send a critical security alert to Slack or Teams webhook."""
    target_url = validate_outbound_http_url(webhook_url)
    color_map = {"info": "#10b981", "warning": "#f59e0b", "critical": "#ef4444"}
    payload = {
        "attachments": [{
            "color": color_map.get(severity, "#10b981"),
            "title": f"🛡️ Sovereign Shield Alert [{severity.upper()}]",
            "text": message,
            "footer": f"Sovereign Shield v2 · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        }]
    }
    try:
        resp = requests.post(  # nosec B113
            target_url,
            json=payload,
            timeout=_outbound_timeout_seconds(),
        )
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")
        return False


# ── FastAPI Routes ────────────────────────────────────────────────────────────

@router.post("/webhooks/register")
def register_webhook(hook: OutboundWebhook, current_user: TokenPayload = Depends(require_webhook_admin)) -> Dict[str, Any]:
    """Register an outbound webhook for Sentinel events."""
    hook_id = dispatcher.register(hook)
    return {"status": "registered", "hook_id": hook_id, "event_types": hook.event_types, "registered_by": current_user.sub}


@router.delete("/webhooks/{hook_id}")
def deregister_webhook(hook_id: str, current_user: TokenPayload = Depends(require_webhook_admin)) -> Dict[str, Any]:
    """Deregister an outbound webhook."""
    ok = dispatcher.deregister(hook_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "deregistered", "hook_id": hook_id}


@router.get("/webhooks")
def list_webhooks(
    tenant_id: str = "default",
    current_user: TokenPayload = Depends(require_webhook_admin),
) -> List[Dict[str, Any]]:
    """List registered webhooks for a tenant."""
    return dispatcher.list_hooks(tenant_id)


@router.get("/webhooks/queue")
def list_webhook_queue(current_user: TokenPayload = Depends(require_webhook_admin)) -> Dict[str, Any]:
    queued = dispatcher.queued_deliveries()
    return {"queued": queued, "total": len(queued)}


@router.post("/webhooks/queue/retry")
def retry_webhook_queue(current_user: TokenPayload = Depends(require_webhook_admin)) -> Dict[str, Any]:
    return dispatcher.retry_queue()


@router.post("/webhooks/test/{hook_id}")
def test_webhook(hook_id: str, current_user: TokenPayload = Depends(require_webhook_admin)) -> Dict[str, Any]:
    """Send a test event to a registered webhook."""
    test_event = WebhookPayload(
        event_type="TEST_PING",
        tenant_id="default",
        payload={"message": "Sovereign Shield webhook test", "version": "2.0"},
    )
    dispatcher.dispatch(test_event)
    return {"status": "dispatched", "event": "TEST_PING"}


@router.post("/incoming/emr")
async def emr_webhook(request: Request, background: BackgroundTasks) -> Dict[str, Any]:
    """
    Receive governed data from EMR systems (Epic, Practo).
    Verifies HMAC signature, runs Sentinel scan, auto-redacts before processing.
    """
    body = await request.body()
    sig = request.headers.get("X-Hub-Signature-256", "")

    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="WEBHOOK_SECRET_NOT_CONFIGURED")
    if not verify_webhook_signature(body, sig, WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Run through Sentinel scan in background
    background.add_task(_scan_and_archive_emr, data)

    return {
        "status": "received",
        "message": "EMR data queued for Sentinel scan and governed ingestion",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def _scan_and_archive_emr(data: Dict[str, Any]):
    """Background task: scan EMR payload for PII and log to audit."""
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from security_scanner import EnterpriseScanner
        from compliance.india_patterns import IndiaPIIScanner
        from audit.ledger import audit_ledger

        text = json.dumps(data)
        scanner = EnterpriseScanner()
        india = IndiaPIIScanner()
        findings = scanner.scan_content(text) + india.scan(text)
        risk = scanner.calculate_risk_score(findings[:len(findings)//2] if findings else [])
        clean = scanner.redact_content(text, [f for f in findings if 'start' in f and 'end' in f])

        audit_ledger.log(
            action="EMR_INGEST",
            user_id="WEBHOOK_EMR",
            user_role="SYSTEM",
            risk_score=risk,
            redactions_applied=[f.get("label") for f in findings],
            metadata={"source": "emr_webhook"},
        )
        logger.info(f"EMR webhook: risk={risk:.1f}, findings={len(findings)}")
    except Exception as e:
        logger.error(f"EMR background scan failed: {e}")


@router.post("/alert/slack")
def alert_slack(req: SlackAlertRequest, current_user: TokenPayload = Depends(require_webhook_admin)) -> Dict[str, Any]:
    """Send a manual alert to a Slack/Teams webhook."""
    ok = send_slack_alert(req.webhook_url, req.message, req.severity)
    return {"status": "sent" if ok else "failed", "severity": req.severity}
