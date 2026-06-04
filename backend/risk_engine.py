"""
Sovereign Shield Enterprise — Oracle User Risk Scoring

Maintains a real-time user/API-key risk profile. If an actor attempts to send
PII more than three times in one hour, the actor is queued for operator
quarantine review and a CISO alert is emitted for downstream integrations.
"""
import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
try:
    from config import security_settings
except ImportError:
    from .config import security_settings

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATE_DIR = os.path.join(BASE_DIR, "logs", "risk")
RISK_STATE_FILE = os.path.join(STATE_DIR, "oracle_risk_state.json")


@dataclass
class RiskEvent:
    timestamp: str
    actor_hash: str
    event_type: str
    severity: float
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActorRiskProfile:
    actor_hash: str
    risk_score: float = 0.0
    pii_attempts_last_hour: int = 0
    injection_attempts_last_hour: int = 0
    semantic_hits_last_hour: int = 0
    quarantined: bool = False
    quarantine_review_required: bool = False
    quarantine_reason: Optional[str] = None
    last_seen: Optional[str] = None
    labels: List[str] = field(default_factory=list)


class OracleRiskEngine:
    PII_QUARANTINE_THRESHOLD = 3

    def __init__(self, state_path: str = RISK_STATE_FILE):
        self.state_path = state_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        self._events: List[RiskEvent] = self._load_events()

    def _redis_client(self):
        redis_url = os.getenv("REDIS_URL", "").strip()
        if not redis_url:
            return None
        try:
            import redis
            client = redis.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=1)
            client.ping()
            return client
        except Exception:
            return None

    def record_interception(
        self,
        actor_id: str,
        findings: List[Dict[str, Any]],
        sensitivity_score: float,
        policy_triggered: Optional[str] = None,
        tenant_id: str = "default",
        api_key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        actor_hash = self.hash_actor(api_key_id or actor_id, tenant_id)
        labels = sorted({str(f.get("label", f.get("type", "UNKNOWN"))) for f in findings})
        event_types = {str(f.get("type", "")).upper() for f in findings}
        event_type = self._event_type(event_types)

        with self._lock:
            self._events.append(
                RiskEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    actor_hash=actor_hash,
                    event_type=event_type,
                    severity=float(sensitivity_score),
                    labels=labels,
                    metadata={
                        "policy_triggered": policy_triggered,
                        "tenant_id": tenant_id,
                        "api_key_id_hash": self.hash_actor(api_key_id, tenant_id) if api_key_id else None,
                        "event_types": sorted(event_types),
                    },
                )
            )
            self._events = self._recent_events(days=7)
            self._save_events()

            profile = self.profile(actor_hash=actor_hash)
            alert = None
            if profile.pii_attempts_last_hour > self.PII_QUARANTINE_THRESHOLD:
                profile.quarantine_review_required = True
                profile.quarantine_reason = "PII_ATTEMPTS_EXCEEDED_3_PER_HOUR"
                alert = self._ciso_alert(profile, policy_triggered)

            return {
                "actor_hash": actor_hash,
                "risk_score": profile.risk_score,
                "quarantined": profile.quarantined,
                "quarantine_review_required": profile.quarantine_review_required,
                "quarantine_reason": profile.quarantine_reason,
                "ciso_alert": alert,
                "profile": asdict(profile),
            }

    def profile(self, actor_id: Optional[str] = None, actor_hash: Optional[str] = None, tenant_id: str = "default") -> ActorRiskProfile:
        resolved_hash = actor_hash or self.hash_actor(actor_id or "UNKNOWN", tenant_id)
        recent = [event for event in self._events if event.actor_hash == resolved_hash and self._within_last_hour(event)]
        labels = sorted({label for event in recent for label in event.labels})
        pii_attempts = sum(1 for event in recent if self._has_type(event, {"PII", "INDIA_PII", "SECRET"}))
        injection_attempts = sum(1 for event in recent if self._has_type(event, {"PROMPT_INJECTION"}))
        semantic_hits = sum(1 for event in recent if self._has_type(event, {"SEMANTIC_DLP"}))
        score = self._score(recent, pii_attempts, injection_attempts, semantic_hits)

        quarantine_review_required = pii_attempts > self.PII_QUARANTINE_THRESHOLD
        return ActorRiskProfile(
            actor_hash=resolved_hash,
            risk_score=score,
            pii_attempts_last_hour=pii_attempts,
            injection_attempts_last_hour=injection_attempts,
            semantic_hits_last_hour=semantic_hits,
            quarantined=False,
            quarantine_review_required=quarantine_review_required,
            quarantine_reason="PII_ATTEMPTS_EXCEEDED_3_PER_HOUR" if quarantine_review_required else None,
            last_seen=max((event.timestamp for event in recent), default=None),
            labels=labels,
        )

    def heatmap(self, tenant_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        profiles = []
        actor_hashes = sorted({event.actor_hash for event in self._events})
        for actor_hash in actor_hashes:
            profile = self.profile(actor_hash=actor_hash)
            if profile.last_seen:
                profiles.append(asdict(profile))

        profiles.sort(key=lambda item: item["risk_score"], reverse=True)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window": "1h",
            "tenant_id": tenant_id,
            "quarantined_users": sum(1 for p in profiles if p["quarantined"]),
            "quarantine_review_users": sum(1 for p in profiles if p.get("quarantine_review_required")),
            "actors": profiles[:limit],
        }

    def is_quarantined(self, actor_id: str, tenant_id: str = "default") -> bool:
        return self.profile(actor_id=actor_id, tenant_id=tenant_id).quarantined

    @staticmethod
    def hash_actor(actor_id: Optional[str], tenant_id: str = "default") -> str:
        salt = security_settings()["actor_hash_salt"]
        return hashlib.sha256(f"{salt}:{tenant_id}:{actor_id or 'UNKNOWN'}".encode()).hexdigest()

    def _load_events(self) -> List[RiskEvent]:
        client = self._redis_client()
        if client:
            try:
                raw = client.get("sentinel:oracle:risk_events")
                if raw:
                    return [RiskEvent(**event) for event in json.loads(raw).get("events", [])]
            except Exception:
                pass
        if not os.path.exists(self.state_path):
            return []
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return [RiskEvent(**event) for event in raw.get("events", [])]
        except Exception:
            return []

    def _save_events(self):
        payload = {"events": [asdict(event) for event in self._events]}
        client = self._redis_client()
        if client:
            try:
                client.set("sentinel:oracle:risk_events", json.dumps(payload))
            except Exception:
                pass
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def _recent_events(self, days: int) -> List[RiskEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return [event for event in self._events if self._parse_time(event.timestamp) >= cutoff]

    @staticmethod
    def _within_last_hour(event: RiskEvent) -> bool:
        return OracleRiskEngine._parse_time(event.timestamp) >= datetime.now(timezone.utc) - timedelta(hours=1)

    @staticmethod
    def _parse_time(value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @staticmethod
    def _event_type(event_types: set[str]) -> str:
        if "PROMPT_INJECTION" in event_types:
            return "PROMPT_INJECTION"
        if "SEMANTIC_DLP" in event_types:
            return "SEMANTIC_DLP"
        if event_types & {"PII", "INDIA_PII", "SECRET"}:
            return "PII_ATTEMPT"
        return "POLICY_EVENT"

    @staticmethod
    def _has_type(event: RiskEvent, expected: set[str]) -> bool:
        event_types = set(event.metadata.get("event_types", []))
        return bool(event_types & expected) or event.event_type in expected

    @staticmethod
    def _score(events: List[RiskEvent], pii_attempts: int, injection_attempts: int, semantic_hits: int) -> float:
        base = sum(min(10.0, event.severity) for event in events)
        score = base + (pii_attempts * 8.0) + (injection_attempts * 12.0) + (semantic_hits * 10.0)
        if pii_attempts > OracleRiskEngine.PII_QUARANTINE_THRESHOLD:
            score += 25.0
        return min(100.0, round(score, 2))

    @staticmethod
    def _ciso_alert(profile: ActorRiskProfile, policy_triggered: Optional[str]) -> Dict[str, Any]:
        return {
            "severity": "CRITICAL",
            "type": "QUARANTINE_REVIEW_REQUIRED",
            "actor_hash": profile.actor_hash,
            "reason": profile.quarantine_reason,
            "risk_score": profile.risk_score,
            "policy_triggered": policy_triggered,
            "message": "Actor exceeded allowed PII attempts within one hour and was queued for operator quarantine review.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }


oracle_risk_engine = OracleRiskEngine()
