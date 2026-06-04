#!/usr/bin/env python3
"""Seed safe synthetic demo events for Sovereign Shield buyer walkthroughs."""
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from audit.ledger import audit_ledger  # noqa: E402
from risk_engine import oracle_risk_engine  # noqa: E402


def main() -> int:
    events = [
        {
            "action": "DEMO_PII_MASKED",
            "user_id": "demo.ciso@buyer.local",
            "policy_triggered": "INDIA_PII_PSEUDONYMIZED",
            "risk_score": 6.4,
            "redactions_applied": ["[Aadhaar_1]", "[PAN_1]"],
        },
        {
            "action": "DEMO_PROMPT_BLOCKED",
            "user_id": "demo.redteam@buyer.local",
            "policy_triggered": "LLM_FINGERPRINT_PROMPT_INJECTION",
            "risk_score": 9.1,
            "redactions_applied": [],
        },
        {
            "action": "DEMO_EVIDENCE_READY",
            "user_id": "demo.audit@buyer.local",
            "policy_triggered": "DPDP_2026_EVIDENCE_EXPORT",
            "risk_score": 2.0,
            "redactions_applied": [],
        },
    ]
    for event in events:
        audit_ledger.log(
            action=event["action"],
            user_id=event["user_id"],
            user_role="SUPER_ADMIN",
            department="GLOBAL_SECURITY",
            prompt_text="Synthetic buyer demo prompt with fake identifiers only.",
            redactions_applied=event["redactions_applied"],
            policy_triggered=event["policy_triggered"],
            risk_score=event["risk_score"],
            metadata={"synthetic_demo": True},
        )

    for _ in range(4):
        oracle_risk_engine.record_interception(
            actor_id="demo-risk-actor",
            findings=[{"type": "PII", "label": "Aadhaar Number"}],
            sensitivity_score=8.5,
            policy_triggered="DEMO_QUARANTINE",
        )

    demo_dir = ROOT / "logs" / "demo"
    demo_dir.mkdir(parents=True, exist_ok=True)
    validation_path = demo_dir / "simulated_validation_events.jsonl"
    actors = ["finance-analyst-demo", "banking-crm-demo", "hospital-intake-demo", "legal-ops-demo", "redteam-api-demo"]
    event_types = [
        ("PII_MASKED_BEFORE_LLM", "DPDP_PII_PSEUDONYMIZATION", "Aadhaar", 6.5),
        ("PII_MASKED_BEFORE_LLM", "INDIA_STACK_PAN_MASKING", "PAN", 6.1),
        ("PROMPT_INJECTION_BLOCKED", "LLM_FINGERPRINT_SHIELD", "Prompt Injection", 9.2),
        ("SEMANTIC_DLP_BLOCKED", "SEMANTIC_TRADE_SECRET_DLP", "Trade Secret Context", 8.8),
        ("HIGH_SENSITIVITY_LOCAL_ROUTE", "AIR_GAPPED_ROUTING", "Trade Secret Context", 8.1),
        ("QUARANTINE_REVIEW_REQUIRED", "ORACLE_QUARANTINE_REVIEW", "Aadhaar", 10.0),
    ]
    now = datetime.now(timezone.utc)
    with validation_path.open("w", encoding="utf-8") as handle:
        for idx in range(1200):
            event_name, policy, detection_type, risk = event_types[idx % len(event_types)]
            handle.write(json.dumps({
                "timestamp": (now - timedelta(minutes=1200 - idx)).isoformat(),
                "actor": actors[idx % len(actors)],
                "event": event_name,
                "policy": policy,
                "detection_type": detection_type,
                "risk_score": round(min(10.0, risk + ((idx % 5) * 0.1)), 2),
                "simulated": True,
                "disclaimer": "Simulated system validation data; not customer usage.",
            }) + "\n")

    print(f"Seeded safe synthetic buyer demo data: {validation_path} (1200 events).")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("DEPLOYMENT_MODE", "airgap")
    raise SystemExit(main())
