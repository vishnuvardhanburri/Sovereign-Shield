"""Print the Sovereign Shield acquisition demo narrative.

This command is intentionally offline-safe. It does not claim real usage,
customers, or revenue; it gives the founder a crisp walkthrough for video and
buyer diligence.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


API = "http://localhost:8000"


def fetch(path: str) -> dict:
    try:
        with urllib.request.urlopen(f"{API}{path}", timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {}


def line(title: str) -> None:
    print(f"\n== {title} ==")


def main() -> None:
    narrative = fetch("/demo/narrative")
    readiness = fetch("/demo/acquisition-readiness")
    metrics = fetch("/demo/metrics")

    print("Sovereign Shield: $500K Acquisition Demo Narrative")
    print("Category: Human-Governed Enterprise Security Platform for Private AI Governance")
    print("Core message: humans stay in control while AI accelerates analysis, detection, prioritization, and governance.")
    print("Important: demo metrics are synthetic; no fake customer or revenue claims.")

    line("Open These URLs")
    print("Dashboard: http://localhost:3000")
    print("API health: http://localhost:8000/health")
    print("Demo metrics: http://localhost:8000/demo/metrics")
    print("Narrative API: http://localhost:8000/demo/narrative")
    print("Readiness API: http://localhost:8000/demo/acquisition-readiness")
    print("Pricing: http://localhost:3000/pricing")

    line("Acquisition Anchor")
    acquisition = narrative.get("acquisition_positioning", {})
    print(f"Target price: {acquisition.get('target_price', '$500K')}")
    print(acquisition.get("replacement_cost_story", "Replaces 6-12 months of engineering."))
    print("Monthly/annual signal: Starter $499/mo, Growth $999/mo, Enterprise custom annual for governed operations.")

    line("60-Second Video Flow")
    for idx, step in enumerate(narrative.get("video_flow", []), 1):
        print(f"{idx}. {step}")

    line("Demo Narrative")
    for step in narrative.get("steps", []):
        print(f"{step['step']}. {step['name']} -> {step['status']}")
        print(f"   Buyer value: {step['buyer_value']}")

    line("Readiness Score")
    if readiness:
        print(f"{readiness.get('status')} · {readiness.get('score')}/100")
        for control in readiness.get("controls", []):
            print(f"- {control['area']}: {control['score']} · {control['proof']}")
    else:
        print("Start the backend with `pnpm launch` to show live readiness.")

    line("Proof Metrics")
    summary = metrics.get("summary", {})
    if summary:
        print(f"Security events blocked: {summary.get('security_events_blocked')}")
        print(f"PII detections: {summary.get('pii_detections')}")
        print(f"Local high-sensitivity routes: {summary.get('high_sensitivity_local_routes')}")
    else:
        print("Start the backend with `pnpm launch` to show live synthetic metrics.")

    line("Commands To Run For Buyer Confidence")
    print("pnpm launch")
    print("pnpm submit:ready")
    print("pnpm generate:data-room")


if __name__ == "__main__":
    main()
