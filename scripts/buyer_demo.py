#!/usr/bin/env python3
"""Prepare a local buyer demo without using real PII."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    steps = [
        ["python3", "scripts/seed_demo_data.py"],
        ["python3", "scripts/deployment_doctor.py"],
        ["python3", "scripts/production_readiness_certificate.py"],
    ]
    for step in steps:
        subprocess.run(step, cwd=ROOT, check=False)
    print("\nBuyer demo prepared.")
    print("Dashboard: http://localhost:3000")
    print("API:       http://localhost:8000")
    print("Positioning: human-governed security command center with evidence-backed operations.")
    print("Demo uses synthetic fake events only.")
    print("Start services with: pnpm dev:backend and pnpm dev:frontend")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
