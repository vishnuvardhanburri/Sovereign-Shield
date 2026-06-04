#!/usr/bin/env python3
"""Prepare investor demo data and launch the live dashboard."""
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    subprocess.run([sys.executable, "scripts/seed_demo_data.py"], cwd=ROOT, check=False)
    print("Investor demo seeded with synthetic security activity.")
    print("Starting human-governed command center, API, live logs, risk scoring, and audit proof...")
    launch = subprocess.Popen([sys.executable, "scripts/launch_ready.py"], cwd=ROOT)
    time.sleep(3)
    print("Opening dashboard at http://localhost:3000")
    webbrowser.open("http://localhost:3000")
    print("Opening visual proof theater at http://localhost:3000/proof/")
    webbrowser.open("http://localhost:3000/proof/")
    return launch.wait()


if __name__ == "__main__":
    raise SystemExit(main())
