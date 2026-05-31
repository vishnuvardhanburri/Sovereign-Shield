#!/usr/bin/env python3
"""Buyer-grade end-to-end verification runner for Sovereign Shield."""
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "logs" / "verification"
OUT.mkdir(parents=True, exist_ok=True)


def run(name: str, command: list[str], timeout: int = 240) -> dict:
    print(f"[VERIFY] {name}...", flush=True)
    try:
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
        ok = completed.returncode == 0
        print(f"[{'OK' if ok else 'FAIL'}] {name}", flush=True)
        return {
            "name": name,
            "ok": ok,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-3000:],
            "stderr_tail": completed.stderr[-3000:],
        }
    except Exception as exc:
        print(f"[FAIL] {name}: {exc}", flush=True)
        return {"name": name, "ok": False, "error": str(exc)}


def port_open(port: int) -> bool:
    sock = socket.socket()
    sock.settimeout(0.4)
    ok = sock.connect_ex(("127.0.0.1", port)) == 0
    sock.close()
    return ok


def load_env() -> dict:
    env = dict(os.environ)
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, value = stripped.split("=", 1)
                env.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    return env


def seed_verification_secrets() -> None:
    """Provide ephemeral secrets for local verification without writing a .env file."""
    for key in ("JWT_SECRET_KEY", "LICENSE_MASTER_SECRET", "ACTOR_HASH_SALT", "LEDGER_MASTER_SALT"):
        os.environ.setdefault(key, f"verify_{secrets.token_urlsafe(72)}")


def preferred_python() -> str:
    buyer_python = ROOT / ".buyer_venv/bin/python"
    if buyer_python.exists():
        return str(buyer_python)
    for candidate in [ROOT / ".verify_venv/bin/python", ROOT / ".runtime_venv/bin/python"]:
        if candidate.exists():
            try:
                version = subprocess.check_output([str(candidate), "-c", "import sys; print(sys.version_info[:2])"], text=True, timeout=5)
                if "(3, 13)" not in version and "(3, 14)" not in version:
                    return str(candidate)
            except Exception:
                pass
    for candidate in ["python3.11", "python3"]:
        try:
            completed = subprocess.run([candidate, "--version"], capture_output=True, text=True, timeout=5)
            if completed.returncode == 0:
                if candidate == "python3.11":
                    ensure_buyer_venv(candidate)
                    return str(buyer_python)
                return candidate
        except Exception:
            pass
    return sys.executable


def ensure_buyer_venv(seed_python: str) -> None:
    buyer_python = ROOT / ".buyer_venv/bin/python"
    if buyer_python.exists():
        return
    print("[VERIFY] Creating Python 3.11 buyer runtime...", flush=True)
    subprocess.run([seed_python, "-m", "venv", str(ROOT / ".buyer_venv")], cwd=ROOT, check=True)
    subprocess.run([str(buyer_python), "-m", "pip", "install", "--upgrade", "pip"], cwd=ROOT, check=True)
    subprocess.run([str(ROOT / ".buyer_venv/bin/pip"), "install", "-r", "requirements.txt"], cwd=ROOT, check=True)


def start_backend_if_needed() -> tuple[subprocess.Popen | None, dict]:
    if port_open(8000):
        return None, {"name": "backend_autostart", "ok": True, "detail": "backend already running"}
    python = preferred_python()
    print(f"[VERIFY] Starting backend with {python}...", flush=True)
    env = load_env()
    env.setdefault("PYTHONPATH", str(ROOT / "backend"))
    proc = subprocess.Popen(
        [python, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(180):
        if port_open(8000):
            return proc, {"name": "backend_autostart", "ok": True, "detail": f"started with {python}"}
        if proc.poll() is not None:
            stderr = proc.stderr.read()[-2000:] if proc.stderr else ""
            return proc, {"name": "backend_autostart", "ok": False, "detail": stderr}
        time.sleep(0.5)
    return proc, {"name": "backend_autostart", "ok": False, "detail": "timeout waiting for localhost:8000"}


def main() -> int:
    seed_verification_secrets()
    python = os.getenv("VERIFY_PYTHON", preferred_python())
    backend_proc, backend_check = start_backend_if_needed()
    checks = [
        backend_check,
        run("compile", [python, "-m", "compileall", "backend", "tests"]),
        run("frontend_lint", ["pnpm", "--dir", "frontend", "lint"]),
        run("frontend_build_optional", ["pnpm", "--dir", "frontend", "build"], timeout=180),
        run("deployment_doctor", [python, "scripts/deployment_doctor.py"]),
        run("api_smoke", [python, "scripts/smoke_e2e.py"]),
        run("browser_smoke_optional", [python, "scripts/browser_e2e.py"]),
        run("release_certificate", [python, "scripts/production_readiness_certificate.py"]),
        run("handoff_pdf", [python, "scripts/generate_handoff_pdf.py"]),
        run("handoff_zip", [python, "scripts/buyer_handoff_zip.py"], timeout=300),
    ]
    api_smoke_ok = next((c.get("ok") for c in checks if c["name"] == "api_smoke"), False)
    if not backend_check.get("ok") and api_smoke_ok and port_open(8000):
        backend_check["ok"] = True
        backend_check["detail"] = "backend started slowly; verified healthy by api_smoke"
    if backend_proc and backend_proc.poll() is None:
        backend_proc.terminate()
    optional = {"browser_smoke_optional", "frontend_build_optional"}
    required = [c for c in checks if c["name"] not in optional]
    score = round(sum(1 for c in checks if c.get("ok")) / len(checks) * 100, 2)
    passed_required = all(c.get("ok") for c in required)
    result = {
        "product": "Sovereign Shield",
        "company": "Xavira Tech Labs",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "status": "BUYER_VERIFIED" if passed_required else "ACTION_REQUIRED",
        "checks": checks,
    }
    path = OUT / f"buyer_verification_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(result, indent=2))
    print(json.dumps({"status": result["status"], "score": score, "file": str(path)}, indent=2))
    return 0 if passed_required else 1


if __name__ == "__main__":
    raise SystemExit(main())
