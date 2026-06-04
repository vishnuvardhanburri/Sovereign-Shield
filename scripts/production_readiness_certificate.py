#!/usr/bin/env python3
"""Generate a signed local production readiness certificate without external deps."""
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "logs" / "audit" / "audit_ledger.jsonl"


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


def compute_entry_hash(entry: dict, salt: str) -> str:
    payload = {k: v for k, v in entry.items() if k not in {"entry_hash", "signature"}}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(f"{salt}:{canonical}".encode()).hexdigest()


def verify_ledger(env: dict) -> dict:
    if not LEDGER.exists():
        return {"valid": True, "total_entries": 0, "corrupted_at": None}
    salt = env.get("LEDGER_MASTER_SALT", "")
    prev = "GENESIS"
    lines = [line for line in LEDGER.read_text().splitlines() if line.strip()]
    for idx, line in enumerate(lines, start=1):
        entry = json.loads(line)
        if entry.get("prev_hash") != prev:
            return {"valid": False, "total_entries": len(lines), "corrupted_at": f"Entry {idx} prev_hash mismatch"}
        expected = compute_entry_hash(entry, salt)
        if entry.get("entry_hash") != expected or entry.get("signature", expected) != expected:
            return {"valid": False, "total_entries": len(lines), "corrupted_at": f"Entry {idx} signature mismatch"}
        prev = expected
    return {"valid": True, "total_entries": len(lines), "corrupted_at": None}


def run_check(name: str, command: list[str]) -> dict:
    try:
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
        return {"name": name, "ok": completed.returncode == 0, "returncode": completed.returncode}
    except Exception as exc:
        return {"name": name, "ok": False, "error": str(exc)}


def count_policy_rules() -> int:
    count = 0
    for folder in [ROOT / "presets", ROOT / "policies"]:
        if not folder.exists():
            continue
        for path in folder.rglob("*.y*ml"):
            text = path.read_text(errors="ignore")
            count += text.count("\n  - name:") + text.count("\n- name:")
    return count


def main() -> int:
    out_dir = ROOT / "logs" / "certificates"
    out_dir.mkdir(parents=True, exist_ok=True)
    env = load_env()
    required = ["JWT_SECRET_KEY", "LICENSE_MASTER_SECRET", "ACTOR_HASH_SALT", "LEDGER_MASTER_SALT"]
    ledger = verify_ledger(env)
    policy_rules = count_policy_rules()
    checks = [
        {"name": "fail_closed_secrets", "ok": all(len(env.get(k, "")) >= 32 for k in required)},
        {"name": "cors_no_wildcard", "ok": "*" not in env.get("ALLOWED_ORIGINS", "http://localhost:3000")},
        {"name": "ledger_valid", "ok": bool(ledger.get("valid"))},
        {"name": "policy_rules_loaded", "ok": policy_rules > 0, "count": policy_rules},
        {"name": "docs_present", "ok": all((ROOT / p).exists() for p in ["README.md", "DOCS.md", "SECURITY.md", "RELEASE.md"])},
        run_check("python_compile", ["python3", "-m", "compileall", "backend", "tests"]),
        run_check("frontend_lint", ["pnpm", "--dir", "frontend", "lint"]),
    ]
    score = round(sum(1 for item in checks if item.get("ok")) / len(checks) * 100, 2)
    certificate = {
        "product": "Sovereign Shield",
        "company": "Xavira Tech Labs",
        "positioning": "Human-governed enterprise security platform with evidence-driven operations.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "status": "PRODUCTION_READY" if score >= 85 else "ACTION_REQUIRED",
        "checks": checks,
        "ledger": ledger,
    }
    payload = json.dumps(certificate, sort_keys=True, ensure_ascii=True)
    certificate["signature"] = hashlib.sha256(payload.encode()).hexdigest()
    path = out_dir / f"readiness_certificate_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(certificate, indent=2))
    print(path)
    print(json.dumps({"status": certificate["status"], "score": score, "signature": certificate["signature"]}, indent=2))
    return 0 if score >= 70 else 1


if __name__ == "__main__":
    raise SystemExit(main())
