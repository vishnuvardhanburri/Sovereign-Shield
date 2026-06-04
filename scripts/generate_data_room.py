#!/usr/bin/env python3
"""Generate acquisition data-room artifacts for buyer diligence."""
import json
import os
import secrets
import sys
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "logs" / "data_room"
OUT.mkdir(parents=True, exist_ok=True)

BUYER_PYTHON = ROOT / ".buyer_venv" / "bin" / "python"
if BUYER_PYTHON.exists() and Path(sys.executable).resolve() != BUYER_PYTHON.resolve():
    os.execv(str(BUYER_PYTHON), [str(BUYER_PYTHON), *sys.argv])


def ensure_data_room_security_env():
    """Use synthetic local secrets for artifact generation without weakening app boot."""
    for name in ("JWT_SECRET_KEY", "LICENSE_MASTER_SECRET"):
        os.environ.setdefault(name, f"data-room-{name.lower()}-{secrets.token_hex(32)}")
    for name in ("ACTOR_HASH_SALT", "LEDGER_MASTER_SALT"):
        os.environ.setdefault(name, f"data-room-{name.lower()}-{secrets.token_hex(24)}")


def run(command: list[str]):
    subprocess.run([sys.executable if part == "python3" else part for part in command], cwd=ROOT, check=False)


def write_pdf(path: Path, title: str, lines: list[str]):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        path.with_suffix(".txt").write_text(title + "\n\n" + "\n".join(lines))
        return
    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    y = height - 72
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, y, title)
    y -= 28
    c.setFont("Helvetica", 10)
    for line in lines:
        for chunk in [line[i:i + 95] for i in range(0, len(line), 95)] or [""]:
            if y < 72:
                c.showPage()
                y = height - 72
                c.setFont("Helvetica", 10)
            c.drawString(72, y, chunk)
            y -= 15
    c.save()


def copy_if_exists(src: Path, dst: Path):
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def main() -> int:
    ensure_data_room_security_env()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    room = OUT / f"sovereign_shield_data_room_{stamp}"
    room.mkdir(parents=True, exist_ok=True)

    run(["python3", "scripts/generate_deployment_pack.py"])
    run(["python3", "scripts/generate_handoff_pdf.py"])
    run(["python3", "scripts/production_readiness_certificate.py"])
    run(["python3", "scripts/seed_demo_data.py"])
    run(["python3", "scripts/capture_dashboard_screenshots.py"])

    docs = [
        "README.md",
        "DOCS.md",
        "SECURITY.md",
        "THREAT_MODEL.md",
        "DATA_PROCESSING.md",
        "PRIVACY.md",
        "BUYER_FAQ.md",
        "START_HERE.md",
        "docs/HOMEPAGE_COPY.md",
        "docs/ACQUIRE_LISTING_COPY.md",
        "docs/COMPLIANCE_MAPPING.md",
        "docs/KNOWN_LIMITATIONS.md",
        "docs/BUYER_REPLIES.md",
        "docs/API_INTEGRATION_EXAMPLES.md",
        "docs/RED_TEAM_TEST_PACK.md",
        "docs/HA_RUNBOOK.md",
        "docs/TIER3_GOVERNED_RESILIENCE.md",
        "docs/SYSTEM_SNAPSHOT.md",
        "docs/CROSS_PLATFORM_ARCHITECTURE.md",
        "docs/cross-platform/API_CONTRACT.md",
        "docs/cross-platform/SECURITY_HARDENING_CHECKLIST.md",
        "docs/cross-platform/RELEASE_WORKFLOW.md",
        "docs/cross-platform/MIGRATION_PLAN.md",
        "docs/cross-platform/PACKAGING_MATRIX.md",
    ]
    for name in docs:
        copy_if_exists(ROOT / name, room / name)

    write_pdf(
        room / "architecture_summary.pdf",
        "Sovereign Shield Architecture Summary",
        [
            "Category: Human-Governed Enterprise Security Platform for Private AI Governance.",
            "Core path: enterprise app -> Sovereign Shield proxy -> redaction/DLP/prompt-injection checks -> policy explanation -> local/cloud router -> model.",
            "Client path: Next.js web, Tauri desktop, and React Native mobile consoles -> shared TypeScript SDK -> FastAPI gateway.",
            "Default positioning: local-first AI using Ollama, with high-sensitivity prompts forced to private inference and critical actions kept operator-controlled.",
            "Evidence path: every security decision and approval record can be written to a tamper-evident JSONL ledger and summarized into PDF reports.",
        ],
    )
    write_pdf(
        room / "security_controls.pdf",
        "Security Controls Checklist",
        [
            "Auth: JWT, RBAC, token revocation, disabled-user enforcement.",
            "Cross-platform auth: refresh-token rotation, device session tracking, and device revocation.",
            "Gateway: rate limiting, cost controls, request size limits, suspicious path blocking.",
            "Network: strict CORS, secure headers, mTLS support via Nginx/Envoy verified headers.",
            "AI Governance: PII detection, pseudonymization, prompt injection blocking, semantic DLP, local routing, and human-directed critical actions.",
            "Audit: salted SHA-256 hash-chained JSONL ledger and evidence PDF certificates.",
            "Operations: pnpm deploy:enterprise, pnpm submit:ready, pnpm demo:investor, pnpm generate:data-room.",
        ],
    )
    write_pdf(
        room / "known_limitations.pdf",
        "Known Limitations",
        [
            "Demo metrics are simulated validation data, not customer usage, revenue, or traction.",
            "Compliance mapping is implementation evidence, not legal certification.",
            "mTLS enforcement expects a buyer-controlled reverse proxy.",
            "Redis is recommended for production multi-node state.",
            "Off-box immutable ledger anchoring must be configured by the buyer.",
            "Local model performance depends on buyer-selected Ollama model and hardware.",
        ],
    )
    write_pdf(
        room / "deployment_guide.pdf",
        "Enterprise Deployment Guide",
        [
            "Run pnpm deploy:enterprise for local launch and validation.",
            "Run pnpm submit:ready before buyer submission or handoff.",
            "Production mode should set JWT_SECRET_KEY, LICENSE_MASTER_SECRET, ACTOR_HASH_SALT, LEDGER_MASTER_SALT, and ALLOWED_ORIGINS.",
            "Use Nginx/Envoy for mTLS termination and forward verified certificate headers to the gateway.",
        ],
    )

    screenshots_src = ROOT / "docs" / "screenshots"
    if screenshots_src.exists():
        shutil.copytree(screenshots_src, room / "screenshots", dirs_exist_ok=True)

    demo_src = ROOT / "docs" / "demo"
    if demo_src.exists():
        shutil.copytree(demo_src, room / "demo", dirs_exist_ok=True)

    iac_src = ROOT / "iac"
    if iac_src.exists():
        shutil.copytree(iac_src, room / "iac", dirs_exist_ok=True)

    api_spec = room / "api_docs_openapi.json"
    try:
        import sys
        sys.path.insert(0, str(ROOT / "backend"))
        from app import app
        api_spec.write_text(json.dumps(app.openapi(), indent=2))
    except Exception as exc:
        api_spec.write_text(json.dumps({"error": str(exc), "note": "Run with backend dependencies installed."}, indent=2))

    manifest = {
        "product": "Sovereign Shield",
        "company": "Xavira Tech Labs",
        "category": "Human-Governed Enterprise Security Platform for Private AI Governance",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "Demo usage metrics are simulated; no customer or revenue claims are made.",
        "contents": sorted(str(p.relative_to(room)) for p in room.rglob("*") if p.is_file()),
        "governed_resilience": {
            "guardian": "backend/llm_guardian.py",
            "legacy_demo_endpoint": "GET /demo/tier3-self-healing",
            "ha_runbook": "docs/HA_RUNBOOK.md",
            "iac": ["iac/terraform/aws", "iac/cloudformation/sovereign-shield-ha.yaml"],
        },
        "cross_platform": {
            "web": "apps/web",
            "desktop": "apps/desktop",
            "mobile": "apps/mobile",
            "shared_sdk": "packages/sdk",
            "design_system": "packages/design-system",
            "release_workflow": ".github/workflows/cross-platform-release.yml",
        },
    }
    (room / "DATA_ROOM_MANIFEST.json").write_text(json.dumps(manifest, indent=2))

    zip_path = OUT / f"{room.name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in room.rglob("*"):
            if path.is_file():
                zf.write(path, str(path.relative_to(room.parent)))
    print(json.dumps({"status": "DATA_ROOM_READY", "folder": str(room), "zip": str(zip_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
