import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

from app import app


client = TestClient(app)
REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_SITE = REPO_ROOT / "frontend" / "site"


def test_health_endpoint_has_security_headers():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] in {"awake", "healthy"}
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_root_endpoint_is_xavira_branded():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["signature"] == "BY XAVIRA TECH LABS"


def test_suspicious_env_probe_is_blocked():
    response = client.get("/.env")

    assert response.status_code == 404
    assert response.json()["detail"] == "NOT_FOUND"


def test_local_control_room_reports_real_device_snapshot():
    response = client.get("/api/v2/local/control-room")

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "LOCAL_REALTIME_CONTROL_ROOM"
    assert body["gateway"]["status"] in {"awake", "healthy"}
    assert body["device"]["hostname"]
    assert body["device"]["platform"]
    assert "disk" in body["device"]
    assert body["live_stream_url"] == "/api/v2/local/control-room/stream"


def test_local_proof_endpoint_masks_input_and_returns_real_diagnostics():
    response = client.post(
        "/api/v2/local/proxy/proof",
        json={
            "text": "Customer Aadhaar 2345 6789 0123 and PAN ABCDE1234F must stay local.",
            "actor": "local-health-test",
            "source_app": "pytest",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "LOCAL_REALTIME_PROOF"
    assert body["protected_prompt"] != body["raw_prompt"]
    assert "[Aadhaar_" in body["protected_prompt"]
    assert "device" in body
    assert body["device"]["platform"]


def test_local_evidence_certificate_uses_real_ledger_surface():
    response = client.get("/api/v2/local/evidence-certificate")

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "LOCAL_REALTIME_EVIDENCE"
    assert body["certificate"]
    assert "download_url" in body


def test_frontend_suite_uses_asset_shell_navigation_contract():
    pages = {
        "overview": FRONTEND_SITE / "index.html",
        "control": FRONTEND_SITE / "ops" / "index.html",
        "proof": FRONTEND_SITE / "proof" / "index.html",
        "trust": FRONTEND_SITE / "demo" / "index.html",
        "commercial": FRONTEND_SITE / "pricing" / "index.html",
    }

    for suite_page, path in pages.items():
        html = path.read_text(encoding="utf-8")
        assert 'class="asset-app"' in html
        assert f'data-suite-page="{suite_page}"' in html
        assert '<aside class="asset-nav" id="asset-nav"></aside>' in html
        assert '<script src="/shell.js"></script>' in html


def test_overview_page_is_asset_registry_not_demo_console():
    html = (FRONTEND_SITE / "index.html").read_text(encoding="utf-8")

    assert "Runtime Abstract" in html
    assert "Security Architecture" in html
    assert "Verification Paths" in html
    assert "Asset Registry" in html
    assert "Live Gateway Test" not in html


def test_asset_shell_palette_removes_green_branding_tokens():
    css = (FRONTEND_SITE / "styles.css").read_text(encoding="utf-8")

    assert "--accent-rgb: 143, 216, 255;" in css
    assert "--warm-rgb: 245, 181, 88;" in css
    for stale_token in ("#34d399", "#10b981", "52, 211, 153", "16, 185, 129"):
        assert stale_token not in css


def test_asset_shell_uses_numbered_navigation_and_summary():
    shell = (FRONTEND_SITE / "shell.js").read_text(encoding="utf-8")
    overview = (FRONTEND_SITE / "index.html").read_text(encoding="utf-8")

    for index in ('index: "01"', 'index: "02"', 'index: "03"', 'index: "04"', 'index: "05"'):
        assert index in shell
    assert "Acquisition-grade operator asset" in shell
    assert 'class="summary-table"' in overview
    assert "Primary buyer path" in overview
