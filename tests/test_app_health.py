import os
import sys
import importlib
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

app_module = importlib.import_module("app")
app = app_module.app


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


def test_local_control_room_uses_cached_diagnostics_by_default(monkeypatch):
    def fail_if_called():
        raise AssertionError("default control-room request should not refresh heavy diagnostics")

    monkeypatch.setattr(app_module.sentinel_check, "run_all", fail_if_called)
    response = client.get("/api/v2/local/control-room")

    assert response.status_code == 200
    assert response.json()["mode"] == "LOCAL_REALTIME_CONTROL_ROOM"


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


def test_frontend_suite_uses_enterprise_shell_navigation_contract():
    pages = {
        "command": FRONTEND_SITE / "index.html",
        "ops": FRONTEND_SITE / "ops" / "index.html",
        "proof": FRONTEND_SITE / "proof" / "index.html",
        "admin": FRONTEND_SITE / "demo" / "index.html",
        "license": FRONTEND_SITE / "pricing" / "index.html",
    }

    for page_key, path in pages.items():
        html = path.read_text(encoding="utf-8")
        assert 'class="app-shell"' in html
        assert f'data-page="{page_key}"' in html
        assert '<aside class="side-nav" id="side-nav"></aside>' in html
        assert '<header class="top-bar" id="top-bar"></header>' in html
        assert '<script src="/config.js"></script>' in html
        assert '<script src="/shell.js"></script>' in html


def test_overview_page_is_enterprise_command_center_not_marketing_page():
    html = (FRONTEND_SITE / "index.html").read_text(encoding="utf-8")

    assert "Enterprise AI Security Command Center" in html
    assert "Active Security Queue" in html
    assert "Control Plane Snapshot" in html
    assert "Operator Actions" in html
    assert "Sign in to load protected surfaces" not in html
    assert "packaged as a security asset" not in html
    assert "Acquisition" not in html


def test_enterprise_shell_palette_uses_institutional_tokens():
    css = (FRONTEND_SITE / "styles.css").read_text(encoding="utf-8")

    assert "--nav: #101820;" in css
    assert "--blue: #2457c5;" in css
    assert "--radius: 8px;" in css
    assert ".app-shell" in css
    assert ".side-nav" in css
    assert ".top-bar" in css
    for stale_token in ("asset-app", "asset-nav", "#34d399", "#10b981", "52, 211, 153", "16, 185, 129"):
        assert stale_token not in css


def test_enterprise_shell_uses_runtime_config_auth_and_command_navigation():
    shell = (FRONTEND_SITE / "shell.js").read_text(encoding="utf-8")
    overview = (FRONTEND_SITE / "index.html").read_text(encoding="utf-8")
    config = (FRONTEND_SITE / "config.js").read_text(encoding="utf-8")

    for label in ("Command Center", "Operations", "Evidence", "Administration", "Licensing"):
        assert label in shell
    assert "SOVEREIGN_CONFIG" in config
    assert "API_BASE_URL" in config
    assert "apiBase" in shell
    assert "auth-form" in shell
    assert "/api/v2/auth/login" in shell
    assert 'class="kpi-grid"' in overview
    assert "Runtime Seal" in overview
    assert "Acquisition-grade operator asset" not in shell
