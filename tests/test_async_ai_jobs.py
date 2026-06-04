import os
import sys
import time

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

import app as app_module  # noqa: E402
from app import app, get_active_user  # noqa: E402
from auth.jwt_handler import TokenPayload  # noqa: E402
from db.session import init_db  # noqa: E402
from shadow_ai.detector import require_shadow_admin  # noqa: E402


def super_admin():
    return TokenPayload(
        sub="admin@sentinel.local",
        email="admin@sentinel.local",
        role="SUPER_ADMIN",
        department="GLOBAL_SECURITY",
        tenant_id="default",
    )


def test_ai_heavy_routes_accept_async_jobs(monkeypatch):
    init_db()
    app.dependency_overrides[get_active_user] = super_admin
    app.dependency_overrides[require_shadow_admin] = super_admin
    client = TestClient(app)

    monkeypatch.setattr(app_module.model_router, "route", lambda *args, **kwargs: {
        "answer": "Protected [Aadhaar_1] response",
        "model_used": "ollama/test",
        "fallback_used": False,
    })
    monkeypatch.setattr(app_module.shadow_detector, "scan_once", lambda user_hint="SYSTEM": [])

    accepted = [
        client.post("/api/v2/chat", json={"message": "hello"}),
        client.post("/api/v2/chat/stream", json={"message": "hello"}),
        client.post("/ask", json={"prompt": "hello"}),
        client.post("/api/v2/enterprise/model-benchmark"),
        client.post("/shadow-ai/scan"),
    ]
    for response in accepted:
        assert response.status_code == 202
        body = response.json()
        assert body["job_id"]
        assert body["status"] == "queued"
        assert body["status_url"].startswith("/api/v2/jobs/")
        assert body["result_url"].startswith("/api/v2/jobs/")
        assert body["cancel_url"].startswith("/api/v2/jobs/")

    for response in accepted:
        job_id = response.json()["job_id"]
        deadline = time.time() + 5
        while time.time() < deadline:
            result = client.get(f"/api/v2/jobs/{job_id}/result")
            if result.status_code == 200:
                assert result.json()["ready"] is True
                break
            assert result.status_code == 202
            time.sleep(0.05)
        else:
            raise AssertionError(f"job did not complete: {job_id}")

    chat_result = client.get(f"/api/v2/jobs/{accepted[0].json()['job_id']}/result")
    assert chat_result.json()["result"]["model_used"] == "ollama/test"
