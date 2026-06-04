import os
import sys
import time

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

from app import app, get_active_user  # noqa: E402
from auth.jwt_handler import TokenPayload  # noqa: E402
from db.session import init_db  # noqa: E402
from integrations.webhook_engine import WebhookDispatcher, WebhookPayload, OutboundWebhook  # noqa: E402


def super_admin():
    return TokenPayload(
        sub="admin@sentinel.local",
        email="admin@sentinel.local",
        role="SUPER_ADMIN",
        department="GLOBAL_SECURITY",
        tenant_id="default",
    )


def client():
    init_db()
    app.dependency_overrides[get_active_user] = super_admin
    return TestClient(app)


def wait_for_job(c: TestClient, job_id: str, timeout_seconds: float = 5.0):
    deadline = time.time() + timeout_seconds
    last_status = None
    while time.time() < deadline:
        status = c.get(f"/api/v2/jobs/{job_id}/status")
        assert status.status_code == 200
        last_status = status.json()["status"]
        if last_status == "succeeded":
            result = c.get(f"/api/v2/jobs/{job_id}/result")
            assert result.status_code == 200
            return result.json()["result"]
        if last_status in {"failed", "cancelled", "timeout"}:
            result = c.get(f"/api/v2/jobs/{job_id}/result")
            raise AssertionError(f"job ended as {last_status}: {result.json()}")
        time.sleep(0.05)
    raise AssertionError(f"job did not finish, last status={last_status}")


def test_deployment_doctor_license_usage_and_model_benchmark(monkeypatch):
    c = client()
    monkeypatch.setenv("SENTINEL_LICENSE_DEMO_MODE", "true")
    license_check = c.post("/api/v1/license/validate", json={"tenant_id": "default"})
    assert license_check.status_code == 200
    assert license_check.json()["valid"] is True

    demo_metrics = c.get("/demo/metrics")
    assert demo_metrics.status_code == 200
    assert demo_metrics.json()["mode"] == "SIMULATED_ENTERPRISE_USAGE"

    badge = c.get("/api/v2/enterprise/badge")
    assert badge.status_code == 200
    assert badge.json()["company"] == "Xavira Tech Labs"

    doctor = c.get("/api/v2/enterprise/deployment-doctor")
    assert doctor.status_code == 200
    assert "checks" in doctor.json()

    usage = c.get("/api/v2/enterprise/license-usage")
    assert usage.status_code == 200
    assert "active_users" in usage.json()

    monkeypatch.setattr("app.model_router.route", lambda prompt, sensitivity_score=8.0: {
        "answer": "Protected [Aadhaar_1] response",
        "model_used": "ollama/test",
        "fallback_used": False,
    })
    bench = c.post("/api/v2/enterprise/model-benchmark")
    assert bench.status_code == 202
    assert bench.json()["status_url"].startswith("/api/v2/jobs/")
    benchmark_result = wait_for_job(c, bench.json()["job_id"])
    assert len(benchmark_result["results"]) == 3

    demo_control_room = c.get("/demo/control-room")
    assert demo_control_room.status_code == 200
    assert demo_control_room.json()["mode"] == "SIMULATED_ENTERPRISE_CONTROL_ROOM"

    with c.stream("GET", "/demo/control-room/stream?max_events=1&interval_seconds=1") as response:
        payload = response.read().decode()
    assert "event: control-room" in payload


def test_break_glass_tenant_export_import_and_policy_versions():
    c = client()
    bg = c.post("/api/v2/enterprise/break-glass", json={
        "reason": "Emergency buyer recovery drill",
        "duration_minutes": 15,
    })
    assert bg.status_code == 200
    assert bg.json()["break_glass_token"]

    exported = c.get("/api/v2/enterprise/tenant/export")
    assert exported.status_code == 200
    assert exported.json()["certificate"]

    imported = c.post("/api/v2/enterprise/tenant/import", json={
        "bundle": exported.json(),
        "dry_run": True,
    })
    assert imported.status_code == 200
    assert imported.json()["status"] == "DRY_RUN_OK"

    version = c.post("/api/v2/enterprise/policy-versions", json={
        "bundle_name": "buyer-policy-v1",
        "yaml_content": "rules: []",
        "approval_state": "approved",
    })
    assert version.status_code == 200
    assert version.json()["version"]["certificate"]

    versions = c.get("/api/v2/enterprise/policy-versions")
    assert versions.status_code == 200
    assert versions.json()["versions"]


def test_guided_buyer_demo_runs_with_synthetic_data():
    response = client().post("/api/v2/enterprise/demo/run")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "GUIDED_DEMO_COMPLETE"
    assert "2345 6789 0123" not in body["proxy"]["protected_text"]
    assert body["report"]["certificate"]


def test_webhook_dispatcher_queues_failed_delivery(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_WEBHOOK_TARGETS", "true")
    monkeypatch.setenv("ALLOW_HTTP_WEBHOOK_TARGETS", "true")
    dispatcher = WebhookDispatcher()
    dispatcher._registry = []
    dispatcher._registry_path = lambda: str(tmp_path / "registry.json")
    dispatcher._queue_path = lambda: str(tmp_path / "queue.jsonl")
    hook_id = dispatcher.register(OutboundWebhook(
        target_url="http://127.0.0.1:9/nowhere",
        event_types=["CISO_ALERT"],
        tenant_id="default",
    ))
    assert hook_id
    dispatcher.dispatch(WebhookPayload(event_type="CISO_ALERT", payload={"x": 1}))
    queued = dispatcher.queued_deliveries()
    assert len(queued) == 1
