import base64
import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

from app import app, _totp_code  # noqa: E402
from auth.jwt_handler import create_access_token  # noqa: E402
from db.models import User  # noqa: E402
from db.session import SessionLocal, init_db, pwd_context  # noqa: E402


def _admin_headers() -> dict[str, str]:
    _upsert_user("admin@sentinel.local", "TemporaryPass123!")
    token = create_access_token(
        {
            "sub": "admin@sentinel.local",
            "email": "admin@sentinel.local",
            "role": "SUPER_ADMIN",
            "department": "GLOBAL_SECURITY",
            "tenant_id": "default",
        }
    )
    return {"Authorization": f"Bearer {token}"}


def _upsert_user(email: str, password: str, *, mfa_secret: str | None = None):
    init_db()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                id=email,
                email=email,
                full_name=email.split("@")[0],
                hashed_password=pwd_context.hash(password),
                role="SUPER_ADMIN",
                department="GLOBAL_SECURITY",
                tenant_id="default",
                is_active=True,
                metadata_={},
            )
            db.add(user)
        else:
            user.hashed_password = pwd_context.hash(password)
            user.is_active = True
        if mfa_secret:
            user.mfa_enabled = True
            user.metadata_ = {"mfa_secret": mfa_secret}
        else:
            user.mfa_enabled = False
            user.metadata_ = {}
        db.commit()
    finally:
        db.close()


def test_mounted_admin_routers_require_authentication():
    c = TestClient(app)

    assert c.post("/license/issue", json={"organization": "Buyer", "email": "buyer@example.com"}).status_code in {401, 403}
    assert c.get("/integrations/webhooks").status_code in {401, 403}
    assert c.get("/shadow-ai/summary").status_code in {401, 403}


def test_webhook_registration_rejects_private_network_ssrf(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_WEBHOOK_TARGETS", raising=False)
    monkeypatch.setenv("ALLOW_HTTP_WEBHOOK_TARGETS", "true")
    response = TestClient(app).post(
        "/integrations/webhooks/register",
        headers=_admin_headers(),
        json={"target_url": "http://127.0.0.1:9/metadata", "event_types": ["CISO_ALERT"], "tenant_id": "default"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "OUTBOUND_URL_PRIVATE_NETWORK_FORBIDDEN"


def test_license_validation_fails_closed_without_demo_or_key(monkeypatch):
    monkeypatch.delenv("SENTINEL_LICENSE_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_LICENSE_DEMO_MODE", raising=False)

    response = TestClient(app).post("/api/v1/license/validate", json={"tenant_id": "default"})

    assert response.status_code == 402
    assert response.json()["detail"] == "LICENSE_REQUIRED"


def test_login_enforces_mfa_for_enabled_user():
    secret = base64.b32encode(b"01234567890123456789").decode()
    email = "mfa-admin@sovereign.local"
    password = "TemporaryPass123!"
    _upsert_user(email, password, mfa_secret=secret)
    c = TestClient(app)

    missing = c.post("/api/v2/auth/login", json={"email": email, "password": password})
    assert missing.status_code == 401
    assert missing.json()["detail"] == "MFA_CODE_REQUIRED"

    valid = c.post("/api/v2/auth/login", json={"email": email, "password": password, "mfa_code": _totp_code(secret)})
    assert valid.status_code == 200
    assert valid.json()["tokens"]["accessToken"]


def test_revoked_device_session_refresh_token_is_rejected():
    email = "session-admin@sovereign.local"
    password = "TemporaryPass123!"
    _upsert_user(email, password)
    c = TestClient(app)

    login = c.post(
        "/api/v2/auth/login",
        json={
            "email": email,
            "password": password,
            "device": {"device_id": "revocation-test", "platform": "web"},
        },
    )
    assert login.status_code == 200
    body = login.json()
    access = body["tokens"]["accessToken"]
    refresh = body["tokens"]["refreshToken"]
    session_id = body["device_session"]["id"]

    revoked = c.post(
        "/api/v2/devices/sessions/revoke",
        headers={"Authorization": f"Bearer {access}"},
        json={"session_id": session_id},
    )
    assert revoked.status_code == 200

    refresh_attempt = c.post("/api/v2/auth/refresh", json={"refresh_token": refresh})
    assert refresh_attempt.status_code == 401
    assert refresh_attempt.json()["detail"] in {"Token revoked", "REFRESH_SESSION_REVOKED"}


def test_encoded_env_probe_is_blocked():
    response = TestClient(app).get("/%2eenv")

    assert response.status_code == 404
    assert response.json()["detail"] == "NOT_FOUND"
