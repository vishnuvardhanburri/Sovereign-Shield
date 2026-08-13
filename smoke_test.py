"""
Sentinel Shield v2 — End-to-End Smoke Test
Verifies all core modules: Auth, Audit, Policy, Compliance, Gateway, and Shadow AI.
"""
import requests
import json
import time
import sys
import os

os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"
os.environ.setdefault("JWT_SECRET_KEY", "ci_jwt_secret_64_chars_minimum_for_fail_closed_loader_2026_xavira")
os.environ.setdefault("LICENSE_MASTER_SECRET", "ci_license_secret_64_chars_minimum_for_fail_closed_loader_2026_xavira")
os.environ.setdefault("ACTOR_HASH_SALT", "ci_actor_hash_salt_32_chars_minimum_2026")
os.environ.setdefault("LEDGER_MASTER_SALT", "ci_ledger_hash_salt_32_chars_minimum_2026")

API_BASE = os.getenv("API_BASE", "http://localhost:8000")

def log_test(name, success, detail=""):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"[{status}] {name}")
    if not success and detail:
        print(f"    Error: {detail}")

def get_client():
    """Returns a requests session or FastAPI TestClient fallback."""
    try:
        resp = requests.get(f"{API_BASE}/api/health", timeout=1.5)
        if resp.status_code == 200:
            session = requests.Session()
            session.trust_env = False
            return session, API_BASE
    except Exception:
        pass

    # Fall back to in-process FastAPI TestClient
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
    from db.session import SessionLocal, init_db, User, pwd_context
    init_db()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "admin@demo.com").first()
        if not user:
            demo_user = User(
                id="demo-admin-id",
                email="admin@demo.com",
                full_name="Demo Admin",
                hashed_password=pwd_context.hash("demo1234"),
                role="SUPER_ADMIN",
                department="GLOBAL_SECURITY",
                is_active=True,
                metadata_={"force_password_change": False}
            )
            db.add(demo_user)
            db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()

    from app import app
    from fastapi.testclient import TestClient
    client = TestClient(app)
    return client, ""

def run_smoke_test():
    print("🚀 Starting Sentinel Shield v2 End-to-End Smoke Test...\n")
    client, base_url = get_client()

    def make_req(method, endpoint, **kwargs):
        url = f"{base_url}{endpoint}" if base_url else endpoint
        if method.lower() == "get":
            return client.get(url, **kwargs)
        elif method.lower() == "post":
            return client.post(url, **kwargs)

    # ── 1. Auth Test (Login) ──────────────────────────────────────────────────
    token = ""
    try:
        resp = make_req("post", "/auth/login", json={
            "email": "admin@demo.com",
            "password": "demo1234"
        })
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            log_test("Authentication (Login)", True)
        else:
            log_test("Authentication (Login)", False, f"Status {resp.status_code}: {resp.text}")
            return
    except Exception as e:
        log_test("Authentication (Login)", False, str(e))
        return

    headers = {"Authorization": f"Bearer {token}"}

    # ── 2. System Status Test ─────────────────────────────────────────────────
    try:
        resp = make_req("get", "/status", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            log_test("System Status Check", True)
            print(f"    Mode: {data.get('infra', {}).get('deployment_mode')}")
            print(f"    Audit Chain: {'Intact' if data.get('audit', {}).get('chain_integrity') else 'BROKEN'}")
        else:
            log_test("System Status Check", False, resp.text)
    except Exception as e:
        log_test("System Status Check", False, str(e))

    # ── 3. Governed AI Query (PII Redaction + Policy) ─────────────────────────
    try:
        test_prompt = "Patient Aadhaar: 2345 6789 0123 has been admitted to the ICU."
        print(f"\nTesting Query with Aadhaar: '{test_prompt}'")
        resp = make_req("post", "/ask", headers=headers, json={
            "prompt": test_prompt,
            "department": "HOSPITAL"
        })
        
        if resp.status_code == 202:
            data = resp.json()
            log_test("Governed AI Query (Async Job Queued)", True)
            print(f"    Job ID: {data.get('job_id')}, Status: {data.get('status')}")
        elif resp.status_code == 403:
            data = resp.json().get("detail", {})
            log_test("PII Policy Enforcement (BLOCK)", True)
            print(f"    Action: {data.get('action')}, Reason: {data.get('reason')}")
        elif resp.status_code == 200:
            data = resp.json()
            if "REDACTED" in data.get("answer", "") or data.get("redactions_applied", 0) > 0:
                log_test("PII Policy Enforcement (REDACT)", True)
            else:
                log_test("PII Policy Enforcement", False, "No redaction applied to sensitive data")
        else:
            log_test("Governed AI Query", False, resp.text)
    except Exception as e:
        log_test("Governed AI Query", False, str(e))

    # ── 4. Audit Log Test ─────────────────────────────────────────────────────
    try:
        resp = make_req("get", "/audit/log?limit=5", headers=headers)
        if resp.status_code == 200:
            entries = resp.json().get("entries", [])
            if len(entries) > 0:
                log_test("Audit Ledger Retrieval", True)
                print(f"    Last Event: {entries[0].get('action')} by {entries[0].get('user_id')}")
            else:
                log_test("Audit Ledger Retrieval", False, "No entries found in log")
        else:
            log_test("Audit Ledger Retrieval", False, resp.text)
    except Exception as e:
        log_test("Audit Ledger Retrieval", False, str(e))

    # ── 5. Compliance Scoring Test ────────────────────────────────────────────
    try:
        resp = make_req("get", "/compliance/score", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            log_test("Compliance Scoring Engine", True)
            print(f"    Global Grade: {data.get('grade')} (Score: {data.get('composite_score')})")
        else:
            log_test("Compliance Scoring Engine", False, resp.text)
    except Exception as e:
        log_test("Compliance Scoring Engine", False, str(e))

    # ── 6. Shadow AI Detection Test ───────────────────────────────────────────
    try:
        resp = make_req("post", "/shadow-ai/scan", headers=headers)
        if resp.status_code in (200, 202):
            data = resp.json()
            log_test("Shadow AI Scanning Engine", True)
            if resp.status_code == 202:
                print(f"    Async Job ID: {data.get('job_id')}, Status: {data.get('status')}")
            else:
                print(f"    Domains Scanned: {data.get('scanned')}, Detections: {data.get('detected')}")
        else:
            log_test("Shadow AI Scanning Engine", False, resp.text)
    except Exception as e:
        log_test("Shadow AI Scanning Engine", False, str(e))

    # ── 7. License Server Test ────────────────────────────────────────────────
    try:
        resp = make_req("get", "/license/list", headers=headers)
        if resp.status_code == 200:
            log_test("License Server API", True)
        else:
            log_test("License Server API", False, resp.text)
    except Exception as e:
        log_test("License Server API", False, str(e))

    print("\n🏁 Smoke Test Finished.")

if __name__ == "__main__":
    run_smoke_test()
