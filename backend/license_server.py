"""
Sovereign Shield v2 — Automated License Server
Handles license key generation, activation, validation, expiry, and seat tracking.
Designed to replace the manual email → key workflow with a full API.
"""
import os
import json
import uuid
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
try:
    from config import security_settings
    from auth.jwt_handler import TokenPayload, get_current_user
    from auth.rbac_engine import Permission, rbac
    from db.models import User
    from db.session import get_db
except ImportError:
    from .config import security_settings
    from .auth.jwt_handler import TokenPayload, get_current_user
    from .auth.rbac_engine import Permission, rbac
    from .db.models import User
    from .db.session import get_db

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LICENSE_DB = os.path.join(BASE_DIR, "logs", "licenses.jsonl")
LICENSE_DB_DIR = os.path.dirname(LICENSE_DB)

MASTER_SECRET = security_settings()["license_master_secret"]

router = APIRouter(prefix="/license", tags=["License"])


# ── Pydantic Schemas ────────────────────────────────────────────────────────

class LicenseIssueRequest(BaseModel):
    organization: str
    email: str
    seats: int = 5
    plan: str = "ENTERPRISE"        # STARTER | PRO | ENTERPRISE
    deployment_mode: str = "airgap" # airgap | cloud
    hardware_id: Optional[str] = None
    valid_days: int = 365

class LicenseActivateRequest(BaseModel):
    license_key: str
    hardware_id: str
    organization: str

class LicenseValidateRequest(BaseModel):
    license_key: str
    hardware_id: Optional[str] = None


# ── Core License Engine ─────────────────────────────────────────────────────

class LicenseServer:
    """Automated license key lifecycle management."""

    def __init__(self):
        os.makedirs(LICENSE_DB_DIR, exist_ok=True)

    def _generate_key(self, email: str, plan: str, hardware_id: Optional[str]) -> str:
        """
        Generates a deterministic license key.
        Format: SNTL-XXXX-XXXX-XXXX-XXXX (Sentinel-style)
        """
        seed = f"{MASTER_SECRET}:{email}:{plan}:{hardware_id or 'CLOUD'}:{secrets.token_hex(8)}"
        h = hashlib.sha256(seed.encode()).hexdigest().upper()
        return f"SNTL-{h[:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}"

    def _load_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(LICENSE_DB):
            return []
        with open(LICENSE_DB, "r") as f:
            return [json.loads(l) for l in f if l.strip()]

    def _find_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        for lic in self._load_all():
            if lic.get("license_key") == key:
                return lic
        return None

    def _save_record(self, record: Dict[str, Any]):
        """Upsert (overwrite existing key, append new)."""
        all_records = self._load_all()
        updated = False
        for i, r in enumerate(all_records):
            if r.get("license_key") == record["license_key"]:
                all_records[i] = record
                updated = True
                break
        if not updated:
            all_records.append(record)

        with open(LICENSE_DB, "w") as f:
            for r in all_records:
                f.write(json.dumps(r) + "\n")

    def issue(self, req: LicenseIssueRequest) -> Dict[str, Any]:
        """Issue a new license key. Returns the full record."""
        key = self._generate_key(req.email, req.plan, req.hardware_id)
        issued_at = datetime.now(timezone.utc).isoformat()
        expires_at = (datetime.now(timezone.utc) + timedelta(days=req.valid_days)).isoformat()

        record = {
            "license_key":     key,
            "license_id":      str(uuid.uuid4()),
            "organization":    req.organization,
            "email":           req.email,
            "plan":            req.plan,
            "deployment_mode": req.deployment_mode,
            "hardware_id":     req.hardware_id,
            "seats_total":     req.seats,
            "seats_used":      0,
            "issued_at":       issued_at,
            "expires_at":      expires_at,
            "is_active":       True,
            "activated_at":    None,
            "activations":     [],
        }
        self._save_record(record)
        return record

    def activate(self, req: LicenseActivateRequest) -> Dict[str, Any]:
        """Activate a license key on a specific machine."""
        record = self._find_by_key(req.license_key)
        if not record:
            raise HTTPException(status_code=404, detail="License key not found")
        if not record.get("is_active"):
            raise HTTPException(status_code=403, detail="License is deactivated")

        # Expiry check
        exp = datetime.fromisoformat(record["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            raise HTTPException(status_code=403, detail="License has expired")

        # Seat check
        if record["seats_used"] >= record["seats_total"]:
            raise HTTPException(
                status_code=403,
                detail=f"Seat limit reached ({record['seats_total']} seats). Contact Xavira Tech Labs to expand."
            )

        # Hardware lock check (for airgap licenses)
        if record["hardware_id"] and record["hardware_id"] != req.hardware_id:
            raise HTTPException(
                status_code=403,
                detail="Hardware ID mismatch. This license is locked to a different machine."
            )

        # Record activation
        activation = {
            "hardware_id":    req.hardware_id,
            "organization":   req.organization,
            "activated_at":   datetime.now(timezone.utc).isoformat(),
        }
        record["activations"].append(activation)
        record["seats_used"] += 1
        record["activated_at"] = record["activated_at"] or activation["activated_at"]
        self._save_record(record)

        return {
            "status": "ACTIVATED",
            "license_key": req.license_key,
            "plan": record["plan"],
            "seats_remaining": record["seats_total"] - record["seats_used"],
            "expires_at": record["expires_at"],
            "deployment_mode": record["deployment_mode"],
        }

    def validate(self, req: LicenseValidateRequest) -> Dict[str, Any]:
        """Validate a license key and return its current status."""
        record = self._find_by_key(req.license_key)
        if not record:
            return {"valid": False, "reason": "KEY_NOT_FOUND"}
        if not record.get("is_active"):
            return {"valid": False, "reason": "DEACTIVATED"}

        exp = datetime.fromisoformat(record["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            return {"valid": False, "reason": "EXPIRED", "expired_at": record["expires_at"]}

        if req.hardware_id and record.get("hardware_id") and record["hardware_id"] != req.hardware_id:
            return {"valid": False, "reason": "HARDWARE_MISMATCH"}

        return {
            "valid": True,
            "plan": record["plan"],
            "organization": record["organization"],
            "seats_total": record["seats_total"],
            "seats_used": record["seats_used"],
            "expires_at": record["expires_at"],
            "deployment_mode": record["deployment_mode"],
        }

    def revoke(self, license_key: str) -> bool:
        """Revoke (deactivate) a license."""
        record = self._find_by_key(license_key)
        if not record:
            return False
        record["is_active"] = False
        record["revoked_at"] = datetime.now(timezone.utc).isoformat()
        self._save_record(record)
        return True

    def list_licenses(self) -> List[Dict[str, Any]]:
        """Return all license records (admin view)."""
        return self._load_all()


# ── FastAPI Routes ──────────────────────────────────────────────────────────

_server = LicenseServer()


def require_license_admin(current_user: TokenPayload = Depends(get_current_user), db=Depends(get_db)) -> TokenPayload:
    user = db.query(User).filter(User.email == current_user.sub).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="USER_DISABLED_OR_NOT_FOUND")
    rbac.enforce(current_user.role, Permission.MANAGE_LICENSES)
    return current_user


@router.post("/issue")
def issue_license(
    req: LicenseIssueRequest,
    current_user: TokenPayload = Depends(require_license_admin),
) -> Dict[str, Any]:
    """Issue a new license key."""
    _ = current_user
    return _server.issue(req)


@router.post("/activate")
def activate_license(req: LicenseActivateRequest) -> Dict[str, Any]:
    """Activate a license key on a machine."""
    return _server.activate(req)


@router.post("/validate")
def validate_license(req: LicenseValidateRequest) -> Dict[str, Any]:
    """Validate a license key."""
    return _server.validate(req)


@router.get("/list")
def list_licenses(current_user: TokenPayload = Depends(require_license_admin)) -> List[Dict[str, Any]]:
    """List all licenses (admin endpoint)."""
    _ = current_user
    return _server.list_licenses()


@router.delete("/{license_key}")
def revoke_license(
    license_key: str,
    current_user: TokenPayload = Depends(require_license_admin),
) -> Dict[str, Any]:
    """Revoke a license key."""
    _ = current_user
    ok = _server.revoke(license_key)
    if not ok:
        raise HTTPException(status_code=404, detail="License not found")
    return {"status": "REVOKED", "license_key": license_key}
