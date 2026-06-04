"""
Sovereign Shield v2 — Database Models (SQLAlchemy ORM)
Structured storage for users, audit entries, policy configs, and license seats.
PostgreSQL in cloud mode; SQLite for air-gap/local installs.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    Text, JSON, ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id              = Column(String(36), primary_key=True)  # UUID
    email           = Column(String(255), unique=True, nullable=False, index=True)
    full_name       = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role            = Column(String(50), default="STAFF", nullable=False)
    department      = Column(String(100), nullable=True)
    tenant_id       = Column(String(100), default="default", nullable=False, index=True)
    is_active       = Column(Boolean, default=True)
    sso_provider    = Column(String(50), nullable=True)   # azure_ad | google | none
    sso_subject_id  = Column(String(255), nullable=True)
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login      = Column(DateTime, nullable=True)
    mfa_enabled     = Column(Boolean, default=False)
    metadata_       = Column("metadata", JSON, default=dict)

    sessions        = relationship("UserSession", back_populates="user", cascade="all, delete")

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"


class APIKey(Base):
    __tablename__ = "api_keys"

    id              = Column(String(36), primary_key=True)
    tenant_id       = Column(String(100), default="default", nullable=False, index=True)
    name            = Column(String(255), nullable=False)
    key_prefix      = Column(String(24), nullable=False, index=True)
    key_hash        = Column(String(64), unique=True, nullable=False, index=True)
    scopes          = Column(JSON, default=list)
    department      = Column(String(100), nullable=True)
    created_by      = Column(String(255), nullable=False)
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at      = Column(DateTime, nullable=True)
    last_used_at    = Column(DateTime, nullable=True)
    is_active       = Column(Boolean, default=True)
    metadata_       = Column("metadata", JSON, default=dict)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id              = Column(String(36), primary_key=True)
    user_id         = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id       = Column(String(100), nullable=False, index=True)
    device_id       = Column(String(128), nullable=True, index=True)
    device_name     = Column(String(255), nullable=True)
    platform        = Column(String(50), nullable=True)
    app_version     = Column(String(50), nullable=True)
    refresh_jti     = Column(String(128), nullable=True, index=True)
    started_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ended_at        = Column(DateTime, nullable=True)
    revoked_at      = Column(DateTime, nullable=True)
    ip_address      = Column(String(45), nullable=True)
    queries_run     = Column(Integer, default=0)
    total_redactions = Column(Integer, default=0)
    max_risk_score  = Column(Float, default=0.0)

    user            = relationship("User", back_populates="sessions")


class AuditEntry(Base):
    """
    Mirrors the JSONL ledger into SQL for fast querying.
    The JSONL ledger remains the tamper-proof source of truth.
    """
    __tablename__ = "audit_entries"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    entry_hash       = Column(String(64), unique=True, nullable=False, index=True)
    prev_hash        = Column(String(64), nullable=False)
    timestamp        = Column(DateTime, nullable=False, index=True)
    tenant_id        = Column(String(100), nullable=False, index=True)
    user_id          = Column(String(255), nullable=False, index=True)
    user_role        = Column(String(50), nullable=False)
    department       = Column(String(100), nullable=True)
    action           = Column(String(100), nullable=False, index=True)
    document         = Column(String(500), nullable=True)
    prompt_hash      = Column(String(64), nullable=True)
    redactions_applied = Column(JSON, default=list)
    policy_triggered = Column(String(255), nullable=True)
    model_queried    = Column(String(100), nullable=True)
    risk_score       = Column(Float, nullable=True)
    metadata_        = Column("metadata", JSON, default=dict)


class PolicyConfig(Base):
    __tablename__ = "policy_configs"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id    = Column(String(100), nullable=False, index=True)
    department   = Column(String(100), nullable=True)  # None = global
    policy_name  = Column(String(255), nullable=False)
    yaml_content = Column(Text, nullable=False)
    version      = Column(Integer, default=1)
    is_active    = Column(Boolean, default=True)
    created_by   = Column(String(255), nullable=True)
    created_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc))


class LicenseSeat(Base):
    __tablename__ = "license_seats"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    license_key     = Column(String(255), unique=True, nullable=False, index=True)
    tenant_id       = Column(String(100), nullable=False, index=True)
    organization    = Column(String(255), nullable=False)
    plan            = Column(String(50), default="ENTERPRISE")  # STARTER | PRO | ENTERPRISE
    seats_total     = Column(Integer, default=5)
    seats_used      = Column(Integer, default=0)
    deployment_mode = Column(String(20), default="airgap")  # airgap | cloud
    hardware_id     = Column(String(255), nullable=True)   # Locked to machine for airgap
    issued_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at      = Column(DateTime, nullable=True)       # None = perpetual
    is_active       = Column(Boolean, default=True)
    last_validated  = Column(DateTime, nullable=True)
    metadata_       = Column("metadata", JSON, default=dict)

    def is_within_limits(self) -> bool:
        return self.seats_used < self.seats_total and self.is_active


class AsyncJob(Base):
    __tablename__ = "async_jobs"

    id               = Column(String(36), primary_key=True)
    tenant_id        = Column(String(100), default="default", nullable=False, index=True)
    user_id          = Column(String(255), nullable=False, index=True)
    user_role        = Column(String(50), nullable=False)
    department       = Column(String(100), nullable=True)
    job_type         = Column(String(100), nullable=False, index=True)
    status           = Column(String(30), default="queued", nullable=False, index=True)
    payload          = Column(JSON, default=dict)
    result           = Column(JSON, nullable=True)
    error            = Column(JSON, nullable=True)
    attempts         = Column(Integer, default=0)
    max_retries      = Column(Integer, default=1)
    timeout_seconds  = Column(Integer, default=90)
    cancel_requested = Column(Boolean, default=False, nullable=False, index=True)
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                              onupdate=lambda: datetime.now(timezone.utc))
    started_at       = Column(DateTime, nullable=True)
    completed_at     = Column(DateTime, nullable=True)
