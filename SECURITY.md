# Security Policy

## Acquisition-Grade Security Posture

Sovereign Shield is a human-governed enterprise security platform for private AI governance. The production posture is designed for buyer-owned environments where secrets, salts, audit logs, model endpoints, databases, backups, and critical approvals remain under the buyer's control.

This document is written for CISO, CTO, security engineering, and M&A diligence review. It is not a certification claim and does not replace a buyer's legal or compliance review.

## Supported Version

Production buyers should run the latest sealed commit on `main` and keep a private copy of `.env`, ledger files, local databases, TLS material, and backup keys.

## Security Controls

| Area | Control | Implementation |
| --- | --- | --- |
| Auth | JWT auth, RBAC roles, token revocation | `backend/auth/jwt_handler.py`, `backend/auth/rbac_engine.py` |
| Sessions | Refresh-token rotation and device session tracking | `backend/app.py`, `backend/db/models.py` |
| Admin | Super Admin, Admin, Auditor, Staff, API Client roles | `backend/db/models.py`, RBAC permissions |
| Secrets | Fail-closed config, no placeholder fallback | `backend/config.py` |
| CORS | Explicit origin allowlist, no wildcard | `ALLOWED_ORIGINS`, FastAPI CORS middleware |
| API Gateway | Rate limiting, cost budget, suspicious path blocking | `backend/api_shield.py` |
| Request Limits | Content-Length rejection for oversized protected calls | `API_SHIELD_MAX_BODY_BYTES` |
| Secure Headers | nosniff, DENY frame, no-referrer, no-store, permissions policy, CSP, HSTS | `ZeroTrustAPIShieldMiddleware` |
| mTLS | Nginx/Envoy mTLS termination with verified cert headers | `API_SHIELD_ENFORCE_MTLS`, generated deployment pack |
| PII DLP | India and global PII detection | `backend/security_scanner.py`, `backend/compliance/india_patterns.py` |
| Prompt Security | Prompt injection and leakage detector | `backend/prompt_injection.py` |
| Semantic DLP | Sensitive context / trade-secret detection | `backend/semantic_dlp.py` |
| Pseudonymization | Context-preserving placeholders before LLM | `backend/redaction_middleware.py` |
| Local AI | High-sensitivity routing to Ollama/local path | `backend/gateway/model_router.py` |
| Risk | Oracle risk scoring with operator-controlled quarantine review workflows | `backend/risk_engine.py` |
| Audit | Hash-chained JSONL ledger with salted signatures | `backend/audit/ledger.py` |
| Evidence | PDF report with SHA-256 certificate | `backend/reporting/evidence_report.py`, `/demo/evidence-certificate` |
| Cross-Platform Clients | Thin operator consoles with no business logic duplication | `apps/`, `packages/sdk/` |

## Secret Handling

The backend is fail-closed. These values must be present, sufficiently long, and non-placeholder before boot:

- `JWT_SECRET_KEY`
- `LICENSE_MASTER_SECRET`
- `ACTOR_HASH_SALT`
- `LEDGER_MASTER_SALT`
- `ALLOWED_ORIGINS`

Never commit `.env`, databases, ledgers, vault documents, certificates, private keys, screenshots containing secrets, or production evidence exports.

## Network Security

Production deployments should use Nginx or Envoy for TLS and mTLS termination. The gateway accepts verified certificate metadata only from trusted internal reverse proxies. For internet-facing deployments, put the gateway behind a WAF, enable rate controls, and restrict admin routes to VPN, private network, or identity-aware proxy.

Recommended environment controls:

```bash
API_SHIELD_ENFORCE_MTLS=true
API_SHIELD_MAX_REQUESTS=120
API_SHIELD_WINDOW_SECONDS=60
API_SHIELD_MAX_COST_USD=5.0
API_SHIELD_MAX_BODY_BYTES=524288
ALLOWED_ORIGINS=https://your-dashboard.example.com
```

## Data Residency

Air-gap mode routes high-risk AI requests through local Ollama. Sensitive prompts are scanned, pseudonymized, policy-checked, and audit-logged before model inference. Cloud adapters are optional and should only be enabled by buyer policy. Critical containment, break-glass, and kill-switch decisions remain human-approved and ledger-backed.

## Cross-Platform Client Security

Web, desktop, and mobile clients are operator consoles only. They never embed LLM keys, database URLs, license secrets, ledger salts, or direct Ollama endpoints. Desktop uses a deny-by-default Tauri IPC surface. Mobile stores tokens through encrypted platform storage and requires certificate pinning for production native builds. All high-risk actions still require FastAPI RBAC, explicit operator intent, and ledger audit.

## Production Defaults

- Self-registration is disabled unless `ENABLE_SELF_REGISTRATION=true`.
- First-run admin credentials are generated once and must be rotated.
- Protected APIs reject disabled users even if they hold an old JWT.
- JWT revocation uses Redis when `REDIS_URL` is configured, with memory fallback for localhost.
- The API shield blocks suspicious paths such as `/.env`, traversal attempts, oversized requests, and excessive protected calls.
- Demo metrics are clearly labeled as simulated validation data and must not be represented as customer usage.

## Mandatory Buyer Hardening Before Live Customer Data

1. Rotate all secrets and salts.
2. Enable mTLS at the reverse proxy.
3. Configure buyer-controlled backup passphrase and immutable storage.
4. Configure Redis for revocation, rate limiting, and multi-node risk state.
5. Run `pnpm submit:ready` and archive the verification JSON.
6. Run `pnpm generate:data-room` for due diligence artifacts.
7. Review `docs/KNOWN_LIMITATIONS.md` and close buyer-specific deployment decisions.

## Vulnerability Reporting

Report security issues privately to Xavira Tech Labs support. Do not open public GitHub issues for secrets, bypasses, tenant isolation failures, authentication bugs, prompt-injection bypasses, or data exposure.

Include affected commit hash, deployment mode, reproduction steps, redacted logs, expected impact, and whether the issue touches real buyer data.
