# Production Readiness

## Readiness Summary

Sovereign Shield includes the core controls expected for a buyer-owned enterprise deployment, but final production readiness depends on buyer configuration, infrastructure, and operational sign-off.

## Required Production Controls

| Control | Status In Repository | Buyer Action |
| --- | --- | --- |
| Secret validation | Fail-closed validation exists | Provide production secrets |
| Authentication | JWT and session controls exist | Integrate enterprise identity policy |
| RBAC | Role and permission engine exists | Map to buyer roles |
| API keys | Scoped key support exists | Define issuance and rotation process |
| CORS | Strict origin configuration exists | Set approved origins |
| Audit ledger | Hash-chained ledger exists | Anchor to buyer-controlled storage |
| Redis | Supported for shared state | Deploy managed Redis or equivalent |
| Postgres | Supported for production metadata | Deploy managed database |
| Docker | Compose and Dockerfiles exist | Validate target runtime |
| Monitoring | Surfaces exist | Connect observability stack |
| Backup | Scripts and runbooks exist | Implement retention and restore drills |

## Startup Reliability

Production boot should validate:

- JWT secret
- License master secret
- Actor hash salt
- Ledger master salt
- Allowed origins
- Database connectivity
- Redis connectivity where configured
- Ollama endpoint where local inference is required
- File-system permissions for logs and reports

## Deployment Readiness Checklist

1. Configure production `.env`.
2. Build backend and frontend images.
3. Run deployment doctor.
4. Confirm `/health`.
5. Confirm authenticated control-room endpoints.
6. Confirm redaction and prompt-injection tests.
7. Confirm local model route.
8. Confirm audit ledger write.
9. Confirm evidence report generation.
10. Confirm backup and restore.
11. Confirm SIEM export path.
12. Confirm operator approval workflow.

## Production Risks

- Placeholder secrets must never be used.
- Single-node local state is not sufficient for high-availability production.
- Buyer must configure TLS, mTLS, DNS, firewall, and object storage.
- Compliance claims require legal and control-owner review.
- Monitoring and alerting must be connected before go-live.

## Recommended Go-Live Gates

- Security owner sign-off
- Platform owner sign-off
- Compliance owner sign-off
- Backup restore passed
- Load test passed
- Incident drill completed
- Ledger integrity verified
- Rollback plan approved

