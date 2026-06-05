# Disaster Recovery

## Recovery Objective

Sovereign Shield should be deployed so the buyer can recover governance operations, audit evidence, and policy enforcement after infrastructure failure.

Recommended targets:

- RTO: under 60 minutes for standard deployment, lower where active-passive infrastructure is configured
- RPO: near-zero for database and Redis-backed state when managed backups are enabled
- Ledger RPO: depends on buyer-controlled WORM or object-lock replication interval

## Critical Data

| Data | Recovery Requirement |
| --- | --- |
| User and role metadata | Restore from database backup |
| API keys and sessions | Restore or revoke according to incident policy |
| Risk state | Restore from Redis or rebuilt from audit records where possible |
| Audit ledger | Preserve hash chain and off-box copy |
| Evidence reports | Regenerate from ledger and state when possible |
| Policy rules | Restore from version-controlled configuration |
| Deployment secrets | Restore from buyer secret manager |

## Backup Strategy

Recommended buyer-owned backup plan:

- Managed database automated backups
- Redis persistence or managed snapshot policy
- Ledger shipping to WORM/object-lock storage
- Version-controlled deployment configuration
- Encrypted backup storage
- Restore tests on a fixed schedule

## Recovery Procedure

1. Confirm incident scope and affected environment.
2. Freeze or copy current audit ledger state.
3. Restore database from approved recovery point.
4. Restore Redis state or rebuild risk cache.
5. Rehydrate ledger path from immutable storage.
6. Restart backend and frontend services.
7. Run deployment doctor.
8. Verify `/health` and authenticated control-room APIs.
9. Verify ledger hash chain.
10. Generate evidence report.
11. Record recovery decision and operator approvals.

## Failover Procedure

For active-passive deployments:

1. Passive node runs same signed image.
2. Load balancer monitors active node health.
3. Shared state remains in Redis and Postgres.
4. Ledger writes use mounted durable storage or shipped append-only records.
5. Buyer promotes passive node when active health checks fail.

## Disaster Recovery Tests

Run quarterly or before production acceptance:

- Database restore test
- Redis recovery test
- Ledger integrity test
- Evidence report regeneration
- API health and login test
- Local model route test
- SIEM export test
- Operator approval audit test

## DR Risks

- Ledger integrity depends on off-box immutable storage.
- Restore quality depends on buyer backup retention and encryption policy.
- Secrets recovery must use buyer secret manager, not repository files.
- RTO depends on infrastructure automation maturity.

