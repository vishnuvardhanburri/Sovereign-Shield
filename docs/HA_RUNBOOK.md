# Active-Passive High Availability Runbook

Sovereign Shield is packaged for active-passive deployment in a buyer-owned private network. The goal is to keep the security governance command center available if one node, VM, or container host fails.

## State Sync

- JWT revocation and session invalidation: Redis
- Oracle risk scores and quarantine decisions: Redis
- Users, tenants, policies, licenses, and metadata: Postgres
- Obsidian audit ledger: append-only JSONL with SHA-256 hash chain, anchored to buyer-controlled storage
- Evidence reports: regenerated from ledger and risk state

## Failover Model

1. Buyer load balancer routes traffic to the active Shield API node.
2. Passive Shield node runs the same image and checks `/api/v2/enterprise/deployment-doctor`.
3. Both nodes share Redis and Postgres.
4. Ledger files are written to a mounted WORM-capable path or shipped to buyer object storage.
5. If active health checks fail, the load balancer promotes passive within the buyer-defined health threshold.

Target RTO: under 60 seconds after load-balancer health-check failure.

Target RPO: zero for Redis/Postgres-backed state; ledger RPO depends on buyer storage sync interval.

## Drift Checks

Run before demo, handoff, or weekly operations:

```bash
pnpm submit:ready
pnpm generate:data-room
curl http://localhost:8000/api/v2/enterprise/deployment-doctor
curl http://localhost:8000/demo/tier3-self-healing
```

## Recovery Drill

1. Start primary and passive nodes from the same signed image.
2. Send a PII prompt and verify redaction, risk score, and ledger entry.
3. Stop the primary node.
4. Confirm passive node serves `/` and `/demo/metrics`.
5. Generate evidence PDF and verify hash-chain status.

## Buyer Ownership Boundary

This is production-ready infrastructure code, not a hosted compliance certification. The buyer owns cloud account, secrets, TLS CA, DNS, network policy, backup retention, and operational monitoring.
