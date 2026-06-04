# Sentinel Shield v2.1 Enterprise Lockdown

Release tag: `v2.1-enterprise-lockdown`

## Production-Ready Scope

- Local-first Vault AI through Ollama.
- India PII and enterprise PII pseudonymization.
- Prompt injection shield and semantic DLP.
- Tamper-evident Obsidian audit ledger.
- Oracle risk scoring and operator quarantine review.
- JWT auth, first-run admin generation, forced password rotation, MFA, and scoped API keys.
- Universal proxy interface for CRM, Slack, Teams, and custom enterprise apps.
- Evidence PDF generation, readiness certificate, deployment pack, and buyer handoff ZIP.
- Dashboard Enterprise Center for readiness, policy simulation, API keys, alerts, reports, backups, and trust operations.

## Verification Commands

```bash
pnpm verify:buyer
pnpm release:certificate
pnpm handoff:zip
```

## Known Assumptions

- Ollama must be running with the configured local model pulled.
- mTLS enforcement requires Nginx or Envoy in front of the FastAPI gateway.
- Redis is optional for localhost demos and recommended for distributed production risk state.
- Off-box ledger anchoring should be configured to buyer-controlled immutable storage.

## Handoff Artifacts

- `logs/certificates/*` readiness certificates.
- `logs/handoff/*` architecture PDF, manifest, and buyer ZIP.
- `logs/deployment_pack/*` Nginx, systemd, firewall, and checklist.
