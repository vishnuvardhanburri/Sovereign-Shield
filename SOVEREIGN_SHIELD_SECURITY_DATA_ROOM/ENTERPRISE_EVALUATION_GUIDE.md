# Enterprise Evaluation Guide

## Evaluation Objective

Help a buyer evaluate Sovereign Shield as a human-governed enterprise security platform without confusing demo validation data with production deployment evidence.

## Recommended Evaluation Plan

| Phase | Goal | Acceptance Evidence |
| --- | --- | --- |
| 1. Architecture review | Confirm deployment and trust boundaries | `SECURITY_ARCHITECTURE.md` reviewed |
| 2. Control validation | Test redaction, prompt security, DLP, and local routing | Synthetic prompt tests passed |
| 3. Governance review | Confirm approval and review workflow | `SECURITY_GOVERNANCE.md` reviewed |
| 4. Audit validation | Verify ledger and report output | Evidence report generated |
| 5. Compliance review | Confirm control mapping and boundaries | `COMPLIANCE_OVERVIEW.md` reviewed |
| 6. Performance review | Measure API and dashboard targets | p50, p95, p99, CPU, memory captured |
| 7. Production readiness | Validate secrets, backups, monitoring, SIEM | Go-live checklist approved |
| 8. Procurement close | Confirm legal, support, and commercial boundaries | Procurement questions answered |

## Evaluation Test Cases

1. Login as operator.
2. Submit prompt containing synthetic PII.
3. Confirm pseudonymization before inference.
4. Submit prompt-injection pattern.
5. Confirm block or escalation.
6. Submit trade-secret-style content.
7. Confirm semantic DLP and local route.
8. Trigger repeated risky behavior.
9. Confirm quarantine review queue.
10. Verify ledger entry.
11. Generate evidence report.
12. Review compliance mapping.
13. Run deployment readiness check.
14. Review backup and restore plan.
15. Review procurement FAQ.

## Top 25 Procurement Questions

| # | Question | Answer | Supporting Documentation |
| --- | --- | --- | --- |
| 1 | What category is this product? | Human-governed enterprise security platform for private AI governance and evidence-driven operations. | `SECURITY_EXECUTIVE_SUMMARY.md` |
| 2 | Who owns deployment? | The buyer owns infrastructure, secrets, network, storage, monitoring, and production operations. | `PRODUCTION_READINESS.md` |
| 3 | Does it require external AI providers? | No. Local Ollama is the default high-sensitivity path. External providers are optional. | `SECURITY_ARCHITECTURE.md` |
| 4 | Does it process sensitive data? | It is designed to inspect and reduce sensitive data before model inference. Buyer must validate storage and retention. | `COMPLIANCE_OVERVIEW.md` |
| 5 | Does it certify compliance? | No. It provides technical evidence for buyer compliance programs. | `COMPLIANCE_OVERVIEW.md` |
| 6 | What data-room artifacts exist? | Architecture, governance, compliance, threat model, performance, readiness, DR, and FAQs. | `SOVEREIGN_SHIELD_SECURITY_DATA_ROOM/` |
| 7 | What is simulated in the demo? | Demo validation metrics may be synthetic and are labeled as such. | `SECURITY_DEMO_CHECKLIST.md` |
| 8 | What support model is required? | Buyer or partner must define support, updates, incident process, and escalation paths. | `PROCUREMENT_FAQ.md` |
| 9 | What are production prerequisites? | Secrets, TLS, DNS, database, Redis, object storage, monitoring, SIEM, and backups. | `PRODUCTION_READINESS.md` |
| 10 | What security controls are included? | Auth, RBAC, redaction, prompt security, semantic DLP, local routing, audit ledger, evidence reports. | `SECURITY_ARCHITECTURE.md` |
| 11 | What remains buyer-owned? | Legal compliance, retention, identity policy, infrastructure, monitoring, backups, and approvals. | `PROCUREMENT_FAQ.md` |
| 12 | Is there an audit trail? | Yes. The design includes hash-chained ledger records and evidence reports. | `SECURITY_GOVERNANCE.md` |
| 13 | How are critical actions approved? | Critical outcomes should be queued for human review and logged with operator context. | `SECURITY_GOVERNANCE.md` |
| 14 | Can it be white-labeled? | Yes, with clear partner and buyer responsibilities. | `WHITE_LABEL_SECURITY_PARTNER_GUIDE.md` |
| 15 | What is the DR plan? | Restore database, Redis, ledger, reports, and verify health and evidence integrity. | `DISASTER_RECOVERY.md` |
| 16 | How is performance evaluated? | Measure API latency, dashboard load, queue throughput, CPU, memory, and Ollama latency. | `PERFORMANCE_REPORT.md` |
| 17 | What are known risks? | Deployment ownership, model quality, compliance interpretation, monitoring, backup, and ledger anchoring. | `THREAT_MODEL.md` |
| 18 | Can it integrate with SIEM? | SIEM forwarding should be configured and validated in the buyer environment. | `PRODUCTION_READINESS.md` |
| 19 | What proof should procurement request? | Demo checklist, evidence report, readiness output, threat model, compliance overview, DR plan. | `SECURITY_DEMO_CHECKLIST.md` |
| 20 | What legal terms matter? | Data processing, confidentiality, support, incident notice, license scope, and warranty boundaries. | `PROCUREMENT_FAQ.md` |
| 21 | How should success be measured? | Reduced sensitive-data exposure, reviewable decisions, evidence generation, and production readiness. | `SECURITY_EXECUTIVE_SUMMARY.md` |
| 22 | Can we evaluate in a sandbox? | Yes. Use synthetic data and keep demo metrics clearly labeled. | `ENTERPRISE_EVALUATION_GUIDE.md` |
| 23 | What should block go-live? | Missing secrets, no backup restore, no monitoring, no approval workflow, no legal review. | `PRODUCTION_READINESS.md` |
| 24 | How do we assess vendor risk? | Review architecture, threat model, compliance boundaries, DR, support, and operational ownership. | `PROCUREMENT_FAQ.md` |
| 25 | What is the buyer outcome? | A governed security command center for AI workflows with evidence, visibility, and accountable human review. | `SECURITY_EXECUTIVE_SUMMARY.md` |

## Evaluation Exit Criteria

- Buyer confirms use-case fit.
- CISO approves governance model.
- Platform team approves deployment model.
- Compliance owner approves evidence boundaries.
- Procurement accepts support and ownership model.
- Security team validates redaction, prompt security, local routing, audit chain, and report generation.

