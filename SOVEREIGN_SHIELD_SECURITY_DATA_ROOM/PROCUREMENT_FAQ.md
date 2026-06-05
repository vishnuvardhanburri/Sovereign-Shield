# Procurement FAQ

## Product Category

Human-governed enterprise security platform for private AI governance, audit evidence, compliance visibility, and security command-center operations.

## Primary Buyer

Security, compliance, platform, and AI governance teams in regulated or risk-sensitive organizations.

## Deployment Model

Buyer-owned deployment. The repository includes Docker, scripts, and runbooks. Production use requires buyer infrastructure, secrets, DNS, TLS, storage, monitoring, and operational ownership.

## Data Handling

Sovereign Shield is designed to reduce sensitive-data exposure before model inference through redaction, pseudonymization, semantic DLP, and local-first routing for high-sensitivity content.

## Vendor Risk Questions

| Question | Response |
| --- | --- |
| Does it require external AI providers? | No. Local Ollama is the default posture. |
| Does it store raw PII by default? | The design reduces PII exposure through pseudonymization before inference. Buyer must validate storage policy. |
| Does it provide audit evidence? | Yes. Hash-chained ledger and report generation are included. |
| Does it support RBAC? | Yes. Role and permission controls are included. |
| Does it support production secrets? | Yes. Missing or placeholder secrets fail closed. |
| Does it certify compliance? | No. It provides technical evidence for buyer compliance programs. |

## Procurement Review Checklist

- Security architecture reviewed
- Threat model reviewed
- Compliance boundaries accepted
- Data-processing responsibilities assigned
- Production secrets plan approved
- Infrastructure ownership assigned
- Monitoring and alerting plan approved
- Backup and restore plan approved
- License and support terms reviewed
- Legal review completed

## Commercial Diligence Notes

Sovereign Shield should be evaluated as a packaged security governance asset. The value is in reducing internal build time for controls, dashboards, evidence workflows, deployment scripts, and buyer-facing security documentation.

## Contracting Considerations

Buyers should define:

- Support model
- Security update process
- Data-processing terms
- Incident notification process
- Deployment responsibility
- Warranty boundaries
- License scope
- Confidentiality terms
- Compliance responsibilities

