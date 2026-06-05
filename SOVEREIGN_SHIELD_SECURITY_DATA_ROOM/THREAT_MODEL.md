# Threat Model

## Scope

This threat model covers Sovereign Shield as a buyer-owned security governance platform for AI-bound enterprise requests, evidence generation, and operator review workflows.

## Primary Assets

- Sensitive prompts and documents
- Pseudonymization mappings
- User and API-key identities
- Audit ledger records
- Policy rules and route decisions
- Evidence reports
- Local model endpoint configuration
- Deployment secrets
- Risk and alert state

## Threats And Controls

| Threat | Risk | Sovereign Shield Control |
| --- | --- | --- |
| PII sent to model | Regulatory and privacy exposure | Redaction and pseudonymization before inference |
| Prompt injection | Policy bypass or data leakage | Prompt-injection detector and guardian checks |
| Trade-secret disclosure | Business confidentiality loss | Semantic DLP and local-first routing |
| Unauthorized API use | Abuse or data exposure | JWT, RBAC, API keys, session revocation |
| Repeated risky behavior | Insider misuse or compromised credential | Risk scoring and operator quarantine review |
| Audit tampering | Loss of evidence integrity | Hash-chained audit ledger |
| Cloud route misuse | Data residency and vendor exposure | Policy-governed adapters and local high-sensitivity route |
| Weak deployment secrets | Authentication or ledger compromise | Fail-closed secret validation |
| Oversized requests | Availability risk | Request-size limits |
| Misconfigured CORS | Browser-origin abuse | Strict origin configuration |

## Abuse Cases

1. A user includes Aadhaar or PAN data in a prompt.
2. A user asks the model to ignore policy and reveal hidden instructions.
3. A contractor tries to send merger or formula details to a cloud model.
4. A compromised API key repeatedly submits sensitive records.
5. An operator exports evidence without approval.
6. A deployment uses placeholder secrets.
7. A buyer forgets to configure off-box ledger anchoring.

## Residual Risks

- Local model quality depends on buyer-selected Ollama model and hardware.
- Compliance outcome depends on buyer policies and legal review.
- Off-box immutability requires buyer-controlled storage.
- Production monitoring must be connected to buyer observability tools.
- Quarantine review workflows must be staffed and enforced.
- SIEM forwarding must be validated in the buyer environment.

## Security Review Priorities

1. Confirm production secrets are non-placeholder.
2. Confirm RBAC roles and permissions match buyer policy.
3. Validate prompt-injection and redaction paths with synthetic data.
4. Validate local routing for high-sensitivity prompts.
5. Verify audit ledger integrity.
6. Test backup and restore.
7. Confirm operator approval workflow.
8. Confirm SIEM and alert routing.

