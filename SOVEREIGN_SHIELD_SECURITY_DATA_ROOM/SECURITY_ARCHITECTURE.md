# Security Architecture

## Architecture Overview

Sovereign Shield is organized as a human-governed security control plane around AI-bound enterprise traffic.

Primary flow:

1. Enterprise user or service submits a request.
2. Sovereign Shield gateway authenticates and validates the request.
3. Policy, redaction, prompt-injection, and semantic DLP checks run before inference.
4. High-sensitivity requests are routed to local Ollama-backed inference.
5. Low-sensitivity requests may use governed adapters when configured by the buyer.
6. Security outcomes are logged to an audit ledger.
7. Operators review risk, evidence, reports, and critical-action queues in the command center.

## Core Components

| Component | Purpose |
| --- | --- |
| FastAPI gateway | Central policy enforcement and API surface |
| Redaction middleware | Pseudonymizes PII before model inference |
| Prompt-injection detector | Blocks or escalates instruction-hierarchy attacks |
| Semantic DLP | Detects confidential business, legal, healthcare, and trade-secret context |
| Model router | Routes requests to local or configured provider paths under policy |
| Ollama adapter | Local-first model execution for private inference |
| Job queue | Asynchronous execution for AI-heavy request paths |
| Audit ledger | Hash-chained evidence records |
| Enterprise command center | Operator view for posture, alerts, approvals, and reports |
| Evidence reporting | PDF/text evidence for diligence and governance review |

## Trust Boundaries

Sovereign Shield assumes the buyer owns:

- Network boundary
- TLS termination
- Secret management
- Identity provider integration
- Database and Redis infrastructure
- Object storage and ledger anchoring
- SIEM and alert routing
- Backup and restore procedures

The application provides security controls inside that buyer-owned boundary. It does not replace cloud account hardening, IAM governance, endpoint management, or enterprise incident-response procedures.

## Data Protection Design

Sensitive values are reduced before model inference through:

- PII pattern matching
- India-specific identifiers such as Aadhaar, PAN, GST, IFSC, UPI, ABHA, and UHID
- Global email, phone, banking, health, and identity patterns
- Pseudonym tokens that preserve business context without exposing original values
- Semantic DLP for confidential project, merger, formula, architecture, healthcare, and legal content

## AI Governance Design

AI usage is supervised through:

- Policy checks before inference
- Local-first routing for high-sensitivity content
- Governed fallback when providers are unavailable
- Audit entries for model route, policy outcome, risk score, and actor context
- Operator review for critical or high-risk outcomes

## Deterministic Fallbacks

When optional integrations are unavailable, the system is designed to fail into controlled behavior:

- Missing secrets block production boot.
- Missing cloud adapters do not bypass local governance.
- Missing Redis can fall back to local state for single-node mode.
- Missing report libraries produce text fallback artifacts where supported.
- Critical approval workflows remain human-directed.

## Security Architecture Risks

| Risk | Control | Buyer Responsibility |
| --- | --- | --- |
| Weak secrets | Fail-closed secret validation | Provide production-grade secrets |
| Ledger tampering | Hash-chained audit records | Configure WORM or object-lock storage |
| Local model quality variation | Buyer-selected Ollama model | Validate model and hardware |
| Proxy misconfiguration | Strict headers and mTLS support | Configure Nginx/Envoy correctly |
| Unreviewed critical action | Review-required risk workflow | Staff and enforce approval workflow |

