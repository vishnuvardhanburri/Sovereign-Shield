# CISO Discovery Call Guide

## Call Objective

Qualify whether Sovereign Shield fits the buyer's AI governance, security operations, compliance visibility, and evidence-generation needs.

## Opening

"Sovereign Shield is a human-governed enterprise security platform. It helps security teams inspect AI-bound workflows, reduce sensitive-data exposure, route high-risk requests to local inference, and generate audit evidence while keeping humans accountable for critical decisions."

## Discovery Agenda

1. Current AI usage and risk exposure
2. Sensitive-data handling requirements
3. Governance and approval workflows
4. Compliance and audit expectations
5. Deployment environment
6. Monitoring, SIEM, and incident response
7. Procurement and evaluation timeline

## Discovery Questions

- Where are employees using AI today?
- Which teams handle regulated or confidential data?
- What policies govern model/provider usage?
- Who approves high-risk AI use cases?
- What evidence do auditors or executives ask for?
- Which controls must run inside your network?
- What monitoring stack receives security events?
- What would block procurement approval?

## Top 25 CISO Questions

| # | Question | Answer | Evidence Source | Data-Room Reference |
| --- | --- | --- | --- | --- |
| 1 | How does this keep humans in control? | Critical actions are positioned as review-required and operator-directed. The platform accelerates detection and evidence, while people own approvals. | Governance workflow and risk review docs | `SECURITY_GOVERNANCE.md` |
| 2 | What sensitive data can it detect? | It supports PII and sensitive business context detection, including India identifiers, global identifiers, healthcare context, and trade-secret-style content. | Redaction, semantic DLP, compliance mapping | `SECURITY_ARCHITECTURE.md`, `COMPLIANCE_OVERVIEW.md` |
| 3 | Does data have to leave our environment? | No. The default posture is local-first with Ollama for high-sensitivity workflows. External providers are optional buyer configuration. | Model routing and local inference design | `SECURITY_ARCHITECTURE.md` |
| 4 | Can it prevent prompt injection? | It includes prompt-injection detection and guardian checks before model routing. | Threat model and security controls | `THREAT_MODEL.md` |
| 5 | How do we audit decisions? | Security decisions can be written to a hash-chained audit ledger and summarized into evidence reports. | Audit ledger and report generation | `SECURITY_ARCHITECTURE.md`, `SECURITY_GOVERNANCE.md` |
| 6 | Can this prove compliance? | It provides technical evidence and control visibility. Legal compliance remains buyer-owned. | Compliance boundaries | `COMPLIANCE_OVERVIEW.md` |
| 7 | What is the biggest deployment risk? | Misconfigured secrets, identity mapping, ledger storage, monitoring, or backup ownership. | Production readiness risks | `PRODUCTION_READINESS.md` |
| 8 | How does risk scoring work operationally? | Risk scoring prioritizes actors and events for operator review, especially repeated sensitive-data or injection attempts. | Risk review workflow | `SECURITY_GOVERNANCE.md`, `THREAT_MODEL.md` |
| 9 | Can it disable users or keys? | The platform includes identity and API-key controls, but critical enforcement should follow buyer-approved workflow. | Auth and governance docs | `SECURITY_GOVERNANCE.md` |
| 10 | How do we integrate with SIEM? | SIEM forwarding should be connected and validated in the buyer environment. | Monitoring and production readiness | `PRODUCTION_READINESS.md` |
| 11 | What happens if local inference is down? | The system should fail into governed behavior and surface readiness gaps rather than bypass policy. | Fallback design | `SECURITY_ARCHITECTURE.md` |
| 12 | How do we handle model quality? | Buyer-selected Ollama models and hardware must be benchmarked and approved for each use case. | Performance and residual risk | `PERFORMANCE_REPORT.md` |
| 13 | Can we run this in a private network? | Yes. The intended posture is buyer-owned deployment with controlled network, secrets, and storage. | Deployment model | `PRODUCTION_READINESS.md` |
| 14 | What should the board see? | Executive summary, evidence reports, risk heatmap, readiness output, and residual risk register. | Executive reporting | `SECURITY_EXECUTIVE_SUMMARY.md` |
| 15 | How do we prove logs were not changed? | Use the hash-chained ledger plus buyer-controlled immutable storage. | Audit integrity | `SECURITY_ARCHITECTURE.md`, `DISASTER_RECOVERY.md` |
| 16 | Does it replace endpoint DLP? | No. It adds AI governance visibility and controls for model-bound workflows. | Threat boundaries | `THREAT_MODEL.md` |
| 17 | What are the required secrets? | JWT secret, license master secret, actor hash salt, ledger master salt, and approved origins. | Startup readiness | `PRODUCTION_READINESS.md` |
| 18 | How do we handle incident response? | Use risk alerts, ledger evidence, SIEM forwarding, and buyer incident-response process. | DR and governance | `DISASTER_RECOVERY.md`, `SECURITY_GOVERNANCE.md` |
| 19 | Can it support multi-tenant operation? | The architecture includes tenant context, but buyer must validate isolation, data retention, and operational boundaries. | Architecture review | `SECURITY_ARCHITECTURE.md` |
| 20 | Can we white-label it? | Partner packaging is possible with clear control ownership and support boundaries. | Partner guide | `WHITE_LABEL_SECURITY_PARTNER_GUIDE.md` |
| 21 | What tests should we run? | Redaction, injection, local routing, audit chain, evidence generation, backup restore, and load tests. | Evaluation checklist | `ENTERPRISE_EVALUATION_GUIDE.md` |
| 22 | What is simulated in the demo? | Validation metrics and some proof records may be synthetic and are labeled as such. | Demo checklist | `SECURITY_DEMO_CHECKLIST.md` |
| 23 | How does procurement evaluate this? | Review security architecture, threat model, compliance boundaries, production readiness, DR, and support model. | Procurement docs | `PROCUREMENT_FAQ.md` |
| 24 | What evidence exists for performance? | The report defines targets and evidence needed: p50, p95, p99, throughput, CPU, memory, and queue metrics. | Performance report | `PERFORMANCE_REPORT.md` |
| 25 | What is the correct strategic framing? | Palantir-style governance command center for AI security evidence and control, with humans accountable. | Executive summary | `SECURITY_EXECUTIVE_SUMMARY.md` |

## Qualification Signals

Strong fit:

- Buyer has regulated AI workflows
- CISO wants evidence and governance visibility
- Internal teams are using AI without consistent control
- Local inference or data residency matters
- Procurement requires audit documentation

Weak fit:

- Buyer wants only a simple chatbot
- Buyer has no owner for governance workflows
- Buyer cannot operate infrastructure
- Buyer expects legal certification without internal control work

## Close

"The next step is an evaluation against your highest-risk workflow: one prompt path, one approval workflow, one evidence report, one audit review, and one deployment-readiness check."

