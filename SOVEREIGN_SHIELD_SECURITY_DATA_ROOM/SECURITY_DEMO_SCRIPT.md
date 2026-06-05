# Security Demo Script

## Demo Goal

Run a five-minute live buyer demonstration that positions Sovereign Shield as a human-governed enterprise security platform for private AI governance, audit evidence, compliance visibility, and executive accountability.

Core message:

> Sovereign Shield keeps humans in control while using AI to accelerate analysis, detection, prioritization, and governance.

## Five-Minute Flow

| Time | Step | Action | Outcome |
| --- | --- | --- | --- |
| 0:00-0:30 | Login | Sign in as an enterprise operator | Establish authenticated, role-aware access |
| 0:30-1:05 | Security Dashboard | Show command center summary | Show posture, alerts, model status, and risk queue |
| 1:05-1:40 | Shadow AI Detection | Show unsanctioned or risky usage detection | Show visibility into unapproved AI exposure |
| 1:40-2:15 | Governance Controls | Show policy, local routing, and review controls | Show humans remain in charge of critical decisions |
| 2:15-2:50 | Audit Chain | Show ledger integrity and recent security decisions | Show tamper-evident accountability |
| 2:50-3:30 | Evidence Generation | Generate or open evidence output | Show buyer-ready proof artifacts |
| 3:30-4:10 | Compliance Visibility | Show control mapping and compliance scorecard | Show DPDP, GDPR, HIPAA-style evidence visibility |
| 4:10-5:00 | Executive Reporting | Show executive summary and readiness outputs | Close with board and procurement readiness |

## Opening Script

"Sovereign Shield is a human-governed enterprise security platform for private AI governance. The product does not replace the CISO or operator. It gives them a command center to inspect AI-bound requests, reduce sensitive-data exposure, explain policy outcomes, route high-risk prompts to local inference, and generate evidence for security and compliance review."

"The demo is intentionally short. I will show login, dashboard visibility, Shadow AI detection, governance controls, audit chain, evidence generation, compliance visibility, and executive reporting."

## Step-By-Step Script

| Step | Talking Points | Expected Buyer Questions | Technical Answers | Risk Answers | Procurement Answers |
| --- | --- | --- | --- | --- | --- |
| Login | "We start with authenticated access. Operators enter through a controlled security console, not an open model chat surface." | "Does this support enterprise identity?" "Can roles be separated?" | JWT, RBAC, session controls, scoped API keys, and disabled-user enforcement are present in the repository. Enterprise identity mapping is buyer-owned. | Weak identity mapping is a deployment risk; buyer must map roles to policy and review privileged access. | Security ownership, role mapping, and access review process should be included in procurement acceptance. |
| Security Dashboard | "The dashboard is an enterprise security command center: posture, audit health, local model status, high-risk actors, and review queues." | "Is this operational or just a demo page?" | The frontend consumes backend governance APIs and evidence surfaces. Demo metrics are clearly labeled when simulated. | Dashboard data must be connected to production monitoring and buyer-owned state before go-live. | Procurement should require a walkthrough of live controls, not only screenshots. |
| Shadow AI Detection | "This shows where unapproved or risky AI usage can be identified and moved into governed review." | "How do we discover risky AI usage?" | Shadow AI scanning surfaces can record findings, classify risk, and move heavy analysis into jobs. | Discovery does not replace endpoint DLP or network controls; it adds AI governance visibility. | Buyers should define discovery scope, data-processing boundaries, and retention. |
| Governance Controls | "Controls show policy outcomes, local-first routing, risk scoring, and operator quarantine review. Critical actions remain human-directed." | "Can the system enforce policy?" "Who approves critical actions?" | Redaction, prompt-injection checks, semantic DLP, local routing, and risk scoring run before inference. Critical action review is recorded through operator workflows. | Over-enforcement and under-enforcement are both risks; explainability and review queues reduce blind action. | Procurement should require approval workflow ownership and evidence of policy sign-off. |
| Audit Chain | "Every security decision should be explainable and audit-backed. The ledger creates a hash-linked record of events." | "Can audit logs be modified?" "Can we export them?" | The ledger uses chained hashes and supports evidence report generation. Off-box immutability is buyer-owned. | Ledger integrity depends on protected storage and buyer-controlled anchoring. | Procurement should require WORM, object-lock, SIEM, or private repository anchoring for production. |
| Evidence Generation | "Evidence artifacts turn security activity into material a CISO, auditor, or buyer can review." | "Is the report generated from actual controls?" | Evidence reports summarize ledger entries, policy decisions, risk, redactions, and certificate metadata. | Reports are evidence, not legal certification. The buyer validates policy interpretation. | Reports support procurement review, control-owner sign-off, and technical due diligence. |
| Compliance Visibility | "The platform maps controls to compliance themes: data minimization, accountability, residency, and audit readiness." | "Does this make us compliant?" | It provides technical control evidence for DPDP, GDPR, HIPAA-style reviews. Legal compliance remains buyer-owned. | Compliance gaps remain if retention, notices, processor terms, or data subject workflows are missing. | Procurement should treat this as compliance-supporting infrastructure, not a certificate. |
| Executive Reporting | "Executives need accountability: what happened, why it happened, who reviewed it, and what evidence exists." | "Can we show this to a board?" | Executive summaries, readiness outputs, evidence reports, and data-room docs package the story. | Executive reporting must be grounded in real operational data after deployment. | Procurement can use the data-room package for security review, vendor risk, and acquisition diligence. |

## Close

"The takeaway is simple: Sovereign Shield is not another unmanaged AI tool. It is a human-governed security command center. It helps your team accelerate analysis and evidence generation while preserving human approval, explainability, auditability, and executive accountability."

## Do Not Say

- Do not say the platform replaces the security team.
- Do not say it certifies legal compliance.
- Do not say critical actions happen without review.
- Do not imply buyer infrastructure, monitoring, secrets, backups, or legal obligations are included by default.

