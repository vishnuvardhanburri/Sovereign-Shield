# Security Demo Checklist

## Demo Objective

Prepare a founder or security sales engineer to run a controlled, credible, five-minute buyer demonstration of Sovereign Shield without improvisation.

## Pre-Demo Setup

| Item | Check |
| --- | --- |
| Repository is current | Confirm local branch matches GitHub `main` |
| Demo environment starts | Run the documented launch command for the target environment |
| Frontend opens | Confirm command center route loads |
| Backend health responds | Confirm `/health` returns online status |
| Login works | Confirm demo or configured operator account can sign in |
| Ollama available if shown | Confirm local model endpoint is reachable |
| Demo data clearly labeled | Confirm synthetic metrics are not presented as customer usage |
| Evidence artifacts available | Confirm reports, ledger proof, and data-room docs are present |
| Data room generated | Run `pnpm generate:data-room` if a fresh package is needed |
| Screen sharing ready | Use browser zoom and resolution suitable for buyer review |

## Five-Minute Run Sheet

| Minute | Step | Screen | Presenter Goal |
| --- | --- | --- | --- |
| 0 | Login | Sign-in page | Show controlled access |
| 1 | Dashboard | Command center | Show security posture and review queues |
| 1-2 | Shadow AI | Detection surface | Show visibility into risky AI usage |
| 2 | Governance | Policy and controls | Show human-directed decisions |
| 2-3 | Audit | Ledger or recent events | Show traceability and integrity |
| 3 | Evidence | Evidence report | Show buyer-ready proof |
| 3-4 | Compliance | Control mapping | Show compliance visibility |
| 4-5 | Executive | Readiness and summary | Show procurement and board readiness |

## Required Proof Points

- Human approval for critical actions
- Full auditability
- Explainable decisions
- Governance-first architecture
- Security evidence generation
- Compliance visibility
- Executive accountability
- Deterministic fallback behavior

## Demo Data Disclaimers

Use this line when showing synthetic activity:

"These validation metrics are simulated for demonstration and diligence. They do not represent customer usage, revenue, or production traction."

## Technical Preflight

| Area | Validate |
| --- | --- |
| Auth | Login, token handling, session behavior |
| RBAC | Operator role can view demo surfaces |
| API health | `/health` works |
| Control room | Dashboard data loads |
| Shadow AI | Detection page or endpoint responds |
| Governance | Policy/routing explanation is visible |
| Audit | Ledger or evidence record exists |
| Reports | Evidence report opens or generates |
| Data room | Security docs package exists |

## Buyer Question Readiness

Before the demo, prepare short answers for:

- "Where does sensitive data go?"
- "What remains human-approved?"
- "Can this run locally?"
- "Does this certify compliance?"
- "What happens if Ollama is unavailable?"
- "How do we prove audit integrity?"
- "What do we need for production?"
- "What is simulated in the demo?"

## Failure Handling

| Failure | Say | Do |
| --- | --- | --- |
| Login fails | "This is an environment issue, not the control design. I will show the prepared evidence flow while we reset access." | Move to screenshots or data-room docs |
| Local model unavailable | "The platform has governed fallback behavior; model availability is a deployment dependency." | Show routing policy and readiness docs |
| Report generation slow | "Evidence generation can be run as an operational task; here is the generated artifact." | Open existing report or data-room document |
| Dashboard API slow | "The dashboard is a control surface; production tuning uses aggregated endpoints and monitoring." | Show performance report |
| Buyer asks legal compliance | "The platform provides evidence for compliance programs, not legal certification." | Open compliance overview |

## Post-Demo Follow-Up Package

Send or reference:

- `SECURITY_EXECUTIVE_SUMMARY.md`
- `SECURITY_ARCHITECTURE.md`
- `SECURITY_GOVERNANCE.md`
- `COMPLIANCE_OVERVIEW.md`
- `THREAT_MODEL.md`
- `PERFORMANCE_REPORT.md`
- `PRODUCTION_READINESS.md`
- `DISASTER_RECOVERY.md`
- `BUYER_FAQ.md`
- `CISO_FAQ.md`
- `PROCUREMENT_FAQ.md`

