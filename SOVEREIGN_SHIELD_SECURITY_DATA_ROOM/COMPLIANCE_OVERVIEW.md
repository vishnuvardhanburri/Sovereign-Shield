# Compliance Overview

## Purpose

This document summarizes how Sovereign Shield supports compliance visibility and evidence-backed governance. It is not legal advice and does not certify compliance by itself.

## Control Themes

| Theme | Sovereign Shield Capability |
| --- | --- |
| Data minimization | Pseudonymizes sensitive values before model inference |
| Purpose limitation | Records department, actor, route, and policy context |
| Security safeguards | Gateway controls, redaction, prompt-injection defense, DLP, RBAC |
| Accountability | Tamper-evident ledger and evidence reports |
| Data residency | High-sensitivity prompts route to local Ollama by policy |
| Audit readiness | Evidence generation for technical and executive review |
| Access governance | JWT, RBAC, session revocation, API-key controls |
| Incident readiness | Risk scoring, alert queues, SIEM export surfaces |

## DPDP And GDPR Alignment

Sovereign Shield supports technical controls relevant to common DPDP and GDPR governance needs:

- Reduce unnecessary personal data sent to models
- Record security decisions and policy outcomes
- Keep high-sensitivity traffic in buyer-controlled inference
- Maintain evidence of safeguards
- Support operator review of repeated risky behavior
- Provide artifacts for audit and procurement review

Buyer responsibilities remain:

- Lawful basis and notice
- Consent where required
- Data subject request workflows
- Processor agreements
- Retention and deletion policy
- Breach notification process
- Regional transfer assessment
- Legal review

## HIPAA And Healthcare Context

The platform includes health-context detection patterns and can reduce PHI exposure before model inference. Buyers in healthcare must still validate:

- HIPAA policy mapping
- BAA requirements
- Minimum necessary standard
- Access logging
- Retention rules
- Incident response
- Workforce training

## Evidence Artifacts

Recommended compliance evidence package:

- Security architecture summary
- Threat model
- Control mapping
- Audit ledger sample
- Evidence PDF or text report
- Deployment readiness output
- Backup and restore procedure
- Known limitations
- Operator approval workflow
- Data-processing statement

## Compliance Boundaries

Sovereign Shield is a control platform. It does not replace:

- Legal counsel
- Formal compliance certification
- Enterprise GRC system of record
- Identity provider governance
- Endpoint DLP
- Network segmentation
- Cloud account compliance posture

