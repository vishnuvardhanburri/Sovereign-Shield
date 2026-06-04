# DPDP / GDPR Compliance Mapping

This document maps Sovereign Shield controls to common DPDP and GDPR governance needs. It is product evidence for technical diligence, not legal advice or a certification claim.

## Control Mapping

| Compliance Need | DPDP Alignment | GDPR Alignment | Sovereign Shield Evidence |
| --- | --- | --- | --- |
| Data minimization | Reduce unnecessary personal data exposure | Art. 5(1)(c) data minimization | Pseudonymizes Aadhaar, PAN, GST, IFSC, UPI, ABHA, UHID, bank, email, phone, and global identifiers before LLM inference. |
| Purpose limitation | Govern how personal data is used | Art. 5(1)(b) purpose limitation | Policy engine attaches source app, department, actor, policy, model route, and enforcement outcome. |
| Security safeguards | Prevent unauthorized disclosure | Art. 32 security of processing | Prompt injection shield, semantic DLP, Zero-Trust API Shield, mTLS config, rate/cost controls, strict CORS, secure headers. |
| Data residency | Keep sensitive prompts local | Transfer restriction / processor governance | Sensitivity score forces high-risk prompts to local Ollama route. Cloud adapters are optional. |
| Pseudonymization | Reduce risk while preserving workflow logic | Art. 4(5), Art. 32 pseudonymization | Realistic tokens such as `[Aadhaar_1]`, `[PAN_1]`, `[GST_1]` preserve context without exposing original value. |
| Auditability | Evidence of safeguards and governance | Accountability principle | Obsidian JSONL ledger stores timestamp, actor hash, policy triggered, previous hash, and signature. |
| Tamper evidence | Detect changed audit records | Accountability / security evidence | SHA-256 hash chain with buyer-controlled `LEDGER_MASTER_SALT`; evidence PDF includes certificate digest. |
| Incident detection | Identify repeated misuse | Breach readiness / monitoring | Oracle risk engine flags repeated PII or injection attempts and queues operator-controlled quarantine review. |
| Access control | Limit privileged actions | Art. 25/32 access governance | JWT, RBAC, session revocation, API keys, disabled-user enforcement. |
| Documentation | Support audits and due diligence | Accountability documentation | `pnpm generate:data-room` exports architecture, threat model, security controls, API docs, screenshots, deployment guide, and known limitations. |

## Demo Evidence

The following endpoints are designed for buyer validation and are clearly labeled as simulated where applicable:

- `GET /demo/metrics` returns 1,200 simulated validation events.
- `POST /demo/redaction-proof` runs the real redaction/prompt shield flow against synthetic input.
- `GET /demo/institutional-proof` returns the CISO/CTO proof map.
- `GET /demo/evidence-certificate` generates a synthetic evidence PDF with SHA-256 certificate.
- `GET /compliance/score` returns authenticated multi-framework scorecard output.

## Limitations

- This is not a legal determination of DPDP/GDPR compliance.
- Buyer must configure production retention, data subject workflows, and processor agreements.
- Off-box immutability requires buyer-controlled storage such as S3 Object Lock, private Git, WORM storage, or SIEM anchoring.
- Local model behavior depends on the buyer-selected Ollama model.
