# Sentinel Shield Threat Model

## Primary Threats

| Threat | Control |
| --- | --- |
| Prompt injection | Local fingerprint detector blocks jailbreaks and prompt leakage attempts |
| PII leakage | Identity Masking Proxy pseudonymizes before model inference |
| Trade-secret leakage | Semantic DLP flags sensitive business context |
| Audit tampering | Obsidian Ledger hashes every entry with previous hash linkage |
| API draining | Rate and cost controls in Zero-Trust API Shield |
| Unauthorized service calls | mTLS headers and scoped API keys |
| Compromised user token | JWT revocation and active-user enforcement |
| Repeated risky behavior | Oracle Risk Engine queues actors for operator quarantine review |

## Residual Risks

- Local model quality depends on the buyer-selected Ollama model.
- mTLS is only as strong as the buyer's Nginx or Envoy boundary.
- Off-box immutability requires buyer-owned storage configuration.
- Redis outage falls back to local risk state in single-node mode.

## Evidence

Run:

```bash
pnpm verify:buyer
pnpm release:certificate
pnpm handoff:zip
```
