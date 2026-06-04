# Tier 3 Governed Resilience Security Layer

This layer is designed to answer the buyer concern: "Will the system stay explainable, auditable, and resilient after deployment, under adversarial pressure and operational drift?"

## 1. Hallucination & Jailbreak Guardian

`backend/llm_guardian.py` adds a local-first validator before prompts reach model routing. It detects:

- roleplay jailbreaks
- data exfiltration intent
- adversarial suffixes
- Base64 encoded bypass payloads
- optional buyer-owned local judge mode through `LOCAL_JUDGE_ENABLED=true`

No cloud LLM is required for the default guardian path.

## 2. Active-Passive HA Pack

The HA runbook and IaC artifacts package a buyer-owned deployment path:

- `docs/HA_RUNBOOK.md`
- `iac/terraform/aws`
- `iac/cloudformation/sovereign-shield-ha.yaml`

Shared state is designed around Redis, Postgres, and hash-chained ledger anchoring.

## 3. Deep-Packet Contextual DLP

`backend/semantic_dlp.py` detects conceptual sensitive context, including M&A, trade secrets, proprietary formulas, security architecture, and regulated health content. This complements India/global regex PII detection.

## 4. Golden Image Deployment Wizard

`pnpm deploy:enterprise` validates the local stack. The IaC pack gives a buyer the foundation for private cloud deployment with encrypted Redis/Postgres and active-passive node design.

## Demo Endpoint

```bash
curl http://localhost:8000/demo/tier3-self-healing
```

The endpoint keeps its existing route path for compatibility and returns clearly labeled synthetic validation proof. It does not claim customer usage or revenue.
