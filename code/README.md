# Code

This folder is the buyer-facing pointer to the hardened private repo source.

The production code remains in the root-level application folders so existing commands, imports, Docker files, CI, and deployment scripts keep working without brittle path rewrites.

## Hardened Source Map

| Area | Path |
| --- | --- |
| FastAPI security gateway | `../backend/app.py` |
| Authentication and RBAC | `../backend/auth/` |
| Zero-Trust API shield | `../backend/api_shield.py` |
| Fail-closed config loader | `../backend/config.py` |
| PII and India-stack detection | `../backend/security_scanner.py`, `../backend/compliance/india_patterns.py` |
| Identity masking proxy | `../backend/redaction_middleware.py` |
| Prompt injection defense | `../backend/prompt_injection.py` |
| Hallucination and jailbreak guardian | `../backend/llm_guardian.py` |
| Semantic DLP | `../backend/semantic_dlp.py` |
| Risk scoring and quarantine | `../backend/risk_engine.py` |
| Local/cloud model routing | `../backend/gateway/` |
| Tamper-evident audit ledger | `../backend/audit/` |
| Evidence PDF reporting | `../backend/reporting/` |
| Buyer dashboard | `../frontend/site/` |
| Next.js operator console | `../apps/web/` |
| Tauri desktop console | `../apps/desktop/` |
| React Native mobile console | `../apps/mobile/` |
| Shared TypeScript SDK | `../packages/sdk/` |
| Shared design system | `../packages/design-system/` |
| Enterprise scripts | `../scripts/` |
| Tests | `../tests/` |
| Golden-image IaC | `../iac/` |
| HA and governed resilience docs | `../docs/HA_RUNBOOK.md`, `../docs/TIER3_GOVERNED_RESILIENCE.md` |

## Buyer Verification

Run from the repository root:

```bash
pnpm deploy:enterprise
pnpm submit:ready
pnpm generate:data-room
```

Expected proof:

```text
BUYER_VERIFIED
score: 100.0
```

## Runtime Dependency Posture

Default deployment depends on:

- buyer-owned `DATABASE_URL`
- local Ollama runtime for AI
- fail-closed security secrets

It does not require OpenRouter or any external LLM provider key. Cloud adapters are opt-in only through `CLOUD_ADAPTERS_ENABLED=true`.
