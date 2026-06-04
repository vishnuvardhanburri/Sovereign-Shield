# Sovereign Shield Buyer FAQ

## What is Sovereign Shield?

Sovereign Shield by Xavira Tech Labs is a human-governed enterprise security platform for private AI governance. It keeps operators, CISOs, and executives in control while AI accelerates analysis, detection, prioritization, and evidence generation.

## Does it require OpenAI, Claude, or another cloud LLM?

No. The default path is local Ollama. Cloud providers are optional and policy-governed. High-sensitivity prompts are forced to local routing, and critical actions remain operator-controlled.

## What data leaves the buyer environment?

In local/air-gapped mode, no prompt data needs to leave the buyer environment. Sensitive values are pseudonymized before inference.

## How does a CISO prove controls worked?

The Obsidian Ledger records hash-chained JSONL events. Evidence reports, readiness certificates, deployment packs, and handoff ZIPs are generated locally so security leaders can prove what happened, why it happened, and who approved critical action.

## How are enterprise apps integrated?

Apps call `/api/v2/proxy/inspect` with a scoped `X-Sentinel-API-Key`. Examples are in `docs/API_INTEGRATION_EXAMPLES.md`.

## What are the main production assumptions?

Ollama must be running, mTLS requires Nginx or Envoy, Redis is recommended for multi-node deployments, human approval workflows must be mapped to buyer roles, and off-box ledger anchoring should use buyer-owned immutable storage.
