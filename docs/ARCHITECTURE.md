# Production architecture

Run guardrails close to the application as an ASGI middleware and repeat critical controls at the edge, model provider, retrieval layer, and tool executor. The deterministic engine is intentionally fast and explainable. A semantic safety service may enrich findings, but timeouts should follow a documented fail-open/fail-closed policy by route risk.

## Recommended deployment

- API gateway: authentication, tenant identity, quotas, rate limits, WAF
- Guardrail middleware: request limits, injection/harm policy, PII/secrets
- RAG service: tenant-aware retrieval, document ACLs, citation enforcement
- Model gateway: approved aliases, provider moderation, budgets, timeouts
- Tool broker: allowlist, schemas, business authorization, approval, idempotency
- Audit pipeline: encrypted append-only storage with restricted access and retention

## Policy lifecycle

Policies move through `draft -> monitor -> enforced -> retired`. Every change requires an adversarial evaluation, false-positive review, owner, effective date, rollback target, and immutable version identifier.

## Availability

Health endpoints bypass content scanning. Guardrail failures on consequential routes should fail closed. Read-only low-risk routes may use a separately configured degraded policy. Never silently switch modes globally.
