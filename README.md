# Security Guardrail Middleware

Reusable ASGI middleware that detects common prompt-injection patterns, redacts
PII in JSON inputs and outputs, limits request size, and emits privacy-safe audit
events. It can protect an existing FastAPI app with one registration call.

```python
from guardrails import GuardrailMiddleware

app.add_middleware(GuardrailMiddleware, mode="block", audit_key="from-a-secret-manager")
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app:app --reload
```

Try `/docs` or send JSON to `POST /v1/echo`. `block` mode rejects detected
injection attempts; `monitor` mode records them without rejection. PII is
redacted in both modes. Audit records contain only keyed content fingerprints,
rule names, PII categories, request IDs, and timestamps—never raw prompts.

The built-in rules are a defense-in-depth layer, not a guarantee against every
attack. Production systems should also use least-privilege tools, explicit
authorization for consequential actions, output validation, rate limits, and
continuous adversarial evaluation.
