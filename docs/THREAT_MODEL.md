# Threat model

## Assets

- System and developer instructions
- Customer and employee personal information
- Provider credentials, tokens, and private keys
- Retrieval documents and tenant boundaries
- Tool permissions and consequential business actions
- Audit evidence and policy configuration

## Trust boundaries

Untrusted content enters through users, retrieved documents, tool results, uploaded files, and model output. The model is also treated as untrusted: it proposes text and actions but never grants authorization.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Direct/indirect prompt injection | Deterministic detection, monitor/block modes, instruction separation | Novel or obfuscated attacks require semantic detection |
| Sensitive-data leakage | Bidirectional recursive redaction and secret detection | Unsupported modalities and identifiers need added recognizers |
| Harmful instructions | High-confidence deny rules and provider moderation integration point | Context and language can evade lexical rules |
| Tool abuse | Server-side allowlist, human approval, URL validation | Each tool still needs business authorization and idempotency |
| SSRF | Reject local, private, link-local, reserved, and non-HTTP targets | DNS rebinding requires resolution-time network controls |
| Audit data becoming a liability | HMAC fingerprints; no raw content | Operators must protect keys and downstream logs |
| Denial of service | Early body-size termination | Edge rate limiting and timeouts remain required |
| Policy bypass or drift | Version header and versioned audit events | Deployment governance must compare expected versions |

## Non-goals

The middleware does not authenticate users, enforce tenant document permissions, rate-limit traffic, sandbox code, or determine whether a business action is legally authorized. Those controls belong at their respective enforcement points.
