# Guardrails operations runbook

## Alerts

- Sudden increase in `input_rejected` or `unsafe_model_output`
- Policy versions differ between replicas
- Audit delivery failures
- Latency or memory growth from unusually large responses
- Repeated fingerprints across identities or tenants

## Triage

1. Confirm request ID, policy version, route, action, categories, and rules.
2. Do not retrieve raw content unless the approved incident process permits it.
3. Determine whether the change is malicious traffic, model drift, new application content, or a policy regression.
4. Contain abuse at the API gateway or identity layer; revoke affected tools or credentials.
5. For false positives, move only the affected policy version to monitor or roll back to the last approved version.
6. Add a sanitized regression case before changing a rule.

## Secret leakage

Treat detected live credentials as compromised: block the response, rotate the credential, examine access logs, identify its source, and prevent the secret from entering prompts or retrieval indexes again.

## Release evidence

Record test results, adversarial dataset version, false-positive sample, policy diff, image digest, approving owner, deployment time, and rollback version.
