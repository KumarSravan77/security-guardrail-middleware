import hashlib
import hmac
import json
import logging
from dataclasses import asdict, dataclass
from time import time


logger = logging.getLogger("guardrail.audit")


@dataclass(frozen=True)
class AuditEvent:
    event: str
    request_id: str
    content_fingerprint: str
    policy_version: str
    direction: str
    action: str
    categories: tuple[str, ...]
    rules: tuple[str, ...]
    timestamp: float


class Auditor:
    def __init__(self, key: str, policy_version: str = "unknown"):
        if len(key) < 16:
            logger.warning("GUARDRAIL_AUDIT_KEY should be supplied by a secret manager and contain at least 16 characters")
        self.key = key.encode()
        self.policy_version = policy_version

    def fingerprint(self, content: bytes) -> str:
        return hmac.new(self.key, content, hashlib.sha256).hexdigest()[:20]

    def emit(self, event: AuditEvent) -> None:
        logger.info(json.dumps(asdict(event), separators=(",", ":"), sort_keys=True))

    def event(self, name: str, request_id: str, content: bytes, findings=(), direction="input", action="allow") -> AuditEvent:
        return AuditEvent(
            name,
            request_id,
            self.fingerprint(content),
            self.policy_version,
            direction,
            action,
            tuple(dict.fromkeys(f.category for f in findings)),
            tuple(dict.fromkeys(f.rule for f in findings)),
            time(),
        )
