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
    rules: tuple[str, ...]
    pii_types: tuple[str, ...]
    timestamp: float


class Auditor:
    def __init__(self, key: str):
        self.key = key.encode()

    def fingerprint(self, content: bytes) -> str:
        return hmac.new(self.key, content, hashlib.sha256).hexdigest()[:20]

    def emit(self, event: AuditEvent) -> None:
        logger.info(json.dumps(asdict(event), separators=(",", ":"), sort_keys=True))

    def event(self, name: str, request_id: str, content: bytes, rules=(), pii_types=()) -> AuditEvent:
        return AuditEvent(name, request_id, self.fingerprint(content), tuple(rules), tuple(pii_types), time())
