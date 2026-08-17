from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


INJECTION_RULES = {
    "instruction_override": re.compile(r"\b(ignore|disregard|override|forget)\b.{0,60}\b(previous|prior|system|developer)\b.{0,30}\b(instruction|prompt|message)s?\b", re.I | re.S),
    "secret_exfiltration": re.compile(r"\b(reveal|print|show|leak|expose|repeat)\b.{0,60}\b(system prompt|developer message|secret|api key|credentials?|hidden instructions?)\b", re.I | re.S),
    "role_impersonation": re.compile(r"\b(you are now|act as|switch to)\b.{0,40}\b(system|developer|unrestricted|jailbroken|dan)\b", re.I | re.S),
    "prompt_delimiter_attack": re.compile(r"(<\|system\|>|\[/?INST\]|BEGIN SYSTEM PROMPT|###\s*(system|developer))", re.I),
    "indirect_injection": re.compile(r"\bwhen (an ai|the assistant|you) (reads|sees|processes) this\b", re.I),
}

HARM_RULES = {
    "self_harm_instruction": re.compile(r"\b(how to|steps? to|best way to)\b.{0,50}\b(kill myself|commit suicide|self[- ]harm)\b", re.I | re.S),
    "violent_instruction": re.compile(r"\b(how to|instructions? (?:for|to)|steps? to)\b.{0,50}\b(build a bomb|poison|murder|attack)\b", re.I | re.S),
    "credential_abuse": re.compile(r"\b(steal|harvest|phish for|bypass)\b.{0,50}\b(passwords?|credentials?|mfa|authentication)\b", re.I | re.S),
}

PII_RULES = {
    "email": re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "phone": re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\w)"),
    "canadian_postal_code": re.compile(r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ -]?\d[ABCEGHJ-NPRSTV-Z]\d\b", re.I),
    "ssn": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "canadian_sin": re.compile(r"(?<!\d)(?:\d[ -]?){8}\d(?!\d)"),
    "credit_card": re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
}

SECRET_RULES = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.I),
    "generic_api_key": re.compile(r"\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+~=-]{16,}", re.I),
}


@dataclass(frozen=True)
class Finding:
    category: str
    rule: str
    severity: str


@dataclass(frozen=True)
class ScanResult:
    text: str
    findings: tuple[Finding, ...]
    pii_types: tuple[str, ...]

    @property
    def injection_rules(self) -> tuple[str, ...]:
        return tuple(f.rule for f in self.findings if f.category == "prompt_injection")

    @property
    def blocked(self) -> bool:
        return any(f.category in {"prompt_injection", "harmful_instruction"} for f in self.findings)

    def rules(self, category: str | None = None) -> tuple[str, ...]:
        return tuple(f.rule for f in self.findings if category is None or f.category == category)


def _luhn_valid(candidate: str, minimum: int, maximum: int) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not minimum <= len(digits) <= maximum or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def redact_sensitive(text: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    redacted = text
    pii_found: list[str] = []
    secret_found: list[str] = []
    for category, rules, destination in (("PII", PII_RULES, pii_found), ("SECRET", SECRET_RULES, secret_found)):
        for name, pattern in rules.items():
            matches = list(pattern.finditer(redacted))
            if name == "credit_card":
                matches = [m for m in matches if _luhn_valid(m.group(), 13, 19)]
            elif name == "canadian_sin":
                matches = [m for m in matches if _luhn_valid(m.group(), 9, 9)]
            if not matches:
                continue
            destination.append(name)
            for match in reversed(matches):
                redacted = redacted[:match.start()] + f"[REDACTED_{category}_{name.upper()}]" + redacted[match.end():]
    return redacted, tuple(dict.fromkeys(pii_found)), tuple(dict.fromkeys(secret_found))


def redact_pii(text: str) -> tuple[str, tuple[str, ...]]:
    redacted, pii_types, _ = redact_sensitive(text)
    return redacted, pii_types


def scan(text: str) -> ScanResult:
    findings: list[Finding] = []
    findings.extend(Finding("prompt_injection", name, "high") for name, rule in INJECTION_RULES.items() if rule.search(text))
    findings.extend(Finding("harmful_instruction", name, "high") for name, rule in HARM_RULES.items() if rule.search(text))
    redacted, pii_types, secret_types = redact_sensitive(text)
    findings.extend(Finding("pii", name, "medium") for name in pii_types)
    findings.extend(Finding("secret", name, "critical") for name in secret_types)
    return ScanResult(redacted, tuple(findings), pii_types)


def sanitize_json(value: Any) -> tuple[Any, tuple[Finding, ...]]:
    findings: list[Finding] = []
    if isinstance(value, str):
        result = scan(value)
        return result.text, result.findings
    if isinstance(value, list):
        rendered = []
        for item in value:
            clean, item_findings = sanitize_json(item)
            rendered.append(clean)
            findings.extend(item_findings)
        return rendered, tuple(findings)
    if isinstance(value, dict):
        rendered = {}
        for key, item in value.items():
            clean, item_findings = sanitize_json(item)
            rendered[key] = clean
            findings.extend(item_findings)
        return rendered, tuple(findings)
    return value, ()


def unsafe_url_reason(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        return "unsupported_scheme"
    host = (parsed.hostname or "").lower()
    if not host:
        return "missing_host"
    if host in {"localhost", "metadata.google.internal"} or host.endswith(".local"):
        return "local_host"
    try:
        address = ipaddress.ip_address(host)
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            return "non_public_address"
    except ValueError:
        pass
    return None
