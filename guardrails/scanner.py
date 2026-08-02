import re
from dataclasses import dataclass


INJECTION_RULES = {
    "instruction_override": re.compile(
        r"\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|system|developer)\b.{0,20}\b(instruction|prompt|message)s?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "secret_exfiltration": re.compile(
        r"\b(reveal|print|show|leak|expose)\b.{0,40}\b(system prompt|developer message|secret|api key|credentials?)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "role_impersonation": re.compile(
        r"\b(you are now|act as)\b.{0,30}\b(system|developer|unrestricted|jailbroken)\b",
        re.IGNORECASE | re.DOTALL,
    ),
}

PII_RULES = {
    "email": re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "phone": re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\w)"),
    "ssn": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "credit_card": re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
}


@dataclass(frozen=True)
class ScanResult:
    text: str
    injection_rules: tuple[str, ...]
    pii_types: tuple[str, ...]

    @property
    def blocked(self) -> bool:
        return bool(self.injection_rules)


def _luhn_valid(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not 13 <= len(digits) <= 19:
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


def redact_pii(text: str) -> tuple[str, tuple[str, ...]]:
    found: list[str] = []
    redacted = text
    for name, pattern in PII_RULES.items():
        matches = list(pattern.finditer(redacted))
        if name == "credit_card":
            matches = [match for match in matches if _luhn_valid(match.group())]
        if not matches:
            continue
        found.append(name)
        for match in reversed(matches):
            redacted = redacted[:match.start()] + f"[REDACTED_{name.upper()}]" + redacted[match.end():]
    return redacted, tuple(found)


def scan(text: str) -> ScanResult:
    injection_rules = tuple(name for name, rule in INJECTION_RULES.items() if rule.search(text))
    redacted, pii_types = redact_pii(text)
    return ScanResult(redacted, injection_rules, pii_types)
