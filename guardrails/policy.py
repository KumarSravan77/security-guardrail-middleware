from __future__ import annotations

import os
from dataclasses import dataclass

from .scanner import Finding


@dataclass(frozen=True)
class GuardrailPolicy:
    version: str = "2026-08-17"
    mode: str = "block"
    max_body_bytes: int = 100_000
    block_input_categories: frozenset[str] = frozenset({"prompt_injection", "harmful_instruction", "secret"})
    block_output_categories: frozenset[str] = frozenset({"harmful_instruction"})
    excluded_paths: frozenset[str] = frozenset({"/healthz", "/readyz", "/metrics"})

    @classmethod
    def from_env(cls, mode: str | None = None, max_body_bytes: int | None = None) -> "GuardrailPolicy":
        selected_mode = mode or os.getenv("GUARDRAIL_MODE", "block")
        if selected_mode not in {"block", "monitor"}:
            raise ValueError("GUARDRAIL_MODE must be block or monitor")
        return cls(
            version=os.getenv("GUARDRAIL_POLICY_VERSION", cls.version),
            mode=selected_mode,
            max_body_bytes=max_body_bytes or int(os.getenv("GUARDRAIL_MAX_BODY_BYTES", "100000")),
        )

    def should_block(self, findings: tuple[Finding, ...], direction: str) -> bool:
        if self.mode == "monitor":
            return False
        categories = self.block_input_categories if direction == "input" else self.block_output_categories
        return any(f.category in categories for f in findings)
