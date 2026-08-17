from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .scanner import unsafe_url_reason


@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    reason: str


class ToolPolicy:
    """Deterministic authorization boundary for model-proposed tool calls."""

    def __init__(self, allowed_tools: set[str], mutating_tools: set[str] | None = None):
        self.allowed_tools = allowed_tools
        self.mutating_tools = mutating_tools or set()

    def authorize(self, name: str, arguments: dict[str, Any], approved: bool = False) -> ToolDecision:
        if name not in self.allowed_tools:
            return ToolDecision(False, "tool_not_allowlisted")
        if name in self.mutating_tools and not approved:
            return ToolDecision(False, "human_approval_required")
        for key, value in arguments.items():
            if isinstance(value, str) and (key == "url" or key.endswith("_url")):
                if reason := unsafe_url_reason(value):
                    return ToolDecision(False, f"unsafe_url:{reason}")
        return ToolDecision(True, "allowed")
