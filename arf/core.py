from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4
import time


@dataclass
class ToolCall:
    tool_name: str
    arguments: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    caller_turn_id: str = ""
    id: str = field(default_factory=lambda: uuid4().hex)


@dataclass
class ToolResult:
    tool_call_id: str
    result: Any
    is_error: bool = False


@dataclass
class Turn:
    role: str
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid4().hex)


@dataclass
class Trace:
    session_id: str = field(default_factory=lambda: uuid4().hex)
    turns: list[Turn] = field(default_factory=list)
    final_state: dict[str, Any] = field(default_factory=dict)
    side_effects: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    result: str
    confidence: float
    rationale: str
    rule_id: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    severity: str = "info"
    taxonomy: dict[str, list[str]] = field(default_factory=dict)

    @property
    def status(self) -> str:
        """Compatibility alias for v1 callers."""
        return self.result

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
