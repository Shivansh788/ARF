from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import yaml

from arf.core import Trace, Verdict
from arf.taxonomy import redact, validate_taxonomy


class MatchRule(BaseModel):
    tool_name_pattern: str = ".*"
    arguments_contains_any: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        re.compile(self.tool_name_pattern)


class OracleRule(BaseModel):
    rule_id: str
    description: str = ""
    match: MatchRule
    severity: str = "medium"
    taxonomy: dict[str, list[str]] = Field(default_factory=dict)
    status: str = "draft"
    validation: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        validate_taxonomy(self.taxonomy)
        if self.status not in {"draft", "stable", "deprecated"}:
            raise ValueError("Rule status must be draft, stable, or deprecated")


class BehavioralOracle:
    def evaluate(self, trace: Trace, rule: OracleRule) -> Verdict:
        evidence: list[dict[str, Any]] = []
        for turn in trace.turns:
            for call in turn.tool_calls:
                if not re.search(rule.match.tool_name_pattern, call.tool_name):
                    continue
                arguments = repr(call.arguments)
                markers = rule.match.arguments_contains_any
                matched_marker = next((marker for marker in markers if marker in arguments), None)
                if markers and matched_marker is None:
                    continue
                evidence.append({"turn_id": turn.id, "tool_call_id": call.id, "tool_name": call.tool_name, "arguments": call.arguments, "matched_marker": matched_marker})
        if evidence:
            safe_evidence = redact(evidence, rule.match.arguments_contains_any)
            return Verdict("SUCCESS", 1.0, f"Rule {rule.rule_id} matched an observed tool call.", rule.rule_id, safe_evidence, rule.severity, rule.taxonomy)
        return Verdict("FAILURE", 1.0, f"Rule {rule.rule_id} found no matching tool call.", rule.rule_id, [], rule.severity, rule.taxonomy)


def load_rule(path: str | Path) -> OracleRule:
    """Load and validate one pinned YAML oracle rule."""
    with Path(path).open(encoding="utf-8") as stream:
        return OracleRule.model_validate(yaml.safe_load(stream))
