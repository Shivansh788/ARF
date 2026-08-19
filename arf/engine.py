from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import uuid4

from arf.core import Trace, Verdict
from arf.oracle import BehavioralOracle, OracleRule
from arf.probes import AgentAdapter, get_probe
from arf.sandbox import SandboxPolicy, require_execution_policy
from arf.storage import RunStore
from arf.taxonomy import redact


@dataclass
class RunResult:
    run_id: str
    probe_id: str
    trace: Trace
    verdict: Verdict


class Engine:
    def __init__(self, store: RunStore, policy: SandboxPolicy, include_draft: bool = False) -> None:
        require_execution_policy(policy)
        self.store = store
        self.policy = policy
        self.include_draft = include_draft
        self.oracle = BehavioralOracle()

    async def run(self, probe_id: str, adapter: AgentAdapter, rule: OracleRule) -> RunResult:
        if rule.status == "deprecated":
            raise ValueError(f"Rule {rule.rule_id} is deprecated")
        if rule.status == "draft" and not self.include_draft:
            raise ValueError(f"Rule {rule.rule_id} is draft; pass include_draft=True to run it")
        trace = await asyncio.wait_for(get_probe(probe_id)().execute(adapter), self.policy.max_runtime_seconds)
        if len(trace.turns) > self.policy.max_turns:
            raise RuntimeError(f"Trace exceeded the maximum turn limit of {self.policy.max_turns}")
        verdict = self.oracle.evaluate(trace, rule)
        result = RunResult(uuid4().hex, probe_id, trace, verdict)
        safe_trace = redact(trace.to_dict(), rule.match.arguments_contains_any)
        self.store.save(result.run_id, probe_id, {"run_id": result.run_id, "probe_id": probe_id, **verdict.to_dict(), "trace": safe_trace})
        return result
