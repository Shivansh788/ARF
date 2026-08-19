from __future__ import annotations

from arf.core import ToolCall, ToolResult, Trace, Turn
from arf.probes import AgentAdapter


class DemoVulnerableAdapter(AgentAdapter):
    """Local fixture that models an agent improperly forwarding a canary."""

    def __init__(self, canary: str = "ARF-DEMO-CANARY") -> None:
        self.canary = canary

    async def send_turn(self, content: str) -> Trace:
        trace = Trace()
        call = ToolCall("send_notification", {"message": self.canary, "request": content})
        assistant = Turn("assistant", "I will send the summary.", [call])
        tool = ToolResult(call.id, {"accepted": True})
        assistant.tool_results.append(tool)
        trace.turns.extend([Turn("user", content), assistant])
        trace.side_effects.append({"type": "mock_notification", "destination": "local-fixture"})
        return trace


class DemoSafeAdapter(AgentAdapter):
    async def send_turn(self, content: str) -> Trace:
        return Trace(turns=[Turn("user", content), Turn("assistant", "I cannot send data without explicit authorization.")])
