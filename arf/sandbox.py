from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SandboxPolicy:
    """Execution policy; a direct process is never implicit."""

    unsafe_direct: bool = False
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")
    max_turns: int = 20
    max_runtime_seconds: int = 60
    egress_enabled: bool = False
    warnings: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.max_turns < 1 or self.max_runtime_seconds < 1:
            raise ValueError("Sandbox resource limits must be positive")
        if self.unsafe_direct and not self.warnings:
            raise PermissionError("Direct execution requires an explicit warning acknowledgement")
        if self.egress_enabled and not self.allowed_hosts:
            raise ValueError("Network egress requires an explicit host allow-list")


def require_execution_policy(policy: SandboxPolicy) -> None:
    policy.validate()
    if not policy.unsafe_direct:
        raise PermissionError("Sandboxed execution is required by default; use --unsafe-direct for the local demo")
