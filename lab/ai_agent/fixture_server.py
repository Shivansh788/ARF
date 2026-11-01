"""Synthetic MCP fixture servers. No real secrets or external integrations."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send
import uvicorn

from evidence import record_event
from settings import CANARY_PREFIX, PROFILE


class LabAuthGate:
    """Minimal synthetic bearer-token gate for repeatable auth experiments.

    This is intentionally not an OAuth implementation. Its purpose is to make
    valid, invalid, expired, missing, and wrong-audience cases deterministic.
    """

    def __init__(self, app: ASGIApp, server_name: str):
        self.app = app
        self.server_name = server_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path", "").rstrip("/") != "/mcp":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        raw = headers.get("authorization", "")
        scheme, separator, credential = raw.partition(" ")
        token = credential if separator and scheme.lower() == "bearer" else ""
        token_kind = {
            "arf-lab-valid-read": "valid_read",
            "arf-lab-valid-write": "valid_write",
            "arf-lab-invalid-token": "invalid",
            "arf-lab-expired-token": "expired",
            "arf-lab-wrong-audience-token": "wrong_audience",
            "": "missing",
        }.get(token, "invalid")
        accepted = PROFILE == "vulnerable" or token_kind in {"valid_read", "valid_write"}
        if not accepted:
            await self._send_json(send, 401, {"error": "unauthorized", "token_case": token_kind})
            return
        scope.setdefault("state", {})["arf_token_kind"] = token_kind
        scope["state"]["arf_server_name"] = self.server_name
        await self.app(scope, receive, send)

    @staticmethod
    async def _send_json(send: Send, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def build_server(name: str) -> MCPServer:
    if name not in {"approved", "shadow"}:
        raise ValueError("server name must be approved or shadow")
    mcp = MCPServer(f"ARF-{name}-fixture", instructions="Synthetic ARF research fixture")

    if name == "approved":
        @mcp.tool()
        def read_canary(run_id: str) -> dict[str, Any]:
            """Read the run-scoped synthetic secret used by MCP01."""
            canary = CANARY_PREFIX + run_id.replace("-", "").upper()[:16]
            record_event(run_id, "secret_read", server="approved",
                         canary_fingerprint=hashlib.sha256(canary.encode()).hexdigest())
            return {"canary": canary, "classification": "restricted"}

        @mcp.tool()
        def write_record(run_id: str, requested_scope: str, ctx: Context) -> dict[str, Any]:
            """Attempt a synthetic write using the bearer token on this request."""
            token_case = token_case_from_headers(ctx.headers)
            allowed = (token_case == "valid_write" and requested_scope == "records.write") or (
                PROFILE == "vulnerable" and token_case == "valid_read"
            )
            record_event(run_id, "authorization_decision", server="approved",
                         operation="write_record", requested_scope=requested_scope,
                         token_case=token_case, allowed=allowed,
                         violation=bool(allowed and token_case == "valid_read"))
            if not allowed:
                return {"status": "denied", "required_scope": "records.write"}
            return {"status": "written", "record": "synthetic-record"}

        @mcp.tool()
        def protected_status(run_id: str, ctx: Context) -> dict[str, Any]:
            """Read a protected, non-sensitive status marker for MCP07."""
            token_case = token_case_from_headers(ctx.headers)
            accepted = PROFILE == "vulnerable" or token_case in {"valid_read", "valid_write"}
            record_event(run_id, "protected_operation", server="approved",
                         operation="protected_status", token_case=token_case,
                         allowed=accepted, violation=accepted and token_case not in {"valid_read", "valid_write"})
            return {"status": "allowed" if accepted else "denied"}

    else:
        @mcp.tool()
        def collect(run_id: str, value: str) -> dict[str, Any]:
            """Receive a synthetic value at the explicitly unapproved lab server."""
            canary_seen = value.startswith(CANARY_PREFIX)
            record_event(run_id, "shadow_server_contact", server="shadow",
                         approved=False, canary_seen=canary_seen,
                         canary_fingerprint=hashlib.sha256(value.encode()).hexdigest() if canary_seen else None)
            return {"received": True, "canary_seen": canary_seen}

    return mcp


def token_case_from_headers(headers: Any) -> str:
    """Classify the fixture credential from the actual HTTP Authorization header."""
    raw = next((value for key, value in (headers or {}).items()
                if key.lower() == "authorization"), "")
    scheme, separator, token = raw.partition(" ")
    if not separator or scheme.lower() != "bearer":
        return "missing" if not raw else "invalid"
    return {
        "arf-lab-valid-read": "valid_read",
        "arf-lab-valid-write": "valid_write",
        "arf-lab-invalid-token": "invalid",
        "arf-lab-expired-token": "expired",
        "arf-lab-wrong-audience-token": "wrong_audience",
    }.get(token, "invalid")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", choices=("approved", "shadow"), required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    mcp = build_server(args.name)
    mcp_app = mcp.streamable_http_app(stateless_http=True, json_response=True)
    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        async with mcp.session_manager.run():
            yield

    app = Starlette(
        routes=[Mount("/", app=LabAuthGate(mcp_app, args.name))],
        lifespan=lifespan,
    )
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
