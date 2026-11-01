#!/usr/bin/env python3
"""Local-only browser dashboard for the fixed ARF lab target."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

from arf_common import TARGET_BASE, TARGET_IP, execute, guard_target
from run_suite import CASES
from structural_oracle import classify, expected_label

HERE = Path(__file__).resolve().parent
RUN_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, mime: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/":
            return self._send(200, (HERE / "gui" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path == "/app.js":
            return self._send(200, (HERE / "gui" / "app.js").read_bytes(), "text/javascript; charset=utf-8")
        if self.path == "/style.css":
            return self._send(200, (HERE / "gui" / "style.css").read_bytes(), "text/css; charset=utf-8")
        if self.path == "/api/status":
            try:
                guard_target()
                r = requests.get(f"{TARGET_BASE}/health", timeout=5)
                r.raise_for_status()
                return self._json(200, {"target": TARGET_IP, **r.json()})
            except Exception as exc:
                return self._json(503, {"error": str(exc)})
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path not in {"/api/run", "/api/suite"}:
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1024:
            return self._json(413, {"error": "request too large"})
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("body must be an object")
            with RUN_LOCK:
                guard_target()
                if self.path == "/api/run":
                    cat, variant = payload.get("category"), payload.get("variant")
                    if (cat, variant) not in CASES:
                        return self._json(400, {"error": "choose one of the listed fixed cases"})
                    result = execute(cat, variant)
                    observed, rationale = classify(result)
                    expected = expected_label(result)
                    return self._json(200, {"category": cat, "variant": variant,
                        "profile": result.get("profile"), "observed": observed,
                        "expected": expected, "rationale": rationale,
                        "events": result.get("events", [])})
                samples = []
                profile = None
                for cat, variant in CASES:
                    result = execute(cat, variant)
                    if result.get("category") != cat or result.get("variant") != variant:
                        raise RuntimeError(f"Target response identity mismatch for {cat}/{variant}")
                    if profile is None:
                        profile = result.get("profile")
                    elif result.get("profile") != profile:
                        raise RuntimeError("Target profile changed during the suite; discard this result")
                    observed, rationale = classify(result)
                    expected = expected_label(result)
                    if observed == "INCONCLUSIVE" or observed != expected:
                        raise RuntimeError(f"{cat}/{variant}: observed {observed}, expected {expected}: {rationale}")
                    samples.append({"category": cat, "variant": variant,
                        "observed": observed, "expected": expected,
                        "events": result.get("events", [])})
                return self._json(200, {"profile": profile, "samples": samples,
                                        "note": "Deterministic structural outcomes; fixed nine-case suite."})
        except Exception as exc:
            return self._json(502, {"error": str(exc)})

    def _json(self, code: int, value: dict) -> None:
        self._send(code, json.dumps(value, indent=2).encode(), "application/json; charset=utf-8")

    def log_message(self, *_args) -> None:
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8787), Handler)
    print(f"ARF dashboard: http://127.0.0.1:8787  | fixed lab target {TARGET_IP}:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
