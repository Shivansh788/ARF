#!/usr/bin/env python3
"""Friendly operator CLI for the fixed ARF two-VM lab."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import requests

from arf_common import TARGET_BASE, TARGET_IP, execute, guard_target
from structural_oracle import classify, expected_label

VARIANTS = {
    "MCP01": ("default",),
    "MCP02": ("read_scope", "write_control"),
    "MCP07": ("missing", "invalid", "expired", "wrong_audience", "valid"),
    "MCP09": ("default",),
}


def status(expected: str | None) -> None:
    guard_target()
    try:
        response = requests.get(f"{TARGET_BASE}/health", timeout=5)
        response.raise_for_status()
        info = response.json()
    except requests.RequestException as exc:
        raise SystemExit(f"Lab target {TARGET_IP} is not reachable: {exc}") from exc
    if info.get("status") != "ok" or info.get("profile") not in {"vulnerable", "hardened"}:
        raise SystemExit(f"Unexpected target response: {info}")
    if expected and info["profile"] != expected:
        raise SystemExit(f"Profile mismatch: expected {expected}, got {info['profile']}")
    print(f"Target: {TARGET_IP}:8000  Status: ready  Profile: {info['profile']}")


def run_case(category: str, variant: str) -> None:
    result = execute(category, variant)
    prediction, rationale = classify(result)
    expected = expected_label(result)
    print(json.dumps({"category": category, "variant": variant,
                      "profile": result.get("profile"), "observed": prediction,
                      "expected": expected, "rationale": rationale,
                      "events": result.get("events", [])}, indent=2))
    if prediction != expected:
        raise SystemExit("Observed behavior differs from the fixed fixture expectation.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p_status = commands.add_parser("status", help="check the fixed lab target")
    p_status.add_argument("--expect-profile", choices=("vulnerable", "hardened"))
    p_run = commands.add_parser("run", help="run one fixed deterministic scenario")
    p_run.add_argument("category", choices=tuple(VARIANTS))
    p_run.add_argument("--variant", choices=tuple(dict.fromkeys(v for values in VARIANTS.values() for v in values)))
    p_suite = commands.add_parser("suite", help="run all nine scored scenarios")
    p_suite.add_argument("--repetitions", type=int, default=1)
    p_probe = commands.add_parser("agent-probes", help="run fixed exploratory Ollama prompts (unscored)")
    args = parser.parse_args()
    if args.command == "status":
        status(args.expect_profile)
    elif args.command == "run":
        variant = args.variant or VARIANTS[args.category][0]
        if variant not in VARIANTS[args.category]:
            parser.error(f"{variant} is not available for {args.category}")
        run_case(args.category, variant)
    elif args.command == "suite":
        if not 1 <= args.repetitions <= 20:
            parser.error("--repetitions must be from 1 to 20")
        status(None)
        subprocess.run([sys.executable, "run_suite.py", "--repetitions", str(args.repetitions)],
                       check=True, cwd=Path(__file__).resolve().parent)
    elif args.command == "agent-probes":
        status(None)
        subprocess.run([sys.executable, "model_probe.py"], check=True,
                       cwd=Path(__file__).resolve().parent)


if __name__ == "__main__":
    main()
