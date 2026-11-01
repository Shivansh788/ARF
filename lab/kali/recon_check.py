#!/usr/bin/env python3
"""Fixed-target preflight; contacts only the configured lab agent API."""
from __future__ import annotations

import argparse
import json

import requests

from arf_common import TARGET_BASE, TARGET_IP, guard_target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-profile", choices=("vulnerable", "hardened"))
    args = parser.parse_args()
    guard_target()
    try:
        response = requests.get(f"{TARGET_BASE}/health", timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise SystemExit(f"Preflight failed for fixed target {TARGET_IP}: {exc}") from exc
    state = response.json()
    if state.get("status") != "ok":
        raise SystemExit(f"Unexpected health response: {state}")
    if args.expected_profile and state.get("profile") != args.expected_profile:
        raise SystemExit(f"Expected {args.expected_profile}, target reports {state.get('profile')}")
    print(json.dumps({"target": TARGET_IP, "health": state, "scope": "single fixed lab host"}, indent=2))


if __name__ == "__main__":
    main()
