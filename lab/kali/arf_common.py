"""Shared target guard and HTTP helpers for the fixed two-VM experiment."""
from __future__ import annotations

import ipaddress
import json
import sys
from typing import Any

import requests

TARGET_IP = "192.168.56.10"
TARGET_BASE = f"http://{TARGET_IP}:8000"
LAB_NETWORK = ipaddress.ip_network("192.168.56.0/24")


def guard_target() -> None:
    address = ipaddress.ip_address(TARGET_IP)
    if address not in LAB_NETWORK or str(address) != "192.168.56.10":
        raise SystemExit("REFUSED: target must remain the fixed lab VM 192.168.56.10")


def execute(category: str, variant: str, timeout: float = 45) -> dict[str, Any]:
    guard_target()
    try:
        response = requests.post(
            f"{TARGET_BASE}/experiment",
            json={"category": category, "variant": variant},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise SystemExit(f"Cannot reach the fixed lab target {TARGET_IP}: {exc}") from exc
    if response.status_code != 200:
        raise SystemExit(f"Target rejected {category}/{variant}: HTTP {response.status_code} {response.text[:200]}")
    return response.json()


def write_json(path: str, value: Any) -> None:
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
