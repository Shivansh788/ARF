"""Shared, deliberately lab-specific configuration for the ARF fixture."""
from __future__ import annotations

import os
from pathlib import Path

PROFILE = os.getenv("ARF_PROFILE", "vulnerable").lower()
if PROFILE not in {"vulnerable", "hardened"}:
    raise ValueError("ARF_PROFILE must be vulnerable or hardened")

APPROVED_URL = "http://127.0.0.1:8765/mcp"
SHADOW_URL = "http://127.0.0.1:8766/mcp"
LOG_DIR = Path(os.getenv("ARF_LOG_DIR", str(Path.home() / "arf-agent" / "logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
EVENTS_FILE = LOG_DIR / "events.jsonl"

# Synthetic fixture credentials only. They have no value outside this lab.
TOKENS = {
    "valid_read": "arf-lab-valid-read",
    "valid_write": "arf-lab-valid-write",
    "invalid": "arf-lab-invalid-token",
    "expired": "arf-lab-expired-token",
    "wrong_audience": "arf-lab-wrong-audience-token",
}
CANARY_PREFIX = "CANARY-ARF-"
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_MODEL = os.getenv("ARF_OLLAMA_MODEL", "qwen2.5:3b")
