#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source .venv/bin/activate
export ARF_PROFILE="${1:-vulnerable}"
case "$ARF_PROFILE" in vulnerable|hardened) ;; *) echo "profile must be vulnerable or hardened" >&2; exit 2 ;; esac
export ARF_LOG_DIR="$HOME/arf-agent/logs"
mkdir -p "$ARF_LOG_DIR"
python -m uvicorn agent_api:app --host 192.168.56.10 --port 8000 >"$ARF_LOG_DIR/agent.log" 2>&1 &
agent_pid=$!
python fixture_server.py --name approved --port 8765 >"$ARF_LOG_DIR/approved-mcp.log" 2>&1 &
approved_pid=$!
python fixture_server.py --name shadow --port 8766 >"$ARF_LOG_DIR/shadow-mcp.log" 2>&1 &
shadow_pid=$!
cleanup() { kill "$agent_pid" "$approved_pid" "$shadow_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
wait -n "$agent_pid" "$approved_pid" "$shadow_pid"
