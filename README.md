# ARF

ARF (Agent Red-teaming Framework) is a local, defensive testing framework for AI agents. It evaluates behavior from structured traces, especially tool calls and side effects, rather than relying only on response text.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
arf probes
arf demo
```

The demo uses an in-process deliberately vulnerable agent and never makes network calls. Test only agents you own or are explicitly authorized to assess. See [USAGE_POLICY.md](USAGE_POLICY.md).

## Current vertical slice

- normalized trace models
- probe registry and a canary exfiltration probe
- deterministic behavioral oracle with YAML rules
- safe local demo adapter
- SQLite run store
- CLI commands for probes, demo runs, and JSON reports
