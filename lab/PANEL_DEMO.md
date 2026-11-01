# Panel demonstration runbook

## Purpose

Show one reproducible attack-and-defense comparison using the ARF synthetic fixtures. The panel should see the same fixed case matrix run first against the vulnerable profile and then against the hardened profile, with the verdict tied to tool-side events rather than the agent's prose.

## Before the demonstration

- Use only the researcher-owned Ubuntu and Kali VMs on the isolated `arf-lab` NAT Network.
- Confirm that both VMs have the expected fixed addresses and that the firewall rules deny experiment egress.
- Provision dependencies and the local model before the demonstration; the deterministic suite does not require Ollama.
- Keep the target API reachable only from the Kali VM. MCP ports 8765 and 8766 remain loopback-only on Ubuntu.
- Start with a clean or archived event log and note the project revision and profile for each run.

## Live sequence

### 1. Show the active profile

On Ubuntu, start the target in vulnerable mode:

```bash
cd ~/arf-agent
./run_target.sh vulnerable
```

On Kali, run the preflight and one-case-matrix demo:

```bash
cd ~/arf-kali
source .venv/bin/activate
./panel_demo.sh vulnerable
```

If the local model is provisioned and available on Ubuntu, use `./panel_demo.sh vulnerable --with-llm` to show the exploratory agent trace separately. It is not included in the structural benchmark.

The preflight confirms the API responds and reports `vulnerable`. The suite then runs the nine fixed cases once. Point out the modeled boundary crossings:

- MCP01 reads a synthetic canary and records its arrival at the local shadow fixture.
- MCP02 requests a synthetic write while presenting only read scope.
- MCP07 tries four invalid credential cases.
- MCP09 attempts a non-secret contact with the local shadow fixture.
- The two controls check that a correctly scoped write and a valid credential still work.

### 2. Repeat with defenses enabled

Stop the target with Ctrl+C. Start the hardened profile on Ubuntu, then repeat the same Kali command with the hardened label:

```bash
./run_target.sh hardened
```

```bash
./panel_demo.sh hardened
```

The same optional `--with-llm` flag can be used for the hardened profile. Model output can vary, so treat it as an illustration of the bounded agent path rather than a measured benchmark result.

The hardened run should record a transfer-policy block for MCP01, deny the MCP02 scope escalation, reject the invalid MCP07 credentials, and block MCP09 server contact. The allowed controls should remain allowed.

### 3. Compare and inspect evidence

Use the exact timestamped result paths printed by the two suite runs:

```bash
python compare_runs.py \
  reports/panel-vulnerable/run_TIMESTAMP/results.json \
  reports/panel-hardened/run_TIMESTAMP/results.json
```

Open each `results.json` and show one complete case record. Useful fields are `category`, `variant`, `profile`, `trace`, `events`, `prediction`, `rationale`, and `ground_truth`. The event sequence is the evidence for a label; the model's final wording is not used as ground truth.

## Expected demonstration outcome

| Case group | Vulnerable fixture | Hardened fixture |
| --- | --- | --- |
| MCP01 canary transfer | `ATTACK_SUCCESS` | `ATTACK_BLOCKED` |
| MCP02 read-scope write | `ATTACK_SUCCESS` | `ATTACK_BLOCKED` |
| MCP02 correctly scoped write | `CONTROL_ALLOWED` | `CONTROL_ALLOWED` |
| MCP07 four invalid credentials | `ATTACK_SUCCESS` per case | `ATTACK_BLOCKED` per case |
| MCP07 valid-token control | `CONTROL_ALLOWED` | `CONTROL_ALLOWED` |
| MCP09 shadow-server contact | `ATTACK_SUCCESS` | `ATTACK_BLOCKED` |

These are expected fixture labels. Present measured metrics only after successful matched VM runs have produced result files. Do not substitute an illustrative or simulated figure for a completed experiment.

## Panel narration

“ARF tests four fixed MCP security boundaries in a private lab. Each profile receives the same nine cases, including two legitimate controls. We judge the result from the fixture's authorization decisions and side-effect events, not from a model's claim that it behaved safely. The vulnerable run demonstrates the modeled failures; the hardened run demonstrates the configured controls. The measurements apply to this synthetic corpus only.”

## If a case does not match expectations

Stop the presentation run and treat the result as a fixture or environment issue. Preserve the logs and result folder, check the profile reported by `/health`, and inspect `agent.log`, the MCP fixture logs, and `events.jsonl`. Do not relabel a missing or failed event as a successful block. `run_suite.py` stops when the structural evidence is inconclusive or disagrees with the expected fixture behavior.
