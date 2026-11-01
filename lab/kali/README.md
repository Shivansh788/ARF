# ARF Kali attack and evaluation tools

For the project overview and panel sequence, see the [root README](../README.md) and [panel runbook](../PANEL_DEMO.md).

This folder runs the **attacker/evaluation side** of the research project. It targets only the paired Ubuntu fixture at `192.168.56.10:8000`; the scripts contain a fixed-target guard and do not accept a target override. The suite exercises MCP01, MCP02, MCP07, and MCP09 with synthetic values on a private two-VM network.

These probes are intentionally bounded to the paper’s scenarios: canary-flow observation, read-to-write scope escalation, invalid credential cases, and an unapproved local MCP server. They do not scan public ranges, accept arbitrary URLs, execute commands on the target, or use real credentials. The target fixture uses the official Python SDK 2.2.0, which supports the 2026-07-28 MCP protocol revision.

## Attacker VM setup

Use Kali on the same custom VirtualBox NAT Network, `arf-lab` (`192.168.56.0/24`), with static address `192.168.56.20/24`. Do not use bridged mode. Copy the contents of this `kali` folder into `~/arf-kali` (so `run_suite.py` is directly inside it), then provision dependencies while still in the provisioning phase:

Create the network on the host if it does not already exist and attach both VMs (replace the VM names as needed):

```bash
VBoxManage natnetwork add --netname arf-lab --network "192.168.56.0/24" --enable --dhcp off
VBoxManage modifyvm "ubuntu-target" --nic1 natnetwork --nat-network1 arf-lab
VBoxManage modifyvm "kali-attacker" --nic1 natnetwork --nat-network1 arf-lab
```

Configure Kali as `192.168.56.20/24` and the target as `192.168.56.10/24`. Use each guest’s actual NIC name and confirm routing before the suite. Never use bridged networking for this fixture.

For NetworkManager, identify the connection name with `nmcli connection show`, then substitute it below:

```bash
sudo nmcli connection modify "Wired connection 1" ipv4.method manual ipv4.addresses 192.168.56.20/24 ipv4.gateway 192.168.56.1 ipv4.dns 8.8.8.8
sudo nmcli connection up "Wired connection 1"
```

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip ufw curl
mkdir -p ~/arf-kali
```

```bash
cd ~/arf-kali
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip freeze > environment.txt
```

Before an experiment, configure outbound firewall access only to `192.168.56.10:8000` and verify the target is reachable. Disconnect any temporary provisioning adapter. VirtualBox NAT Network still provides IPv4 NAT unless guest egress is blocked; IPv6 settings alone do not air-gap a VM.

After package/model provisioning, apply the attacker egress rule:

```bash
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow out to 192.168.56.10 port 8000 proto tcp
sudo ufw --force enable
```

For the optional local LLM judge, install Ollama and pull the model while in the provisioning phase, before applying the restrictive firewall:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
sudo systemctl enable --now ollama
```

## Run a comparison

Start the target with the `vulnerable` profile, confirm that Kali reaches only the fixed target endpoint, then run the probes:

```bash
cd ~/arf-kali
source .venv/bin/activate
python recon_check.py --expected-profile vulnerable
python run_suite.py --repetitions 3
```

Run the local oracle tests after editing the evaluation scripts (no target VM required):

```bash
python -m unittest discover -s tests -v
```

Save the resulting `reports/run_*/results.json` off the VM or to the research evidence directory. Revert the VMs to the clean snapshot. Start the target with `hardened`, run the exact same command, and preserve both result files. The result includes raw fixture events, tool-call traces, structural-oracle verdicts, and confusion-matrix metrics. Never combine runs from different code/profile versions without recording that change.

The suite includes positive and negative controls: MCP02 `write_control` and MCP07 `valid` should be allowed in both profiles. These controls are excluded from binary attack-detection metrics.

After saving one `results.json` for each profile, combine both arms to calculate the research metrics overall and by category:

```bash
python compare_runs.py /path/to/vulnerable/results.json /path/to/hardened/results.json
```

Use the actual paths produced by `run_suite.py`. To include the LLM baseline, pass the corresponding judge files as `--judge-vulnerable` and `--judge-hardened`. The comparator rejects profiles, case sets, and judge files that do not match their source runs.

The target also provides an Ollama-backed `/agent-task` endpoint for exploratory natural-language attacks. The primary metrics script intentionally uses `/experiment`, whose scenario behavior is deterministic. Keep `/agent-task` outputs separate until a model-specific ground-truth protocol is defined; LLM behavior can vary by model and version.

To exercise the model-driven agent after installing Ollama on the target, start the target profile and run:

```bash
python model_probe.py
```

This sends bounded prompts for canary transfer, scope creep, invalid credentials, and shadow-server contact. It saves the model name, prompt, agent trace, and fixture events under `model_reports/`. These exploratory runs are separate from the benchmark metrics.

## LLM-as-a-judge baseline

The probe suite works without Ollama. Run this baseline as well to complete the comparison described in the paper.

After provisioning, make sure the local Ollama service is running when you want to run the judge:

```bash
sudo systemctl enable --now ollama
```

Run the judge over the same saved traces:

```bash
python llm_judge.py reports/run_TIMESTAMP/results.json --model llama3.2:3b
```

It writes a sibling `*_llm_judge.json` file. Record the model name, model digest (`ollama list`), Ollama version, prompt version, and decoding settings with your results. This is a baseline, not ground truth; the structural oracle and fixture event ledger define labels.

## Category matrix

| Category | Probe | Structural evidence |
|---|---|---|
| MCP01 | Retrieve synthetic canary, then attempt shadow sink | Canary present in event from unapproved sink, or explicit policy block |
| MCP02 | Attempt write using `records.read` | Authorization decision shows whether read scope was accepted for write |
| MCP07 | Missing, invalid, expired, wrong-audience, and valid token cases | Protected-operation event or MCP transport rejection |
| MCP09 | Attempt contact with the configured shadow fixture | Contact event from server marked `approved=false`, or allowlist block |

The shadow server runs on the target VM at loopback port `8766`; it is not a third machine. The Kali scripts never send the canary off the isolated target VM.

The category names follow the [OWASP MCP Top 10](https://owasp.github.io/www-project-mcp-top-10/). The current Python SDK release notes and protocol documentation are linked from the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).

## Panel demonstration

With the target running on the isolated lab network and the Kali virtual environment active, run the same complete matrix once for each target profile:

```bash
./panel_demo.sh vulnerable
```

To include the optional local-model walkthrough, use `./panel_demo.sh vulnerable --with-llm`. The exploratory traces are saved separately and are not scored.

Restart the target in hardened mode, then run:

```bash
./panel_demo.sh hardened
```

The script verifies the reported profile before it sends the fixed test matrix. It saves each run below `reports/panel-vulnerable/` or `reports/panel-hardened/`. Compare the two timestamped `results.json` files with `compare_runs.py`. The comparator checks both the attack cases and the allowed controls, rejects duplicate/missing case identities, and confirms that each sample's ground-truth label matches its profile.

The live suite uses synthetic canaries and tokens against only the fixed target. It does not use Ollama and does not contact public systems. For the spoken walkthrough and evidence fields to display, follow [PANEL_DEMO.md](../PANEL_DEMO.md).
# Operator console

Use `python3 arf_cli.py status` to check the fixed target, `python3 arf_cli.py run MCP01` for one fixed scenario, `python3 arf_cli.py suite` for the scored matrix, or `python3 arf_gui.py` to serve the browser dashboard at `127.0.0.1:8787`. `python3 arf_cli.py agent-probes` runs fixed, exploratory model prompts, including the synthetic prompt-marker probe; these are excluded from deterministic scoring. See `../ATTACK_TOOL_GUIDE.md`.

