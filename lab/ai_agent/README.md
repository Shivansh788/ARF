# ARF AI agent fixtures

For the project overview and paired panel demonstration, start with the [root README](../README.md) and [panel runbook](../PANEL_DEMO.md). The MCP client uses the declared `httpx` dependency directly so the target API can start in a clean project virtual environment.

This folder runs the **target side** of the research lab. It contains two real MCP Streamable HTTP fixture servers and a bounded agent API, using the official Python SDK 2.2.0 and the 2026-07-28 protocol revision. The fixture produces deterministic vulnerable/hardened outcomes for MCP01, MCP02, MCP07, and MCP09. It uses synthetic records and synthetic bearer tokens only. Its fixture token gate is not an OAuth conformance implementation and it does not connect to third-party systems.

The `/experiment` API executes a fixed scenario selected by name; it does not run arbitrary shell commands or accept arbitrary MCP URLs. This is the deterministic fixture used for the main vulnerable-versus-hardened metrics. The separate `/agent-task` endpoint is a local Ollama-backed agent path for exploratory, natural-language attacks. It has a fixed tool list, a four-call limit, and no shell or arbitrary URL tool. Keep its results separate from the deterministic corpus unless the experiment protocol is extended to label its model-dependent outcomes.

## Lab network

Use two VMs attached only to a custom **VirtualBox NAT Network** named `arf-lab`, subnet `192.168.56.0/24`:

| VM | Address | Purpose |
|---|---|---|
| Ubuntu 24.04 target | `192.168.56.10` | Agent API and MCP fixtures |
| Kali attacker | `192.168.56.20` | Probe runner and judge |

Do not use bridged networking. Keep a separate temporary provisioning adapter only if needed, then disconnect it before experiments. Confirm egress is blocked at the VM/firewall level before running a suite; disabling IPv6 alone does not disable IPv4 NAT.

Create and attach the network on the host (change VM names to the names you gave your VMs):

```bash
VBoxManage natnetwork add --netname arf-lab --network "192.168.56.0/24" --enable --dhcp off
VBoxManage modifyvm "ubuntu-target" --nic1 natnetwork --nat-network1 arf-lab
VBoxManage modifyvm "kali-attacker" --nic1 natnetwork --nat-network1 arf-lab
```

With DHCP disabled, configure `.10/24` and `.20/24` manually in the respective guests and confirm the default route points to the NAT Network gateway. VirtualBox can still NAT guest traffic to the internet, so enforce the outbound firewall rules below before starting experiments.

## Target VM setup

On a fresh Ubuntu 24.04 VM, first find the interface name with `ip -br link`, then create `/etc/netplan/99-arf-lab.yaml` using the actual name in place of `enp0s3`:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [192.168.56.10/24]
      routes:
        - to: default
          via: 192.168.56.1
      nameservers:
        addresses: [8.8.8.8]
```

Apply with `sudo netplan try` and `sudo netplan apply`. The DNS setting is for provisioning only; experiment egress is denied by UFW.

The remaining setup assumes Python 3.12 from the Ubuntu 24.04 image. For the model-driven `/agent-task` path, install Ollama and pull a local model during provisioning:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip curl
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:3b
sudo systemctl enable --now ollama
mkdir -p ~/arf-agent
```

Copy the contents of this `ai_agent` folder into `~/arf-agent` (so `run_target.sh` is directly inside it), then:

```bash
cd ~/arf-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip freeze > environment.txt
```

Permit inbound TCP `8000` from `192.168.56.20` only. Ports `8765` and `8766` bind to loopback and must not be opened on the VM network interface.

Example UFW rules:

```bash
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow in from 192.168.56.20 to 192.168.56.10 port 8000 proto tcp
sudo ufw allow out to 127.0.0.1
sudo ufw --force enable
```

Run one profile at a time:

```bash
cd ~/arf-agent
./run_target.sh vulnerable
# Stop with Ctrl-C, then run the comparison arm:
./run_target.sh hardened
```

Ollama's service must be running locally for `/agent-task`. Confirm it binds only to loopback (`127.0.0.1:11434`) and keep it off the VM network interface. The deterministic `/experiment` endpoint does not require a model. If needed, set `OLLAMA_HOST=127.0.0.1:11434` in the Ollama service environment before starting it.

The target writes JSONL ground-truth evidence and service logs under `~/arf-agent/logs/`. Snapshot both VMs before each profile, clear or archive the previous evidence directory, and record the profile and run identifier with collected results.

## Fixture behavior

* **MCP01:** reads a run-scoped synthetic canary. The vulnerable profile sends it to the local shadow MCP sink; the hardened profile records a policy block.
* **MCP02:** attempts a write while presenting only `records.read`. The vulnerable profile accepts this scope creep; the hardened profile denies it.
* **MCP07:** tries missing, invalid, expired, and wrong-audience synthetic tokens. The vulnerable profile accepts them; the hardened profile rejects them. A valid-token control is also available.
* **MCP09:** the vulnerable profile contacts the unapproved local shadow server; the hardened profile blocks the connection via its fixed server allowlist.

The “vulnerable” and “hardened” profiles intentionally model one control per category. They are teaching fixtures, not production security configurations. The synthetic `LabAuthGate` is a deterministic test gate, not OAuth. The results support claims about this fixture corpus only.

The target API and the two fixture processes append ground-truth records to the same JSONL file. `evidence.py` uses both a thread lock and a POSIX file lock so concurrent writes from separate local processes remain line-delimited. The project targets Linux VMs, where `fcntl.flock` is available.

## Reference alignment

The selected categories follow the [OWASP MCP Top 10](https://owasp.github.io/www-project-mcp-top-10/). The fixture uses the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/releases) 2.2.0 line, which supports the 2026-07-28 protocol revision. The synthetic token gate is intentionally separate from the protocol's OAuth authorization implementation.
