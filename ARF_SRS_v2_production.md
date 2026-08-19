# Software Requirements Specification (SRS) — v2.0 (Production Grade)
## ARF — Agent Red-teaming Framework
### A Metasploit-class Security Testing Framework for Autonomous AI Agents

**Version:** 2.0
**Supersedes:** v1.0
**Status:** Implementation-ready
**Classification:** Academic / Defensive Security Research Tooling

---

## Changelog from v1.0 (Why This Revision Exists)

A v1 SRS built from first principles is a good architecture document. It is not yet a *production* document, because it's missing the three things that separate a red-team tool from a red-team toy:

1. **It cited a placeholder taxonomy.** The real, ratified taxonomies now exist and must be pinned exactly, not paraphrased. This revision hardcodes them.
2. **It had no threat model for the framework itself.** A red-team tool that runs untrusted, adversarial payloads and can spin up rogue MCP servers is itself a high-value target and a liability if compromised or misused. v1 didn't treat ARF's own attack surface as in-scope.
3. **It had no execution-safety architecture.** "Run adversarial code against a target and capture side effects" requires sandboxing, egress control, and resource limits as first-class architecture, not an afterthought bullet point.

Everything below is written the way I'd review it before signing off on a pen-test tool going into a client engagement or a CTF submission.

---

## 1. Purpose & Threat Landscape (Grounded in Current Data)

### 1.1 Why This Matters Now

The agentic attack surface stopped being theoretical in 2025. Real, cited incidents include a zero-click data-exfiltration flaw in a production Copilot deployment (CVE-2025-32711 / "EchoLeak"), a compromised coding-assistant supply-chain incident affecting an install base in the hundreds of thousands, and an agent deleting a production database during a change freeze due to insufficient guardrails. On the protocol layer specifically, security researchers filed over 30 CVEs against MCP servers, clients, and infrastructure in a two-month window in early 2026, and independent research (Unit 42) measured a 78.3% attack success rate against a single AI agent once it was connected to five MCP servers simultaneously. This isn't a hypothetical capstone topic — it's the live threat model for anyone deploying agents in 2026.

### 1.2 Pinned Taxonomies (Version-Locked — Do Not Paraphrase These IDs)

ARF must map every probe to **both** of the following ratified OWASP lists. These are the actual, current (as of August 2026) IDs — use them verbatim in code, not approximations:

**OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)** — published 9 Dec 2025 by the OWASP GenAI Security Project:

| ID | Category |
|---|---|
| ASI01:2026 | Agent Goal Hijack |
| ASI02:2026 | Tool Misuse & Exploitation |
| ASI03:2026 | Agent Identity & Privilege Abuse |
| ASI04:2026 | Agentic Supply Chain Compromise |
| ASI05:2026 | Unexpected Code Execution |
| ASI06:2026 | Memory & Context Poisoning |
| ASI07:2026 | Insecure Inter-Agent Communication |
| ASI08:2026 | Cascading Agent Failures |
| ASI09:2026 | Human-Agent Trust Exploitation |
| ASI10:2026 | Rogue Agents |

**OWASP MCP Top 10 (MCP01:2025–MCP10:2025)** — OWASP's first project dedicated specifically to the MCP protocol layer, currently in Phase 3 beta, project-led by Vandana Verma Sehgal:

| ID | Category |
|---|---|
| MCP01:2025 | Token Mismanagement & Secret Exposure |
| MCP02:2025 | Privilege Escalation via Scope Creep |
| MCP03:2025 | Tool Poisoning |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering |
| MCP05:2025 | Command Injection & Execution |
| MCP06:2025 | Intent Flow Subversion |
| MCP07:2025 | Insufficient Authentication & Authorization |
| MCP08:2025 | Lack of Audit and Telemetry |
| MCP09:2025 | Shadow MCP Servers |
| MCP10:2025 | Context Injection & Over-Sharing |

**Implementation requirement:** `taxonomy/owasp_asi.py` and `taxonomy/owasp_mcp.py` load these from a version-pinned local YAML/JSON snapshot (checked into the repo with a `source_url` and `retrieved_date` field), **not** fetched live from OWASP at runtime. Both lists are living documents (Phase 3 beta for MCP means rankings may still shift) — pin a version, note it in your report, and add a `taxonomy/CHANGELOG.md` so re-runs stay reproducible even after upstream changes.

Retire the MITRE ATLAS-only mapping from v1 as the *primary* taxonomy — keep it as a **secondary** cross-reference (`taxonomy/mitre_atlas.py`) for the ML-supply-chain and model-level techniques that ASI/MCP don't cover (e.g., training-data poisoning), but ASI + MCP are now your primary citation surface for the agentic/MCP-specific work, since they're purpose-built and current.

### 1.3 Threat Model for ARF Itself (New in v2)

A tool that (a) executes adversarial payloads, (b) can stand up rogue MCP servers, and (c) stores captured secrets/canaries from target systems is, by definition, a high-value target. Treat this with the same rigor as the systems ARF tests:

| Asset | Threat | Control |
|---|---|---|
| SQLite run store (contains captured canaries, potentially real secrets if a probe misfires) | Local file read by another process/user | Encrypt at rest (Fernet/AES-GCM), file permissions `600`, never committed to VCS |
| Target credentials in `connection_config` | Credential theft from ARF's own config | Never plaintext; pull from OS keyring / environment / a secrets manager (see §8) |
| Rogue-MCP-server probe module | Someone repurposes ARF's own attack tooling against a real, unauthorized target | Default-deny network egress in the sandbox (see §4); explicit `--i-have-authorization` gate; usage-policy license terms |
| Probe/plugin supply chain | A malicious third-party probe plugin is installed and runs arbitrary code with ARF's privileges | Plugin signing (sigstore/cosign) + an allow-list of trusted plugin sources; treat this exactly like MCP04/ASI04 — you are your own supply chain risk |
| LLM-judge oracle calls | Sending a target's captured secrets to a third-party LLM API for judging | Redact/tokenize known-secret patterns before any external API call; make LLM-judge opt-in, not default |

---

## 2. Execution Safety Architecture (New — This Is What Makes It "Production")

This is the single biggest gap in a v1-style design: **where does the target agent actually run, and what can it touch?**

### 2.1 Sandboxing Requirements

- **Default execution mode: containerized, network-isolated.** Every fixture/target agent under test runs inside a rootless Docker container (or, for stronger isolation on shared infra, **gVisor** (`runsc`) or **Firecracker microVMs**) with:
  - No default network egress. Egress is allow-listed per-target (e.g., only to `localhost:<mcp_port>` and the LLM provider's API endpoint).
  - Read-only root filesystem; a single writable tmpfs scratch directory that is wiped after each session.
  - CPU/memory/PID limits (`cgroups v2`) to prevent a probe (accidentally or deliberately) triggering a resource-exhaustion condition that takes down the host (this is itself ASI08 — Cascading Agent Failures — so ARF must not become a victim of the category it's testing for).
- **Rogue-server probes run in their own isolated network namespace**, separate from the target's namespace, bridged only through the specific port(s) the probe needs to expose — you don't want your rogue MCP server accidentally reachable from anything but the target under test.
- **Secrets/canaries never touch the container's persistent layer** — inject via environment variables or tmpfs, scrub on teardown.

### 2.2 Updated Module: `sandbox/`

```
arf/
├── sandbox/
│   ├── runtime.py            # Container/microVM lifecycle (start, exec, teardown)
│   ├── network_policy.py     # Egress allow-list enforcement (nftables/iptables rules per run)
│   ├── resource_limits.py    # cgroup v2 limit application
│   └── backends/
│       ├── docker_backend.py
│       ├── gvisor_backend.py     # optional, stronger isolation
│       └── firecracker_backend.py # optional, for CI/high-assurance runs
```

### 2.3 Non-Functional Requirement Addition

| ID | Requirement |
|---|---|
| NFR-S1 | No probe execution shall occur outside an isolated sandbox by default; running against an unsandboxed local process requires an explicit `--unsafe-direct` flag with a printed warning |
| NFR-S2 | Sandbox egress shall default-deny; every allowed destination must be explicitly declared in the target config |
| NFR-S3 | All captured secrets/canaries shall be redacted in logs and reports by default (`****last4`), with a `--reveal-secrets` flag required to print them in full |
| NFR-S4 | Resource limits shall guarantee the framework itself cannot be driven into a DoS condition by a misbehaving or malicious target/probe |

---

## 3. Updated Agent-Framework Adapter Targets

The 2025 adapter list (LangGraph / CrewAI / AutoGen) is now stale — the ecosystem consolidated hard in the first half of 2026. **AutoGen is now maintenance-only**; it's still worth a legacy adapter for coverage, but it should not be a launch priority. The current production landscape is:

| Framework | Priority | Why |
|---|---|---|
| **MCP (raw protocol)** | P0 — Must | The protocol layer itself is where the novel MCP-attack-catalog work lives; framework-agnostic |
| **LangGraph** | P0 — Must | Now the enterprise-adoption leader; graph-based state machine with checkpointing gives you clean hook points for trace capture |
| **Claude Agent SDK** | P0 — Must | Directly relevant given your own toolchain/ecosystem; native MCP support means testing it doubles as testing MCP-client behavior |
| **OpenAI Agents SDK** | P1 — Should | Explicit "handoff" abstraction between agents — good target for ASI07 (Insecure Inter-Agent Communication) probes |
| **CrewAI** | P1 — Should | Still the fastest path to a role-based multi-agent fixture for your `multi_agent/` probe category |
| **Google ADK** | P2 — Could | Relevant mainly if you want to demonstrate cross-framework A2A protocol attacks |
| **AutoGen / AG2** | P2 — Legacy | Maintenance-only upstream; keep a thin adapter for backward-compat coverage, not as a flagship integration |

### 3.1 New Probe Category: Inter-Agent Protocol Attacks (A2A)

With multiple frameworks now supporting the **Agent2Agent (A2A) protocol** for cross-framework agent discovery and task handoff, add a probe category `probes/a2a_attacks/` mapped to **ASI07:2026 (Insecure Inter-Agent Communication)** and covering: forged agent-card advertisement, task-handoff hijacking, and trust-boundary confusion when one framework's agent invokes another's.

---

## 4. Revised Behavioral Oracle — Precision/Recall as a First-Class Requirement

v1 specified the oracle mechanism (rule DSL → structural match → LLM-judge fallback) correctly, but a production tool needs **measured, not assumed, detection quality.**

### 4.1 Oracle Validation Requirement (New)

- ARF ships with a **fixture suite of deliberately vulnerable AND deliberately hardened agents** (`tests/fixtures/vulnerable/`, `tests/fixtures/hardened/`).
- Every oracle rule must be validated against both fixture sets before being marked `stable` in its metadata. Track **true positive rate, false positive rate, and false negative rate per rule**, stored alongside the rule definition:

```yaml
rule_id: mcp_exfil_via_tool_description
# ... (match logic as in v1) ...
validation:
  last_validated: 2026-08-01
  tp_rate: 0.97
  fp_rate: 0.02
  fn_rate: 0.03
  fixture_coverage: ["vuln_agent_v3", "hardened_agent_v1"]
  status: stable   # draft | stable | deprecated
```

- Rules with `status: draft` are excluded from default suite runs (`arf run --suite full`) unless `--include-draft` is passed — this prevents unvalidated detection logic from silently producing findings you'd have to retract in a report.

### 4.2 Confidence-Weighted Verdicts

Change the oracle's output contract from a binary verdict to a structured one:

```python
@dataclass
class Verdict:
    result: Literal["SUCCESS", "PARTIAL", "FAILURE", "INCONCLUSIVE"]
    confidence: float          # 0.0-1.0, derived from rule validation stats + match strength
    evidence: TraceSegment
    rule_id: str
    taxonomy: TaxonomyMapping  # both ASI and MCP IDs where applicable
```

`INCONCLUSIVE` is a first-class state — a production tool must be honest when the trace doesn't cleanly resolve, rather than forcing a false SUCCESS/FAILURE binary (this also protects you from over-claiming findings in your report).

---

## 5. Observability — OpenTelemetry GenAI Semantic Conventions

Rather than inventing a bespoke trace schema, align `core/trace.py` with the **OpenTelemetry Semantic Conventions for Generative AI** (`gen_ai.*` attribute namespace), which has become the de facto standard for LLM/agent observability. This buys you:

- Interoperability — ARF traces can be exported to Jaeger/Tempo/Honeycomb/Langfuse for visual debugging without writing a custom viewer.
- Legitimacy — your report can say "traces conform to OTel GenAI semantic conventions" instead of "traces conform to a schema I invented," which matters if this framework is ever evaluated by industry reviewers.

```
arf/
├── observability/
│   ├── otel_exporter.py       # Maps internal Trace -> OTel spans (gen_ai.* attributes)
│   ├── span_attributes.py     # gen_ai.agent.name, gen_ai.tool.name, gen_ai.tool.call.arguments, etc.
│   └── collectors/
│       └── otlp_collector.py  # Local OTLP collector config for dev (docker-compose)
```

Add `opentelemetry-sdk`, `opentelemetry-exporter-otlp` to the dependency list (§8).

---

## 6. Authentication & Authorization Testing — OAuth 2.1 Awareness

Current MCP deployments increasingly use **OAuth 2.1** for server/client authentication (this directly maps to MCP07:2025 — Insufficient Authentication & Authorization, and is one of the "week 1" fixes security teams are told to prioritize). ARF's `mcp_adapter.py` and the `mcp_attacks/` probe category must therefore explicitly cover:

| Probe | Target Weakness |
|---|---|
| `token_scope_creep.py` | MCP02 — requests token with broad scope, checks if server issues it without pushback |
| `stale_token_replay.py` | MCP01/MCP07 — replays a token past intended lifetime, checks for revocation enforcement |
| `oauth_downgrade.py` | MCP07 — attempts to negotiate a weaker auth flow than the server advertises |
| `unauthenticated_tool_discovery.py` | MCP07/MCP09 — checks whether tool listing is exposed pre-auth (info leak enabling shadow-server reconnaissance) |

Add `authlib` or `oauthlib` to the stack for constructing these probe requests correctly rather than hand-rolling OAuth flows.

---

## 7. Supply-Chain Hardening for ARF's Own Plugin Ecosystem

Since MCP04/ASI04 is "supply chain compromise," and ARF is explicitly a plugin-loading framework, it must not be hypocritical about its own supply chain:

- **Plugin signing**: probes/adapters/oracle-rule-packs distributed outside the core repo should be signable via **Sigstore/cosign**; `plugin_loader.py` verifies signatures against a configured trust root before loading anything not in the core tree.
- **SBOM generation**: `hatch build` pipeline generates a Software Bill of Materials (via `syft` or `cyclonedx-py`) as a release artifact — trivial to add, and it's exactly the kind of detail that separates a student project from a "this person understands production AppSec" project.
- **Dependency pinning + audit**: `pip-audit` or `uv pip audit` runs in CI on every PR; lockfile (`uv.lock` or `poetry.lock`) committed, not just `pyproject.toml` ranges.
- **Reproducible builds**: pin exact tool versions in CI; document the build environment.

---

## 8. Updated Technology Stack (Production Additions Marked ⭐ NEW)

| Purpose | Technology | Notes |
|---|---|---|
| Core language/runtime | Python 3.11+, asyncio | unchanged from v1 |
| CLI | Typer | unchanged |
| Interactive console | Textual / prompt_toolkit | unchanged, still stretch |
| Config/validation | Pydantic v2 | unchanged |
| Plugin discovery | pluggy | unchanged |
| ORM/persistence | SQLAlchemy 2.0 + SQLite (+ Alembic) | unchanged for v1 scope; note a Postgres swap path for a multi-user deployment |
| MCP integration | MCP Python SDK | unchanged |
| Agent adapters | `langgraph`, `claude-agent-sdk`, `openai-agents`, `crewai`, `google-adk` (optional extras) | ⭐ updated list, see §3 |
| Auth testing | `authlib` | ⭐ NEW — OAuth 2.1 flow construction for MCP07 probes |
| Sandboxing | `docker` (Python SDK) as baseline; `gvisor`/`runsc` or Firecracker for stronger isolation | ⭐ NEW — see §2 |
| Network policy | `nftables`/`iptables` rule generation (via subprocess or `python-iptables`) | ⭐ NEW — egress allow-listing |
| Observability | `opentelemetry-sdk`, `opentelemetry-exporter-otlp` | ⭐ NEW — see §5 |
| Secrets management | OS keyring (`keyring` package) for local/dev; pluggable backend for **HashiCorp Vault** or **age/sops**-encrypted files for team use | ⭐ NEW |
| Supply-chain security | `sigstore`/`cosign` (signing), `syft` or `cyclonedx-py` (SBOM), `pip-audit` | ⭐ NEW — see §7 |
| HTTP client | httpx | unchanged |
| LLM-judge | Anthropic Python SDK | unchanged, now explicitly opt-in (§1.3) |
| Templating/reporting | Jinja2 | unchanged |
| Logging | structlog (JSON) | unchanged |
| Testing | pytest, pytest-asyncio, hypothesis | unchanged; ⭐ add fixture-based oracle validation harness (§4.1) |
| Static analysis | ruff, mypy | unchanged |
| Packaging | hatch | unchanged |
| Containerization | Docker + docker-compose; ⭐ optional Kubernetes/Helm chart for a multi-target lab deployment | |
| CI | GitHub Actions | ⭐ add `pip-audit`, SBOM generation, and oracle-fixture-validation as required checks, not just lint/test |

---

## 9. Deployment Topologies

### 9.1 Single-Operator (default — matches your home-lab setup)

CLI-driven, SQLite store, Docker Desktop/Podman for sandboxing, runs on a single Linux box (e.g., your Arch Linux dev environment). This is the default and what Phases 1–4 should target.

### 9.2 Team/Lab Deployment (documented as a future-work path, not required for v1 submission)

- SQLite → Postgres swap (SQLAlchemy makes this a config change, not a rewrite).
- Secrets backend → Vault instead of OS keyring.
- Sandbox backend → Kubernetes Jobs with network policies instead of local Docker.
- Shared run store behind a lightweight FastAPI read API for the HTML dashboard, so multiple testers can view the same run history.

Document this as an explicit "Phase 10 — future work" rather than building it now; a college submission is judged on depth of the core novel contribution (MCP attack catalog + behavioral oracle), not on horizontal scaling you won't get to demo.

---

## 10. Revised Functional Requirements (Delta from v1)

| ID | Requirement | Priority |
|---|---|---|
| FR-17 | All probe execution shall occur inside a sandbox meeting NFR-S1–S4 by default | Must |
| FR-18 | Every finding shall carry both an ASI ID and (where applicable) an MCP ID, sourced from the pinned taxonomy snapshot in §1.2 | Must |
| FR-19 | Oracle rules shall carry validation metadata (tp/fp/fn rate) and be excluded from default runs until `status: stable` | Must |
| FR-20 | The system shall support OAuth 2.1-aware MCP authentication probes (§6) | Should |
| FR-21 | Traces shall be exportable in OpenTelemetry GenAI semantic-convention format | Should |
| FR-22 | Third-party plugins shall be signature-verified before loading unless explicitly run with `--trust-unsigned` | Must |
| FR-23 | The system shall generate an SBOM as part of its release build | Should |

(FR-1 through FR-16 from v1 remain valid and are not restated here.)

---

## 11. Revised Roadmap (Red-Team-Prioritized)

A 50-year-in-the-field red teamer's honest prioritization: **detection credibility and safety architecture come before feature breadth.** A tool with three rock-solid, sandboxed, validated probes beats a tool with thirty probes and no sandbox and no measured false-positive rate — the former is defensible in a report; the latter gets torn apart in five minutes of questions.

| Phase | Deliverable |
|---|---|
| 0 (NEW) | Sandbox + network-policy foundation (§2) — nothing executes without this |
| 1 | Core engine skeleton: `Trace`/`Turn`/`ToolCall` (OTel-aligned), plugin loader, MCP adapter, one probe, structural oracle |
| 2 | Oracle Rule DSL + canary-token injection + **fixture-based validation harness** (§4.1) — no rule ships as `stable` without measured tp/fp/fn |
| 3 | Storage layer + CLI + secrets backend (keyring, minimum) |
| 4 | MCP attack probe catalog mapped to MCP01–MCP10:2025 — your primary novel-contribution chapter |
| 5 | LangGraph + Claude Agent SDK adapters |
| 6 | Reporting (HTML/JSON/MD) with ASI + MCP dual taxonomy mapping and coverage matrix |
| 7 | Supply-chain hardening: plugin signing, SBOM, `pip-audit` in CI |
| 8 | OpenAI Agents SDK / CrewAI adapters + A2A probe category |
| 9 | LLM-judge fallback oracle (opt-in, with secret-redaction pre-filter) |
| 10 | Stretch: interactive REPL console, team/lab deployment topology |

Phases 0–4 are your defensible core-submission target (this replaces v1's "Phases 1–4" — sandboxing now has to come first, not last).

---

## 12. Reporting — Dual-Taxonomy Coverage Matrix (Updated)

The report's coverage matrix must show, per run, how many ASI categories and how many MCP categories were exercised, with pass/fail/inconclusive counts per category — this dual view (agentic-behavior lens + protocol lens) is what makes the report read as current rather than dated, since it mirrors exactly how the industry is now structuring this problem (an agentic-level list plus a protocol-specific list, cross-referenced).

---

## 13. Open Items Still Requiring Your Judgment Call

1. **Isolation backend choice** (Docker vs. gVisor vs. Firecracker): Docker rootless is enough for a college-scale submission; gVisor is worth mentioning in your report as "the production-grade path" even if you don't fully implement it, since Firecracker/gVisor setup is a meaningful time sink on a Pi4/Pentium home lab.
2. **MCP Top 10 is still Phase-3 beta** — note the exact retrieval date you pinned it at, so your report is defensible if OWASP reshuffles rankings before you submit.
3. **Whether to build the Vault-backed secrets path or stop at OS keyring** — keyring is sufficient and honest for a single-operator tool; don't over-engineer for a "team deployment" you're not actually running.
4. **A2A probe depth** — this is genuinely cutting-edge (protocol adoption is still ramping in 2026); scope it as a stretch goal, not a core deliverable, so it doesn't block your MCP-catalog work.

---

*End of SRS v2.0. This revision should be read alongside v1.0 §2–§4, §9–§10, and §14 (module breakdown, oracle DSL syntax, adapter interface contract, and the comparison-to-existing-tools table), which remain unchanged and still apply.*
