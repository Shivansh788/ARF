from __future__ import annotations

import asyncio
import json
import typer
from rich.console import Console

from arf.adapters import DemoSafeAdapter, DemoVulnerableAdapter
from arf.engine import Engine
from arf.oracle import load_rule
from arf.probes import get_probe, list_probes
from arf.sandbox import SandboxPolicy
from arf.taxonomy import redact
from arf.storage import RunStore

app = typer.Typer(help="ARF: authorized behavioral security testing for AI agents.")
console = Console()


@app.command()
def probes() -> None:
    for probe in list_probes():
        console.print(f"[bold]{probe.id}[/bold] - {probe.description}")


@app.command()
def demo(safe: bool = typer.Option(False, help="Use the safe demo agent."), unsafe_direct: bool = typer.Option(False, "--unsafe-direct", help="Acknowledge the local demo runs outside a container."), db: str = "arf.db") -> None:
    if not unsafe_direct:
        raise typer.BadParameter("Demo execution is blocked by default; pass --unsafe-direct for the local fixture.")
    probe_type = get_probe("exfiltration.canary")
    adapter = DemoSafeAdapter() if safe else DemoVulnerableAdapter()
    rule = load_rule("oracle_rules/demo.yaml")
    result_object = asyncio.run(Engine(RunStore(db), SandboxPolicy(unsafe_direct=True, warnings=["CLI --unsafe-direct"])).run(probe_type.id, adapter, rule))
    verdict = result_object.verdict
    result = {"run_id": result_object.run_id, "probe_id": probe_type.id, **verdict.to_dict(), "trace": redact(result_object.trace.to_dict(), rule.match.arguments_contains_any)}
    console.print_json(json.dumps(result))
    if verdict.result == "SUCCESS":
        raise typer.Exit(code=1)


@app.command("list-runs")
def list_runs(db: str = "arf.db") -> None:
    console.print_json(json.dumps(RunStore(db).list()))


if __name__ == "__main__":
    app()
