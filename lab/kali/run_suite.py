#!/usr/bin/env python3
"""Run the fixed ARF category matrix against the target at 192.168.56.10."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from arf_common import execute, guard_target, write_json
from metrics import score
from structural_oracle import classify, expected_label

CASES = [
    ("MCP01", "default"),
    ("MCP02", "read_scope"),
    ("MCP02", "write_control"),
    ("MCP07", "missing"),
    ("MCP07", "invalid"),
    ("MCP07", "expired"),
    ("MCP07", "wrong_audience"),
    ("MCP07", "valid"),
    ("MCP09", "default"),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="reports")
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 20:
        raise SystemExit("--repetitions must be between 1 and 20")
    guard_target()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path(args.output) / f"run_{stamp}"
    outdir.mkdir(parents=True, exist_ok=False)
    samples = []
    run_profile = None
    for repetition in range(args.repetitions):
        for category, variant in CASES:
            result = execute(category, variant)
            if result.get("category") != category or result.get("variant") != variant:
                raise SystemExit(
                    f"Target response identity mismatch for {category}/{variant}: "
                    f"got {result.get('category')}/{result.get('variant')}"
                )
            if result.get("profile") not in {"vulnerable", "hardened"}:
                raise SystemExit(f"Target returned unknown profile: {result.get('profile')!r}")
            if run_profile is None:
                run_profile = result["profile"]
            elif result["profile"] != run_profile:
                raise SystemExit("Target profile changed during the run; discard this partial run")
            prediction, rationale = classify(result)
            expected = expected_label(result)
            if prediction == "INCONCLUSIVE":
                raise SystemExit(
                    f"Fixture produced inconclusive evidence for {category}/{variant}: {rationale}. "
                    "Check the target logs and fixture health; this run was not scored."
                )
            if prediction != expected:
                raise SystemExit(
                    f"Fixture behavior disagrees with expected {expected} for "
                    f"{category}/{variant}: observed {prediction} ({rationale})."
                )
            row = {**result, "variant": variant, "prediction": prediction,
                   "rationale": rationale, "ground_truth": expected,
                   "repetition": repetition + 1}
            samples.append(row)
            print(f"{result['profile']:10} {category:5} {variant:14} -> {prediction:16} expected={row['ground_truth']}")

    attack_samples = [row for row in samples if row["ground_truth"] != "CONTROL_ALLOWED"]
    summary = {
        "created_utc": stamp,
        "target": "192.168.56.10",
        "profile": run_profile,
        "scope": "fixed local fixture scenarios only",
        "structural_oracle": score(attack_samples),
        "samples": len(samples),
    }
    write_json(str(outdir / "results.json"), {"summary": summary, "samples": samples})
    print(json.dumps(summary, indent=2))
    print(f"Evidence written to {outdir / 'results.json'}")


if __name__ == "__main__":
    main()
