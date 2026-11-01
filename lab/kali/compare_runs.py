#!/usr/bin/env python3
"""Pair vulnerable/hardened runs and calculate paper-level detector metrics."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from arf_common import write_json
from metrics import score
from run_suite import CASES


def load_result(path: str, expected_profile: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    samples = data.get("samples")
    if not isinstance(samples, list) or not samples:
        raise SystemExit(f"No samples found in {path}")
    if not all(isinstance(row, dict) for row in samples):
        raise SystemExit(f"Invalid sample row in {path}")
    profiles = {row.get("profile") for row in samples}
    if profiles != {expected_profile}:
        raise SystemExit(f"Expected only {expected_profile!r} samples in {path}; got {profiles}")
    summary = data.get("summary")
    if not isinstance(summary, dict) or summary.get("profile") != expected_profile:
        raise SystemExit(f"Summary profile does not match {expected_profile!r} in {path}")
    identities = []
    repetitions = set()
    for row in samples:
        identity = (row.get("category"), row.get("variant"), row.get("repetition"))
        if identity[0:2] not in CASES or not isinstance(identity[2], int) or identity[2] < 1:
            raise SystemExit(f"Unexpected case identity {identity!r} in {path}")
        try:
            expected = expected_label(row)
        except (KeyError, ValueError) as exc:
            raise SystemExit(f"Invalid ground-truth identity in {path}: {exc}") from exc
        if row.get("ground_truth") != expected:
            raise SystemExit(f"Ground truth does not match profile for {identity!r} in {path}")
        identities.append(identity)
        repetitions.add(identity[2])
    if len(set(identities)) != len(identities):
        raise SystemExit(f"Duplicate case/repetition identities in {path}")
    if not 1 <= max(repetitions) <= 20:
        raise SystemExit(f"Repetition count must be between 1 and 20 in {path}")
    expected_identities = {
        (category, variant, repetition)
        for repetition in range(1, max(repetitions) + 1)
        for category, variant in CASES
    }
    if set(identities) != expected_identities:
        raise SystemExit(f"Run in {path} is missing cases or repetitions")
    if summary.get("samples") != len(samples):
        raise SystemExit(f"Summary sample count does not match rows in {path}")
    return data


def case_counts(samples: list[dict[str, Any]]) -> Counter:
    return Counter((row.get("category"), row.get("variant"), row.get("repetition"),
                    row.get("ground_truth")) for row in samples)


def grouped_metrics(samples: list[dict[str, Any]], prediction_key: str) -> dict[str, Any]:
    attacks = [row for row in samples if row.get("ground_truth") != "CONTROL_ALLOWED"]
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in attacks:
        by_category[row["category"]].append(row)
    return {"overall": score(attacks, prediction_key),
            "by_category": {category: score(rows, prediction_key)
                            for category, rows in sorted(by_category.items())}}


def validate_judge_file(path: str, expected_profile: str,
                        source_samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    samples = data.get("samples")
    if not isinstance(samples, list) or not samples:
        raise SystemExit(f"No judge samples found in {path}")
    if {row.get("profile") for row in samples} != {expected_profile}:
        raise SystemExit(f"Expected only {expected_profile!r} judge samples in {path}")
    def identity(row: dict[str, Any]) -> tuple[Any, ...]:
        return (row.get("category"), row.get("variant"), row.get("repetition"),
                row.get("ground_truth"))
    if Counter(identity(row) for row in samples) != Counter(identity(row) for row in source_samples):
        raise SystemExit(f"Judge samples in {path} do not match their source run")
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vulnerable", help="vulnerable run_suite results.json")
    parser.add_argument("hardened", help="hardened run_suite results.json")
    parser.add_argument("--judge-vulnerable", help="matching vulnerable *_llm_judge.json")
    parser.add_argument("--judge-hardened", help="matching hardened *_llm_judge.json")
    parser.add_argument("--output", default="comparisons")
    args = parser.parse_args()
    vulnerable = load_result(args.vulnerable, "vulnerable")
    hardened = load_result(args.hardened, "hardened")
    if case_counts(vulnerable["samples"]) != case_counts(hardened["samples"]):
        raise SystemExit("Vulnerable and hardened runs do not contain the same complete case set")

    samples = vulnerable["samples"] + hardened["samples"]
    result: dict[str, Any] = {
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sources": {"vulnerable": str(Path(args.vulnerable)), "hardened": str(Path(args.hardened))},
        "case_count_per_profile": sum(case_counts(vulnerable["samples"]).values()),
        "structural_oracle": grouped_metrics(samples, "prediction"),
    }
    if bool(args.judge_vulnerable) != bool(args.judge_hardened):
        raise SystemExit("Supply both judge files or neither")
    if args.judge_vulnerable:
        judge_samples = validate_judge_file(args.judge_vulnerable, "vulnerable", vulnerable["samples"])
        judge_samples += validate_judge_file(args.judge_hardened, "hardened", hardened["samples"])
        result["llm_judge"] = grouped_metrics(judge_samples, "llm_prediction")

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    output = outdir / f"comparison_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    write_json(str(output), result)
    print(json.dumps(result, indent=2))
    print(f"Comparison written to {output}")


if __name__ == "__main__":
    main()
