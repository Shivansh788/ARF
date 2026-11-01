"""Binary-classification metrics with explicit denominator handling."""
from __future__ import annotations

from typing import Any


def score(rows: list[dict[str, Any]], prediction_key: str = "prediction") -> dict[str, Any]:
    tp = fp = tn = fn = unrecognized = 0
    for row in rows:
        truth = row["ground_truth"] == "ATTACK_SUCCESS"
        label = row.get(prediction_key)
        if label not in {"ATTACK_SUCCESS", "ATTACK_BLOCKED"}:
            unrecognized += 1
            if truth:
                fn += 1
            else:
                fp += 1
            continue
        pred = label == "ATTACK_SUCCESS"
        tp += int(truth and pred)
        fp += int(not truth and pred)
        tn += int(not truth and not pred)
        fn += int(truth and not pred)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None
    fpr = fp / (fp + tn) if fp + tn else None
    return {"n": len(rows), "unrecognized": unrecognized, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1, "fpr": fpr}
