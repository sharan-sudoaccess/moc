"""Evaluation of the detector against a labeled corpus.

Binary convention
-----------------
    label 1 (positive): the text contains a prompt-injection attempt
    label 0 (negative): the text is benign (including text that merely
                        MENTIONS an attack phrase, e.g. in a quotation)

    prediction positive  <=>  decision is FLAG or BLOCK   (positive_on="flag", default)
                         <=>  decision is BLOCK           (positive_on="block")
                         <=>  at least one rule matched   (positive_on="match")

    Precision = TP / (TP + FP)      Recall = TP / (TP + FN)
    F1        = 2PR / (P + R)       Accuracy = (TP + TN) / N
A zero denominator yields 0.0 (and is reported as such), never an exception.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

POSITIVE_MODES = ("flag", "block", "match")
SPLITS = ("dev", "heldout", "all")


class CorpusError(ValueError):
    pass


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def load_corpus(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CorpusError(f"corpus not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise CorpusError(f"corpus is not valid JSON: {exc.msg}") from None
    examples = data.get("examples") if isinstance(data, dict) else None
    if not isinstance(examples, list) or not examples:
        raise CorpusError("corpus must be an object with a non-empty 'examples' list")
    seen: set[str] = set()
    for ex in examples:
        for key in ("id", "text", "label", "split"):
            if key not in ex:
                raise CorpusError(f"example {ex.get('id', '?')} is missing '{key}'")
        if ex["label"] not in (0, 1):
            raise CorpusError(f"example {ex['id']}: label must be 0 or 1")
        if ex["split"] not in ("dev", "heldout"):
            raise CorpusError(f"example {ex['id']}: split must be 'dev' or 'heldout'")
        if ex["id"] in seen:
            raise CorpusError(f"duplicate example id {ex['id']}")
        seen.add(ex["id"])
    return examples


def confusion(labels: Iterable[int], predictions: Iterable[int]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for y, p in zip(labels, predictions):
        if y == 1 and p == 1:
            tp += 1
        elif y == 0 and p == 1:
            fp += 1
        elif y == 0 and p == 0:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics_from_confusion(c: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(safe_div(2 * precision * recall, precision + recall), 4),
        "accuracy": round(safe_div(tp + tn, tp + fp + tn + fn), 4),
        "false_positive_rate": round(safe_div(fp, fp + tn), 4),
    }


def is_positive(result: dict[str, Any], positive_on: str) -> int:
    if positive_on == "flag":
        return int(result["action"] in ("FLAG", "BLOCK"))
    if positive_on == "block":
        return int(result["action"] == "BLOCK")
    if positive_on == "match":
        return int(result["detected"])
    raise ValueError(f"positive_on must be one of {POSITIVE_MODES}")


def evaluate(
    service: Any,
    examples: list[dict[str, Any]],
    *,
    split: str = "all",
    policy: str | None = None,
    positive_on: str = "flag",
) -> dict[str, Any]:
    """Run every example through ``service.analyze`` (no audit/metrics side effects)."""
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}")
    if positive_on not in POSITIVE_MODES:
        raise ValueError(f"positive_on must be one of {POSITIVE_MODES}")
    selected = [ex for ex in examples if split == "all" or ex["split"] == split]
    if not selected:
        raise CorpusError(f"no examples in split '{split}'")

    rows = []
    by_tag: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for ex in selected:
        result = service.analyze(ex["text"], policy=policy, record=False)
        pred = is_positive(result, positive_on)
        outcome = (
            "TP" if ex["label"] == 1 and pred == 1
            else "FP" if pred == 1
            else "TN" if ex["label"] == 0
            else "FN"
        )
        rows.append(
            {
                "id": ex["id"],
                "split": ex["split"],
                "text": ex["text"],
                "label": ex["label"],
                "prediction": pred,
                "outcome": outcome,
                "action": result["action"],
                "risk_score": result["risk_score"],
                "rule_ids": result["rule_ids"],
                "tags": ex.get("tags", []),
                "note": ex.get("note", ""),
            }
        )
        for tag in ex.get("tags", []):
            by_tag[tag].append((ex["label"], pred))

    c = confusion([r["label"] for r in rows], [r["prediction"] for r in rows])
    tag_report = {}
    for tag, pairs in sorted(by_tag.items()):
        tc = confusion([p[0] for p in pairs], [p[1] for p in pairs])
        tag_report[tag] = {
            "n": len(pairs),
            "correct": tc["tp"] + tc["tn"],
            "accuracy": round(safe_div(tc["tp"] + tc["tn"], len(pairs)), 4),
            **tc,
        }

    return {
        "split": split,
        "policy": policy or service.default_policy,
        "positive_on": positive_on,
        "dataset_size": len(rows),
        "positives": sum(r["label"] for r in rows),
        "negatives": sum(1 - r["label"] for r in rows),
        "confusion": c,
        "metrics": metrics_from_confusion(c),
        "by_tag": tag_report,
        "false_positives": [r for r in rows if r["outcome"] == "FP"],
        "false_negatives": [r for r in rows if r["outcome"] == "FN"],
        "rows": rows,
        "disclaimer": (
            "Illustrative only: a small, hand-written corpus authored together with the rules. "
            "These numbers do not measure real-world effectiveness."
        ),
    }
