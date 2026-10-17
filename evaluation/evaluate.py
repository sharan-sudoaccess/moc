#!/usr/bin/env python3
"""Evaluate the DFA detector on the labeled corpus.

Usage (from the project root):

    python evaluation/evaluate.py                       # all examples, balanced policy
    python evaluation/evaluate.py --split heldout
    python evaluation/evaluate.py --policy strict --positive-on block
    python evaluation/evaluate.py --json evaluation/results.json

The detector runs in-process through DetectionService (the same code the API
uses). Nothing is written to the audit log or metrics during evaluation.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import Settings  # noqa: E402
from src.evaluation import POSITIVE_MODES, SPLITS, evaluate, load_corpus  # noqa: E402
from src.service import DetectionService  # noqa: E402


def _print_report(report: dict, show_rows: bool) -> None:
    c, m = report["confusion"], report["metrics"]
    print("=" * 72)
    print("AI Prompt Injection Detector (DFA) - evaluation")
    print("=" * 72)
    print(f"split={report['split']}  policy={report['policy']}  positive_on={report['positive_on']}")
    print(f"examples={report['dataset_size']}  positives={report['positives']}  negatives={report['negatives']}")
    print()
    print("Confusion matrix (rows = actual, columns = predicted)")
    print("                      pred +    pred -")
    print(f"  actual + (attack)   TP={c['tp']:<5}  FN={c['fn']:<5}")
    print(f"  actual - (benign)   FP={c['fp']:<5}  TN={c['tn']:<5}")
    print()
    print(f"  Precision = TP/(TP+FP) = {m['precision']:.4f}")
    print(f"  Recall    = TP/(TP+FN) = {m['recall']:.4f}")
    print(f"  F1        = 2PR/(P+R)  = {m['f1']:.4f}")
    print(f"  Accuracy  = (TP+TN)/N  = {m['accuracy']:.4f}")
    print(f"  FPR       = FP/(FP+TN) = {m['false_positive_rate']:.4f}")
    print()
    print("Per-tag accuracy")
    for tag, t in report["by_tag"].items():
        print(f"  {tag:<18} n={t['n']:<3} correct={t['correct']:<3} acc={t['accuracy']:.2f}")
    for title, key in (("False positives", "false_positives"), ("False negatives", "false_negatives")):
        print()
        print(f"{title} ({len(report[key])})")
        for r in report[key]:
            rules = ",".join(r["rule_ids"]) or "-"
            print(f"  {r['id']:<5} {r['action']:<5} rules={rules:<16} {r['text'][:70]!r}")
    if show_rows:
        print()
        print("All rows")
        for r in report["rows"]:
            print(f"  {r['id']:<5} y={r['label']} p={r['prediction']} {r['outcome']} {r['action']:<5} "
                  f"score={r['risk_score']:<5} {','.join(r['rule_ids']) or '-'}")
    print()
    print("NOTE: " + report["disclaimer"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=PROJECT_ROOT / "evaluation" / "corpus.json")
    parser.add_argument("--split", choices=SPLITS, default="all")
    parser.add_argument("--policy", default=None, help="policy name (default: configured default)")
    parser.add_argument("--positive-on", choices=POSITIVE_MODES, default="flag")
    parser.add_argument("--json", type=Path, help="also write the full report to this JSON file")
    parser.add_argument("--rows", action="store_true", help="print every example's outcome")
    args = parser.parse_args(argv)

    # Evaluation must not write to the real audit log: point it at a temp dir.
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings.from_env()
        settings = Settings(**{**settings.__dict__, "audit_log_path": Path(tmp) / "audit.jsonl"})
        service = DetectionService(settings)
        report = evaluate(service, load_corpus(args.corpus), split=args.split,
                          policy=args.policy, positive_on=args.positive_on)
        service.audit.close()

    _print_report(report, args.rows)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Full report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
