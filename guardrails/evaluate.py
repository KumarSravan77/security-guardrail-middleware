from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import scan


def evaluate(path: Path) -> dict[str, float | int]:
    cases = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    correct_blocks = 0
    correct_categories = 0
    for case in cases:
        result = scan(case["text"])
        actual_categories = {finding.category for finding in result.findings}
        correct_blocks += result.blocked == case["expected_blocked"]
        correct_categories += set(case["expected_categories"]).issubset(actual_categories)
    total = len(cases)
    return {
        "cases": total,
        "block_accuracy": correct_blocks / total if total else 0.0,
        "category_recall": correct_categories / total if total else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the versioned adversarial guardrail evaluation")
    parser.add_argument("--cases", type=Path, default=Path("evals/cases.jsonl"))
    parser.add_argument("--minimum-score", type=float, default=1.0)
    args = parser.parse_args()
    report = evaluate(args.cases)
    print(json.dumps(report, sort_keys=True))
    if min(report["block_accuracy"], report["category_recall"]) < args.minimum_score:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
