"""PhishNet 100-Message Benchmark Evaluation Test.

Evaluates PhishNet against a balanced dataset of 100 realistic Indian messages
(50 confirmed scams, 50 confirmed genuine messages).
Computes and asserts Accuracy, Precision, Recall, and F1 Score.
"""

from __future__ import annotations

import json
from pathlib import Path

from phishnet.engine import analyse, load_rules, normalise
from phishnet.links import analyse_links

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_benchmark() -> list[dict]:
    """Load benchmark dataset."""
    benchmark_path = DATA_DIR / "benchmark_dataset.json"
    with open(benchmark_path, encoding="utf-8") as fh:
        return json.load(fh)


def test_benchmark_metrics():
    """Run full benchmark evaluation and assert quality thresholds."""
    load_rules(force=True)
    dataset = load_benchmark()
    assert len(dataset) == 100, f"Expected 100 messages, found {len(dataset)}"

    tp = 0  # Scam correctly flagged as Medium or High
    fp = 0  # Genuine message falsely flagged as Medium or High
    tn = 0  # Genuine message correctly kept in Low tier
    fn = 0  # Scam missed (placed in Low tier)

    scam_scores = []
    genuine_scores = []

    for item in dataset:
        text = item["text"]
        truth = item["ground_truth"]

        norm = normalise(text)
        link_findings = analyse_links(norm)
        result = analyse(text, link_findings=link_findings, mode="default")

        is_flagged = result.tier in ("medium", "high")

        if truth == "scam":
            scam_scores.append(result.score)
            if is_flagged:
                tp += 1
            else:
                fn += 1
        else:
            genuine_scores.append(result.score)
            if not is_flagged:
                tn += 1
            else:
                fp += 1

    total = len(dataset)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 60)
    print("PHISHNET 100-MESSAGE BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Total Evaluated : {total} (50 Scams, 50 Genuine)")
    print(f"True Positives  : {tp}")
    print(f"False Positives : {fp}")
    print(f"True Negatives  : {tn}")
    print(f"False Negatives : {fn}")
    print(f"Accuracy        : {accuracy * 100:.2f}%")
    print(f"Precision       : {precision * 100:.2f}%")
    print(f"Recall          : {recall * 100:.2f}%")
    print(f"F1-Score        : {f1 * 100:.2f}%")
    print("=" * 60)

    # Assert robust quality standards
    assert accuracy >= 0.90, f"Accuracy too low: {accuracy:.2f}"
    assert precision >= 0.90, f"Precision too low: {precision:.2f}"
    assert recall >= 0.90, f"Recall too low: {recall:.2f}"
    assert f1 >= 0.90, f"F1-score too low: {f1:.2f}"
