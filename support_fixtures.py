"""Synthetic evidence for tests and the demo. NOT a real red-team run.

Real evidence comes from `python redteam.py` followed by `python evidence.py record redteam`.
"""
from pathlib import Path

import evidence

LAYERS = {"Input injection": 5, "PII redaction": 4, "Tool-output scan": 2, "Tool policy": 6, "Output guard": 4}


def write_redteam_fixture(base):
    rows = ["<!-- SYNTHETIC FIXTURE for tests and the demo; not a real red-team run -->",
            "| # | Layer | Type | Test | Result |", "|---|---|---|---|---|"]
    n = 0
    for layer, attacks in LAYERS.items():
        for k in range(attacks):
            n += 1
            result = "MISSED" if (layer == "Input injection" and k == 0) else "CAUGHT"   # one deliberate known gap
            rows.append(f"| {n} | {layer} | attack | fixture attack {n} | {result} |")
        n += 1
        rows.append(f"| {n} | {layer} | benign | fixture benign {n} | OK |")
    path = Path(base) / "evidence" / "redteam_results.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def record_fixture_evidence(base, now=None):
    write_redteam_fixture(base)
    return evidence.record(base, "redteam", now=now)
