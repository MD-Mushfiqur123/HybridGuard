"""Compare two or more experiment summaries side by side.

Prints a P/R/F1/tokens/time table and, when two runs are given, the delta of
the second run over the first. Used for the controlled single-pass vs
multi-pass category-bundle comparison.

Usage:
  python scripts/compare_runs.py results/a_summary.json results/b_summary.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: str) -> dict:
    data = json.loads(Path(path).read_text())
    return {"name": data.get("experiment", Path(path).stem), **data["metrics"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("summaries", nargs="+")
    args = ap.parse_args()

    runs = [load(p) for p in args.summaries]
    header = f"{'run':28s} {'P':>6s} {'R':>6s} {'F1':>6s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'tokens':>8s} {'time_s':>8s}"
    print(header)
    print("-" * len(header))
    for r in runs:
        print(
            f"{r['name']:28s} {r['precision']:6.3f} {r['recall']:6.3f} {r['f1']:6.3f}"
            f" {r['tp']:4d} {r['fp']:4d} {r['fn']:4d} {r.get('tokens', 0):8d} {r.get('time_s', 0):8.1f}"
        )
    if len(runs) == 2:
        a, b = runs
        print(
            f"\ndelta ({b['name']} - {a['name']}): "
            f"dP={b['precision'] - a['precision']:+.3f} "
            f"dR={b['recall'] - a['recall']:+.3f} "
            f"dF1={b['f1'] - a['f1']:+.3f} "
            f"dtokens={b.get('tokens', 0) - a.get('tokens', 0):+d}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
