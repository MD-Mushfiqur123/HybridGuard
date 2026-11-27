"""Analyze the DeFiHackLabs Slither sweep against the label corpus.

Reads the per-incident sweep JSONL (one record per incident: status + fired
Slither checks) and results/defihack_labels.json, then reports:

- compile/timeout coverage over the corpus
- per-label detection: of the incidents explicitly labeled with a class, how
  many have at least one mapped Slither detector fire
- overall: share of labeled incidents where Slither fires any check

Slither-to-label mapping is deliberately conservative: a detector only maps to
a label when it genuinely targets that bug class, so the detection numbers are
upper bounds on what pattern tools can do.

Usage:
  python scripts/analyze_defihack_sweep.py \
      --sweep .hybridguard/results/defihack_slither_sweep.jsonl \
      --labels results/defihack_labels.json \
      --out results/defihack_sweep_analysis.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

CHECK_TO_LABEL: dict[str, str] = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "arbitrary-send-eth": "access-control",
    "arbitrary-send-erc20": "access-control",
    "protected-vars": "access-control",
    "unprotected-upgrade": "access-control",
    "suicidal": "access-control",
    "tx-origin": "access-control",
    "delegatecall-to-untrusted": "delegatecall-to-untrusted",
    "controlled-delegatecall": "delegatecall-to-untrusted",
    "dangerous-strict-equalities": "oracle-manipulation",
    "boolean-equal": "logic-error",
    "tautology": "logic-error",
    "boolean-cst": "logic-error",
    "divide-before-multiply": "precision-loss",
    "incorrect-equality": "logic-error",
    "weak-prng": "bad-randomness",
    "block-timestamp": "bad-randomness",
    "calls-in-loop": "front-running",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", default=".hybridguard/results/defihack_slither_sweep.jsonl")
    ap.add_argument("--labels", default="results/defihack_labels.json")
    ap.add_argument("--out", default="results/defihack_sweep_analysis.json")
    args = ap.parse_args()

    labels_data = json.loads(Path(args.labels).read_text())
    by_path = {inc["path"]: inc for inc in labels_data["incidents"]}

    records = [json.loads(line) for line in Path(args.sweep).read_text().splitlines() if line.strip()]
    statuses = Counter(r["status"] for r in records)
    ok = [r for r in records if r["status"] == "ok"]
    ok_paths = {r["path"] for r in ok}

    per_label: dict[str, dict] = {}
    any_fired = 0
    labeled_compilable = 0
    for path, inc in by_path.items():
        explicit = inc.get("labels") or []
        if not explicit or path not in ok_paths:
            continue
        labeled_compilable += 1
        rec = next(r for r in ok if r["path"] == path)
        fired_labels = {CHECK_TO_LABEL[c] for c in rec.get("checks", []) if c in CHECK_TO_LABEL}
        if rec.get("checks"):
            any_fired += 1
        for label in explicit:
            entry = per_label.setdefault(
                label, {"labeled_compilable": 0, "detected": 0, "any_check_fired": 0}
            )
            entry["labeled_compilable"] += 1
            if label in fired_labels:
                entry["detected"] += 1
            if rec.get("checks"):
                entry["any_check_fired"] += 1

    for label, entry in per_label.items():
        n = entry["labeled_compilable"]
        entry["detection_rate"] = round(entry["detected"] / n, 3) if n else None
        entry["any_check_rate"] = round(entry["any_check_fired"] / n, 3) if n else None

    out = {
        "sweep": args.sweep,
        "n_records": len(records),
        "statuses": dict(statuses),
        "compilable_share": round(len(ok) / len(records), 3) if records else None,
        "labeled_compilable": labeled_compilable,
        "any_check_fired_on_labeled": any_fired,
        "per_label": dict(sorted(per_label.items(), key=lambda kv: -kv[1]["labeled_compilable"])),
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
