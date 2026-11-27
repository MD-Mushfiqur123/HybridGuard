"""Build a labeled DeFiHackLabs incident benchmark from PoC exploit files.

Extracts per-incident metadata and tentative ground-truth labels by combining:
  * explicit vulnerability keywords in PoC comments (highest confidence),
  * structural attack-primitive signals in the exploit code (flash loan, oracle
    reads, reentrant callbacks, governance votes, ...).

Output: results/defihack_labels.json
  { "incidents": [{"path", "project", "month", "labels": [...], "signals": {...}}],
    "stats": {"n_incidents", "n_labeled", "per_label": {label: count}} }

Labels marked by comment keywords are "explicit"; structural-only labels are
"tentative" and must be human-verified before being used as ground truth in a
camera-ready evaluation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

COMMENT_KEYWORDS: dict[str, list[str]] = {
    "reentrancy": [r"re-?entranc\w*", r"re-?entran\w* attack"],
    "oracle-manipulation": [r"oracle manipulation", r"price manipulation", r"price oracle", r"spot price"],
    "flash-loan": [r"flash loan", r"flashloan"],
    "access-control": [r"access control", r"unauthorized", r"privilege escalation", r"owner of the contract was removed"],
    "unchecked-arithmetic": [r"integer overflow", r"integer underflow", r"overflow", r"underflow", r"arithmetic"],
    "front-running": [r"front-?run\w*", r"sandwich"],
    "governance": [r"governance", r"proposal", r"vote"],
    "delegatecall-to-untrusted": [r"delegatecall"],
    "bad-randomness": [r"random\w*", r"blockhash"],
    "precision-loss": [r"rounding", r"precision"],
    "logic-error": [r"logic error", r"business logic", r"flawed logic", r"calculation error", r"wrong calculation"],
}

STRUCTURE_SIGNALS: dict[str, list[str]] = {
    "flash-loan": [r"\.flashLoan\w*\(", r"flashloan\w*\(", r"Balancer.*flashLoan", r"executeOperation"],
    "reentrancy": [r"function\s+\w+\s*\(\s*\)\s*(?:external|public)\s+payable\s*\{[^}]{0,200}(?:call\{|transfer\()", r"receive\(\)\s*external\s+payable"],
    "oracle-manipulation": [r"getReserves\w*\(", r"price0Cumulative", r"spotPrice", r"\.latestRoundData\("],
    "governance": [r"\.castVote\w*\(", r"\.propose\w*\(", r"quorum"],
    "unchecked-arithmetic": [r"\w+\s*\*\s*\w+.*(transfer|mint|burn)", r"totalSupply\s*\*"],
    "delegatecall-to-untrusted": [r"\.delegatecall\("],
    "access-control": [r"onlyOwner|require\(msg\.sender\s*==", r"\.owner\(\)\s*!="],
}

_MULTILINE_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def extract_comment_text(source: str) -> str:
    blocks = " ".join(m.group(0) for m in _MULTILINE_COMMENT.finditer(source))
    lines = " ".join(m.group(0) for m in _LINE_COMMENT.finditer(source))
    return (blocks + " " + lines).lower()


def label_incident(path: Path) -> dict:
    source = path.read_text(errors="replace")
    comments = extract_comment_text(source)
    code = _LINE_COMMENT.sub("", _MULTILINE_COMMENT.sub("", source)).lower()

    explicit: list[str] = []
    tentative: list[str] = []
    signals: dict[str, list[str]] = defaultdict(list)

    for label, patterns in COMMENT_KEYWORDS.items():
        for pat in patterns:
            if re.search(pat, comments):
                explicit.append(label)
                signals[label].append(f"comment:{pat}")
                break

    for label, patterns in STRUCTURE_SIGNALS.items():
        for pat in patterns:
            if re.search(pat, code):
                if label not in explicit:
                    tentative.append(label)
                signals[label].append(f"code:{pat}")
                break

    stem = path.stem
    project = stem[:-4] if stem.lower().endswith("_exp") else stem
    month = path.parent.name
    return {
        "path": str(path),
        "project": project,
        "month": month,
        "labels": sorted(set(explicit)),
        "tentative_labels": sorted(set(tentative) - set(explicit)),
        "signals": dict(signals),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datasets/DeFiHackLabs/src/test")
    ap.add_argument("--out", default="results/defihack_labels.json")
    args = ap.parse_args()

    root = Path(args.root)
    files = sorted(root.rglob("*.sol"))
    incidents = []
    for f in files:
        if "template" in f.name.lower() or "rpcs_alive" in f.name.lower():
            continue
        incidents.append(label_incident(f))

    per_label = Counter()
    labeled = 0
    for inc in incidents:
        if inc["labels"]:
            labeled += 1
            for lab in inc["labels"]:
                per_label[lab] += 1

    out = {
        "n_files": len(files),
        "n_incidents": len(incidents),
        "n_labeled_explicit": labeled,
        "per_label": dict(per_label.most_common()),
        "incidents": incidents,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2))
    print(f"incidents: {len(incidents)}, explicit-labeled: {labeled} ({100 * labeled / max(1, len(incidents)):.0f}%)")
    print(json.dumps(dict(per_label.most_common()), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
