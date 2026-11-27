"""Run Slither-only and Mythril-only baselines on the SmartBugs reentrancy subset.

Produces summary JSONs with the same metric shape as run_experiment.py so the
baseline rows can sit next to HybridGuard rows in the paper tables:

  .hybridguard/results/slither_only_reentrancy_summary.json
  .hybridguard/results/mythril_only_reentrancy_summary.json

Usage:
  python scripts/run_baselines.py --dataset datasets/smartbugs-curated/dataset/reentrancy \
      --tools slither mythril [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from hybridguard.slicing.slicer import _required_pragma_version, _resolve_solc_binary

REENTRANCY_CHECKS = {"reentrancy-eth", "reentrancy-no-eth"}
MYTHRIL_SWC_REENTRANCY = 107


def contracts(dataset: Path, limit: int | None) -> list[Path]:
    files = sorted(dataset.rglob("*.sol"))
    if limit:
        files = files[:limit]
    return files


def run_slither(path: Path, timeout: int) -> bool:
    """True when Slither reports an exploitable reentrancy finding."""
    version = _required_pragma_version(str(path))
    binary = _resolve_solc_binary(version) if version else None
    cmd = ["slither", str(path), "--json", "-"]
    if binary:
        cmd += ["--solc", binary]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False
    for det in data.get("results", {}).get("detectors", []):
        if det.get("check") in REENTRANCY_CHECKS:
            return True
    return False


def run_mythril(path: Path, timeout: int) -> bool:
    """True when Mythril reports an issue matching SWC-107 (reentrancy)."""
    env = dict(os.environ)
    version = _required_pragma_version(str(path))
    if version and (_resolve_solc_binary(version) or version):
        env["SOLC_VERSION"] = version
    try:
        proc = subprocess.run(
            ["myth", "analyze", str(path), "-o", "json", "--execution-timeout", str(timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + 90,
            env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        lowered = (proc.stdout + proc.stderr).lower()
        return f"swc id: {MYTHRIL_SWC_REENTRANCY}" in lowered or "reentrancy" in lowered and proc.returncode == 1
    for issue in data.get("issues", []):
        swc = str(issue.get("swc-id", "") or issue.get("swcID", ""))
        if swc.endswith(str(MYTHRIL_SWC_REENTRANCY)):
            return True
        if "reentran" in str(issue.get("title", "") or issue.get("description", "")).lower():
            return True
    return False


def score(detections: dict[str, bool], label: str = "reentrancy") -> dict:
    tp = sum(1 for v in detections.values() if v)
    fn = sum(1 for v in detections.values() if not v)
    fp = 0
    tn = 0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tool": label,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--tools", nargs="+", default=["slither", "mythril"], choices=["slither", "mythril"])
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default=".hybridguard/results")
    args = ap.parse_args()

    dataset = Path(args.dataset)
    files = contracts(dataset, args.limit)
    print(f"baselines: {len(files)} contracts from {dataset}", flush=True)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for tool in args.tools:
        runner = run_slither if tool == "slither" else run_mythril
        analysis_timeout = 25 if tool == "slither" else 60
        detections: dict[str, bool] = {}
        t0 = time.time()
        for i, path in enumerate(files, 1):
            t = time.time()
            try:
                hit = runner(path, analysis_timeout)
            except Exception as exc:
                print(f"  [{i}/{len(files)}] {path.stem} CRASH {type(exc).__name__}: {str(exc)[:60]}", flush=True)
                hit = False
            detections[str(path)] = hit
            print(f"  [{i}/{len(files)}] {path.stem} {'DETECT' if hit else 'clean'} ({time.time() - t:.1f}s)", flush=True)
        tool_result = score(detections, label=f"{tool}-only")
        summary = {
            "experiment": f"{tool}_only_reentrancy",
            "dataset": str(dataset),
            "n_contracts": len(files),
            "provider": "static-tool",
            "slicing": False,
            "verification": "none",
            "mode": "strict",
            "wall_time_s": round(time.time() - t0, 1),
            "metrics": tool_result,
        }
        out = out_dir / f"{tool}_only_reentrancy_summary.json"
        out.write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
