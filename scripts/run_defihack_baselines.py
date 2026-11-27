"""Run tool-only baselines across the DeFiHackLabs incident corpus.

For each incident PoC, records every Slither detector that fires (full check
list, not just reentrancy). The resulting per-incident JSONL is the raw data
for the "static tools vs. business-logic incidents" comparison: coverage
(share of incidents with any finding / that compile), and per-label detection
against results/defihack_labels.json.

Usage:
  python scripts/run_defihack_baselines.py --tool slither [--limit N] [--sample N]
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
from pathlib import Path

from hybridguard.slicing.slicer import _auto_remaps, _required_pragma_version, _resolve_solc_binary


def run_slither(path: Path, timeout: int) -> dict:
    version = _required_pragma_version(str(path))
    binary = _resolve_solc_binary(version) if version else None
    cmd = ["slither", str(path), "--json", "-"]
    if binary:
        cmd += ["--solc", binary]
    remaps = _auto_remaps(str(path))
    if remaps:
        cmd += ["--solc-remaps", *remaps]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except FileNotFoundError:
        return {"status": "tool-missing"}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"status": "compile-error"}
    checks = sorted({d.get("check", "?") for d in data.get("results", {}).get("detectors", [])})
    return {"status": "ok", "checks": checks}


def run_mythril(path: Path, timeout: int) -> dict:
    cmd = ["myth", "analyze", str(path), "-o", "json", "--execution-timeout", str(timeout)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 90)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except FileNotFoundError:
        return {"status": "tool-missing"}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"status": "compile-error"}
    if not data.get("success", True):
        return {"status": "compile-error"}
    swcs = sorted({str(i.get("swc-id", i.get("swcID", "?"))) for i in data.get("issues", [])})
    return {"status": "ok", "swc_ids": swcs}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datasets/DeFiHackLabs/src/test")
    ap.add_argument("--tool", choices=["slither", "mythril"], required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--sample", type=int, default=None, help="random sample of N incidents")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--out", default=".hybridguard/results/defihack_baselines.jsonl")
    args = ap.parse_args()

    root = Path(args.root)
    files = sorted(p for p in root.rglob("*.sol") if "template" not in p.name.lower() and "rpcs_alive" not in p.name.lower())
    if args.sample:
        random.seed(42)
        files = random.sample(files, min(args.sample, len(files)))
    if args.limit:
        files = files[: args.limit]

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    runner = run_slither if args.tool == "slither" else run_mythril

    done: set[str] = set()
    if out.exists():
        for line in out.read_text().splitlines():
            try:
                done.add(json.loads(line)["path"])
            except (json.JSONDecodeError, KeyError):
                continue
    todo = [p for p in files if str(p) not in done]
    print(f"{args.tool} sweep: {len(files)} incidents ({len(done)} already done, {len(todo)} to go)", flush=True)

    statuses: dict[str, int] = {"done-skipped": len(done)}
    with out.open("a") as fh:
        for i, path in enumerate(todo, 1):
            t = time.time()
            result = runner(path, args.timeout)
            result["path"] = str(path)
            result["time_s"] = round(time.time() - t, 1)
            statuses[result["status"]] = statuses.get(result["status"], 0) + 1
            fh.write(json.dumps(result) + "\n")
            fh.flush()
            if i % 25 == 0 or i == len(todo):
                print(f"  [{i}/{len(todo)}] {statuses}", flush=True)

    print(json.dumps(statuses, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
