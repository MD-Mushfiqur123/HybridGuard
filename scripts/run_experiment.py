#!/usr/bin/env python3
"""Run one HybridGuard benchmark experiment and write results + figures.

Usage:
    python scripts/run_experiment.py <name> <dataset_root> --source smartbugs \
        [--limit N] [--provider mock] [--no-slicing] [--verification foundry]
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hybridguard.config import Config
from hybridguard.datasets.loader import load_contracts
from hybridguard.evaluation.metrics import (
    comparison_bar_chart,
    evaluate_reports,
    false_positive_reduction,
    token_efficiency,
    verification_coverage,
)
from hybridguard.pipeline import HybridGuardPipeline


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("dataset")
    ap.add_argument("--source", default="auto")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--provider", default="mock")
    ap.add_argument("--model", default="mock")
    ap.add_argument("--verification", default="foundry")
    ap.add_argument("--no-slicing", action="store_true")
    ap.add_argument("--mode", default="strict", choices=["strict", "detection"])
    ap.add_argument("--multipass", action="store_true", help="one LLM pass per category bundle")
    ap.add_argument("--timeout", type=int, default=300, help="per-contract watchdog (seconds)")
    ap.add_argument("--out", default=".hybridguard/results")
    args = ap.parse_args()

    cfg = Config()
    cfg.llm.provider = args.provider
    cfg.llm.model = args.model
    cfg.llm.multipass = args.multipass
    cfg.verification.backend = args.verification
    cfg.verification.workdir = ".hybridguard/verify"
    cfg.output_dir = args.out

    contracts = load_contracts(args.dataset, source=args.source, limit=args.limit)
    labels = {str(c.path): c.labels for c in contracts if c.labels}
    print(f"[{args.name}] {len(contracts)} contracts, labels for {len(labels)}", flush=True)

    pipeline = HybridGuardPipeline(cfg, slicing=not args.no_slicing)
    reports = []
    t0 = time.time()
    for i, c in enumerate(contracts, 1):
        t = time.time()
        try:
            def _on_timeout(signum, frame):
                raise TimeoutError(f"contract processing exceeded {args.timeout}s")

            signal.signal(signal.SIGALRM, _on_timeout)
            signal.alarm(args.timeout)
            try:
                r = pipeline.scan(c.path)
            finally:
                signal.alarm(0)
        except Exception as exc:
            print(f"  [{i}/{len(contracts)}] {c.stem} CRASH {type(exc).__name__}: {str(exc)[:80]} ({time.time() - t:.1f}s)", flush=True)
            from hybridguard.models import ScanReport

            r = ScanReport(path=str(c.path), errors=[f"{type(exc).__name__}: {exc}"])
            reports.append(r)
            continue
        status = "ERR" if r.errors else f"slices={r.n_slices} findings={r.n_findings} filtered={len(r.filtered_out)}"
        print(f"  [{i}/{len(contracts)}] {c.stem} {status} ({time.time() - t:.1f}s)", flush=True)
        reports.append(r)

    result = evaluate_reports(
        reports, labels=labels, tool_name=f"HybridGuard({args.name})", mode=args.mode
    )
    summary = {
        "experiment": args.name,
        "dataset": args.dataset,
        "n_contracts": len(contracts),
        "provider": args.provider,
        "slicing": not args.no_slicing,
        "verification": args.verification,
        "mode": args.mode,
        "wall_time_s": round(time.time() - t0, 1),
        "metrics": result.as_dict(),
        "false_positive_reduction": false_positive_reduction(reports),
        "token_efficiency": token_efficiency(reports),
        "verification_coverage": verification_coverage(reports),
    }

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.name}_summary.json").write_text(json.dumps(summary, indent=2))
    for r in reports:
        reports_dir = out / f"reports_{args.name}"
        reports_dir.mkdir(exist_ok=True)
        (reports_dir / f"{Path(r.path).stem}.json").write_text(
            json.dumps(HybridGuardPipeline.report_to_dict(r), indent=2)
        )
    if args.no_slicing:
        chart = out / f"{args.name}_tokens.png"
        from hybridguard.evaluation.metrics import efficiency_chart

        efficiency_chart(reports, reports, chart)
    else:
        comparison_bar_chart([result], out / f"{args.name}_fig.png")
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
