"""HybridGuard command-line interface.

    hybridguard scan <contract.sol> [--provider groq --model ...]
    hybridguard benchmark <dataset_root> [--source smartbugs] [--limit 50]
    hybridguard compare <baseline_results.json> [...]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hybridguard.config import Config
from hybridguard.pipeline import HybridGuardPipeline
from hybridguard.version import __version__


def _apply_overrides(config: Config, args) -> Config:
    if args.provider:
        config.llm.provider = args.provider
    if args.model:
        config.llm.model = args.model
    if args.no_slicing:
        pass
    if args.verification:
        config.verification.backend = args.verification
    return config


def cmd_scan(args) -> int:
    config = Config.load(args.config) if args.config else Config()
    config = _apply_overrides(config, args)
    pipeline = HybridGuardPipeline(config, slicing=not args.no_slicing)
    report = pipeline.scan(args.contract)
    print(json.dumps(HybridGuardPipeline.report_to_dict(report), indent=2))
    if args.save:
        path = pipeline.save_report(report)
        print(f"[saved] {path}", file=sys.stderr)
    return 0


def cmd_benchmark(args) -> int:
    from hybridguard.datasets.loader import load_contracts
    from hybridguard.evaluation.metrics import (
        EvaluationSummary,
        ToolResult,
        comparison_bar_chart,
        false_positive_reduction,
        token_efficiency,
    )

    config = Config.load(args.config) if args.config else Config()
    config = _apply_overrides(config, args)
    contracts = load_contracts(args.dataset, source=args.source, limit=args.limit)
    if not contracts:
        print("no contracts found for the given dataset/root", file=sys.stderr)
        return 1
    pipeline = HybridGuardPipeline(config, slicing=not args.no_slicing)
    reports = []
    for c in contracts:
        print(f"[scan] {c.path} (labels={c.labels})", file=sys.stderr)
        reports.append(pipeline.scan(c.path))
    result: ToolResult = ToolResult(tool="HybridGuard")
    from hybridguard.evaluation.metrics import evaluate_reports

    labels = {str(c.path): c.labels for c in contracts if c.labels}
    result = evaluate_reports(reports, labels=labels, tool_name="HybridGuard")
    summary = EvaluationSummary(tools=[result], n_contracts=len(reports))
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary.to_json(out_dir / "benchmark_summary.json")
    chart = comparison_bar_chart([result], out_dir / "fig_precision_recall_f1.png")
    fp = false_positive_reduction(reports)
    eff = token_efficiency(reports)
    print(json.dumps({"summary": result.as_dict(), "false_positive_reduction": fp, "token_efficiency": eff}, indent=2))
    print(f"[figures] {chart}", file=sys.stderr)
    return 0


def cmd_init_config(args) -> int:
    from hybridguard.config import DEFAULT_CONFIG_JSON

    Path(args.path).write_text(json.dumps(DEFAULT_CONFIG_JSON, indent=2))
    print(f"wrote {args.path}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hybridguard", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit one Solidity file end-to-end")
    scan.add_argument("contract")
    scan.add_argument("--provider", help="groq | openrouter | gemini | openai | ollama | mock")
    scan.add_argument("--model")
    scan.add_argument("--verification", help="foundry | mythril | none")
    scan.add_argument("--no-slicing", action="store_true", help="send whole contract to the LLM (baseline mode)")
    scan.add_argument("--config")
    scan.add_argument("--save", action="store_true")
    scan.set_defaults(func=cmd_scan)

    bench = sub.add_parser("benchmark", help="run the pipeline over a dataset and compute metrics")
    bench.add_argument("dataset", help="dataset root (SmartBugs, DeFiHackLabs, or a folder of .sol)")
    bench.add_argument("--source", default="auto", help="smartbugs | defihacklabs | clean | raw | auto")
    bench.add_argument("--limit", type=int, default=None)
    bench.add_argument("--provider")
    bench.add_argument("--model")
    bench.add_argument("--verification")
    bench.add_argument("--no-slicing", action="store_true")
    bench.add_argument("--config")
    bench.set_defaults(func=cmd_benchmark)

    init = sub.add_parser("init-config", help="write a default config file to edit")
    init.add_argument("--path", default="config/default.json")
    init.set_defaults(func=cmd_init_config)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
