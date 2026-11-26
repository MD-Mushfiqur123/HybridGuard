"""Stage 5: evaluation metrics for top-tier comparison tables and plots.

Computes per-tool Precision / Recall / F1 against dataset ground truth, the
False-Positive Reduction Rate achieved by symbolic verification, and token /
time efficiency of sliced vs. whole-contract prompting. Produces
publication-quality figures (300 DPI) with matplotlib.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from hybridguard.models import ScanReport, Verdict


@dataclass
class ToolResult:
    tool: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    tokens: int = 0
    total_time_s: float = 0.0
    n_contracts: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "tn": self.true_negatives,
            "tokens": self.tokens,
            "time_s": round(self.total_time_s, 2),
        }


@dataclass
class EvaluationSummary:
    tools: list[ToolResult] = field(default_factory=list)
    n_contracts: int = 0

    def to_json(self, path: Path | str) -> None:
        Path(path).write_text(
            json.dumps({"n_contracts": self.n_contracts, "tools": [t.as_dict() for t in self.tools]}, indent=2)
        )


def evaluate_reports(
    reports: list[ScanReport],
    labels: dict[str, list[str]] | None = None,
    tool_name: str = "HybridGuard",
) -> ToolResult:
    """Score scan reports against per-contract ground-truth labels.

    Final HybridGuard output = only CONFIRMED findings (REFUTED findings were
    filtered out by symbolic verification and live in `filtered_out`; they do
    NOT count against HybridGuard - that filtering is the paper's core claim).

    Matching rule: a confirmed finding is a TP when its vuln_class matches one
    of the contract's labels; otherwise it is an FP. Unverified (skipped)
    findings count as FPs. Every labelled class with no confirmed finding is
    an FN. Clean/unlabelled contracts with no confirmed findings are TNs.

    `labels` maps a contract path (or stem) to its ground-truth class list.
    """
    result = ToolResult(tool=tool_name)
    lookup = {str(Path(k).resolve()): v for k, v in (labels or {}).items()}
    lookup.update({Path(k).stem: v for k, v in (labels or {}).items()})
    for report in reports:
        keys = {str(Path(report.path).resolve()), Path(report.path).stem}
        contract_labels: list[str] = []
        for key in keys:
            if key in lookup:
                contract_labels = lookup[key]
                break
        confirmed_classes = {vf.finding.vuln_class for vf in report.findings if vf.verdict == Verdict.CONFIRMED}
        for vf in report.findings:
            if vf.verdict != Verdict.CONFIRMED:
                result.false_positives += 1
            elif _matches_any(vf.finding.vuln_class, contract_labels):
                result.true_positives += 1
            else:
                result.false_positives += 1
        if contract_labels:
            for label in contract_labels:
                if not (confirmed_classes & _label_aliases(label)):
                    result.false_negatives += 1
        elif not confirmed_classes:
            result.true_negatives += 1
        result.tokens += report.tokens.total
        result.total_time_s += report.slicing_time_s + report.llm_time_s + report.verification_time_s
    result.n_contracts = len(reports)
    return result


_LABEL_ALIASES = {
    "reentrancy": {"reentrancy-eth", "reentrancy-no-eth", "reentrancy"},
    "reentrancy_dao": {"reentrancy-eth", "reentrancy-no-eth", "reentrancy"},
    "reentrancy_eth": {"reentrancy-eth", "reentrancy-no-eth", "reentrancy"},
    "reentrancy_no_eth": {"reentrancy-no-eth", "reentrancy-eth", "reentrancy"},
    "integer_overflow": {"unchecked-arithmetic"},
    "integer_underflow": {"unchecked-arithmetic"},
    "arbitrary_send": {"arbitrary-send-eth", "unchecked-low-level-call"},
    "arbitrary_send_erfc": {"arbitrary-send-eth", "unchecked-low-level-call"},
    "delegatecall_to_user_supplied_address": {"delegatecall-to-untrusted"},
    "tx_origin": {"access-control"},
    "suicidal": {"access-control"},
    "unprotected_upgradeable": {"access-control"},
    "business-logic": None,  # matches any finding class (case-study mode)
    "business_logic": None,
}


def _label_aliases(label: str) -> set[str] | None:
    return _LABEL_ALIASES.get(label, {label.replace("_", "-")})


def _matches_any(vuln_class: str, labels: list[str]) -> bool:
    for label in labels:
        aliases = _label_aliases(label.strip().lower().replace("-", "_"))
        if aliases is None or vuln_class in aliases:
            return True
    return False


def false_positive_reduction(before_reports: list[ScanReport]) -> dict:
    """Compare raw LLM findings vs. post-verification findings."""
    raw = sum(len(r.findings) + len(r.filtered_out) for r in before_reports)
    kept = sum(len(r.findings) for r in before_reports)
    if raw == 0:
        return {"raw_findings": 0, "kept": 0, "reduction_rate": 0.0}
    return {
        "raw_findings": raw,
        "kept": kept,
        "reduction_rate": round(100.0 * (raw - kept) / raw, 2),
    }


def token_efficiency(reports: list[ScanReport]) -> dict:
    """Average token spend per contract; slicing should keep this well below
    whole-contract prompting (compare with a `--no-slicing` baseline run)."""
    if not reports:
        return {"avg_prompt_tokens": 0.0, "avg_total_tokens": 0.0, "avg_llm_time_s": 0.0}
    n = len(reports)
    return {
        "avg_prompt_tokens": round(sum(r.tokens.prompt_tokens for r in reports) / n, 1),
        "avg_total_tokens": round(sum(r.tokens.total for r in reports) / n, 1),
        "avg_llm_time_s": round(sum(r.llm_time_s for r in reports) / n, 3),
        "avg_slicing_time_s": round(sum(r.slicing_time_s for r in reports) / n, 3),
        "avg_verification_time_s": round(sum(r.verification_time_s for r in reports) / n, 3),
    }


def comparison_bar_chart(tool_results: list[ToolResult], out_path: str | Path) -> Path:
    """Grouped bars: Precision / Recall / F1 per tool - the headline figure."""
    tools = [t.tool for t in tool_results]
    metrics = {
        "Precision": [t.precision for t in tool_results],
        "Recall": [t.recall for t in tool_results],
        "F1": [t.f1 for t in tool_results],
    }
    x = range(len(tools))
    width = 0.25
    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=300)
    for i, (name, values) in enumerate(metrics.items()):
        ax.bar([xi + (i - 1) * width for xi in x], values, width, label=name)
    ax.set_xticks(list(x))
    ax.set_xticklabels(tools, fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("score")
    ax.set_title("Vulnerability detection: Precision / Recall / F1")
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def fp_reduction_chart(reports: list[ScanReport], out_path: str | Path) -> Path:
    raw = sum(len(r.findings) + len(r.filtered_out) for r in reports)
    kept = sum(len(r.findings) for r in reports)
    removed = raw - kept
    fig, ax = plt.subplots(figsize=(4.2, 3.6), dpi=300)
    ax.bar(["raw LLM findings", "after symbolic\nverification"], [raw, kept], color=["#c44e52", "#55a868"])
    for i, v in enumerate([raw, kept]):
        ax.text(i, v, str(v), ha="center", va="bottom", fontsize=10)
    ax.set_ylabel("findings")
    ax.set_title(f"False positives removed: {removed} ({false_positive_reduction(reports)['reduction_rate']}%)")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def efficiency_chart(reports_sliced: list[ScanReport], reports_full: list[ScanReport], out_path: str | Path) -> Path:
    """Token cost: sliced context vs. whole-contract context (the scalability claim)."""
    a = token_efficiency(reports_sliced)
    b = token_efficiency(reports_full)
    fig, ax = plt.subplots(figsize=(4.2, 3.6), dpi=300)
    ax.bar(
        ["HybridGuard\n(sliced)", "LLM-only\n(whole contract)"],
        [a["avg_total_tokens"], b["avg_total_tokens"]],
        color=["#4c72b0", "#dd8452"],
    )
    ax.set_ylabel("avg tokens / contract")
    ax.set_title("Token efficiency of program slicing")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out
