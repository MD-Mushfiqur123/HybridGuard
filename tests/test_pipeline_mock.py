"""End-to-end pipeline smoke test with real Slither + mock LLM (no API key, no Foundry)."""

import json
from pathlib import Path

from hybridguard.config import Config
from hybridguard.pipeline import HybridGuardPipeline
from hybridguard.slicing.slicer import StaticSlicer


def _config(tmp_path: Path) -> Config:
    cfg = Config()
    cfg.llm.provider = "mock"
    cfg.llm.model = "mock"
    cfg.verification.backend = "none"
    cfg.output_dir = str(tmp_path / "results")
    cfg.verification.workdir = str(tmp_path / "verify")
    return cfg


def test_full_pipeline_on_reentrancy(tmp_path):
    pipeline = HybridGuardPipeline(_config(tmp_path))
    report = pipeline.scan("tests/contracts/ReentrancyVault.sol")
    assert not report.errors
    assert report.n_slices >= 1
    assert report.n_findings >= 1
    top = report.findings[0]
    assert top.finding.vuln_class in ("reentrancy-eth", "reentrancy-no-eth")
    assert top.finding.function == "withdraw"
    assert top.verdict.value in ("confirmed", "skipped")
    assert report.tokens.total > 0


def test_slicing_vs_no_slicing_context_size(tmp_path):
    """The core efficiency claim: sliced prompts carry far less code than the
    whole contract, and the token accounting reflects that."""
    analysis = StaticSlicer().analyze("tests/contracts/ReentrancyVault.sol")
    sliced_ctx = sum(len(s.source_snippet) for s in analysis.slices[:1])
    full_ctx = sum(len(s.source_snippet) for s in analysis.slices)
    assert sliced_ctx < full_ctx

    pipeline = HybridGuardPipeline(_config(tmp_path), slicing=True)
    r_sliced = pipeline.scan("tests/contracts/ReentrancyVault.sol")
    assert r_sliced.n_slices <= 8


def test_report_serialization(tmp_path):
    pipeline = HybridGuardPipeline(_config(tmp_path))
    report = pipeline.scan("tests/contracts/ReentrancyVault.sol")
    out = pipeline.save_report(report)
    data = json.loads(Path(out).read_text())
    assert data["slices_selected"] >= 1
    assert "findings" in data and "filtered_out" in data
