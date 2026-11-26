from hybridguard.evaluation.metrics import (
    ToolResult,
    evaluate_reports,
    false_positive_reduction,
    token_efficiency,
)
from hybridguard.models import (
    LLMFinding,
    ScanReport,
    Severity,
    Verdict,
    VerifiedFinding,
)


def _finding(vuln_class="reentrancy-eth"):
    return LLMFinding(
        contract="C",
        function="withdraw",
        vuln_class=vuln_class,
        severity=Severity.HIGH,
        description="d",
    )


def test_precision_recall_with_refuted_findings_excluded():
    confirmed = ScanReport(path="ds/reentrancy/A.sol")
    confirmed.findings.append(VerifiedFinding(finding=_finding(), verdict=Verdict.CONFIRMED))
    refuted = ScanReport(path="ds/reentrancy/B.sol")
    refuted.filtered_out.append(_finding())
    res = evaluate_reports([confirmed, refuted], labels={"A.sol": ["reentrancy"], "B.sol": ["reentrancy"]})
    assert res.true_positives == 1
    assert res.false_positives == 0
    assert res.false_negatives == 1
    assert res.precision == 1.0


def test_confirmed_wrong_class_is_false_positive():
    report = ScanReport(path="ds/reentrancy/A.sol")
    report.findings.append(
        VerifiedFinding(finding=_finding("oracle-manipulation"), verdict=Verdict.CONFIRMED)
    )
    res = evaluate_reports([report], labels={"A.sol": ["reentrancy"]})
    assert res.false_positives == 1
    assert res.true_positives == 0


def test_skipped_finding_counts_as_false_positive():
    report = ScanReport(path="ds/reentrancy/A.sol")
    report.findings.append(VerifiedFinding(finding=_finding(), verdict=Verdict.SKIPPED))
    res = evaluate_reports([report], labels={"A.sol": ["reentrancy"]})
    assert res.false_positives == 1


def test_clean_contract_true_negative():
    report = ScanReport(path="clean/SafeVault.sol")
    res = evaluate_reports([report], labels={})
    assert res.true_negatives == 1


def test_false_positive_reduction_rate():
    raw = ScanReport(path="a.sol")
    raw.filtered_out.append(_finding())
    raw.findings.append(VerifiedFinding(finding=_finding(), verdict=Verdict.CONFIRMED))
    assert false_positive_reduction([raw]) == {"raw_findings": 2, "kept": 1, "reduction_rate": 50.0}


def test_token_efficiency():
    report = ScanReport(path="a.sol")
    report.tokens.prompt_tokens = 900
    report.tokens.completion_tokens = 100
    report.llm_time_s = 1.5
    eff = token_efficiency([report])
    assert eff["avg_total_tokens"] == 1000.0
    assert eff["avg_llm_time_s"] == 1.5


def test_tool_result_math():
    t = ToolResult(tool="x", true_positives=8, false_positives=2, false_negatives=2)
    assert t.precision == 0.8
    assert t.recall == 0.8
    assert abs(t.f1 - 0.8) < 1e-9
