"""End-to-end HybridGuard pipeline: slice -> reason -> verify -> report."""

from __future__ import annotations

import json
import time
from pathlib import Path

from hybridguard.config import Config
from hybridguard.models import ContractAnalysis, ScanReport, Verdict
from hybridguard.slicing.slicer import StaticSlicer


class HybridGuardPipeline:
    def __init__(self, config: Config | None = None, slicing: bool = True):
        self.config = config or Config()
        self.use_slicing = slicing
        self._slicer = StaticSlicer(
            include_ir=self.config.slicing.include_ir,
            include_source=self.config.slicing.include_source,
            max_source_lines=self.config.slicing.max_source_lines,
        )
        self._reasoner = None
        self._verifier = None

    @property
    def reasoner(self):
        if self._reasoner is None:
            from hybridguard.llm.reasoner import LLMReasoner

            self._reasoner = LLMReasoner(self.config.llm)
        return self._reasoner

    @property
    def verifier(self):
        if self._verifier is None:
            backend = self.config.verification.backend
            if backend == "foundry":
                from hybridguard.verification.foundry import FoundryVerifier

                self._verifier = FoundryVerifier(
                    workdir=self.config.verification.workdir,
                    fuzz_runs=self.config.verification.fuzz_runs,
                    timeout_s=self.config.verification.timeout_s,
                )
            elif backend == "mythril":
                from hybridguard.verification.mythril_verify import MythrilVerifier

                self._verifier = MythrilVerifier(timeout_s=self.config.verification.timeout_s)
            else:
                self._verifier = None
        return self._verifier

    def analyze_static(self, contract_path: str | Path) -> ContractAnalysis:
        return self._slicer.analyze(contract_path)

    def scan(self, contract_path: str | Path) -> ScanReport:
        contract_path = Path(contract_path)
        report = ScanReport(path=str(contract_path))

        analysis = self.analyze_static(contract_path)
        if not analysis.compile_ok:
            report.errors.append(f"static analysis failed: {analysis.compile_error}")
            return report
        report.slicing_time_s = 0.0
        t0 = time.time()
        if self.use_slicing:
            selected = self._slicer.select_slices(
                analysis,
                max_slices=self.config.slicing.max_slices,
                min_criticality=self.config.slicing.min_criticality,
            )
        else:
            selected = analysis.slices
        report.slicing_time_s = time.time() - t0
        report.n_slices = len(selected)

        findings, usage, llm_time = self.reasoner.analyze_slices(selected, str(contract_path))
        report.llm_time_s = llm_time
        report.tokens = usage
        report.n_findings = len(findings)
        for finding in findings:
            finding.params = _param_types_for(analysis, finding)
            finding.ctor_params = _ctor_types_for(analysis, finding)

        verifier = self.verifier
        for finding in findings:
            if verifier is None:
                from hybridguard.models import VerifiedFinding

                report.findings.append(
                    VerifiedFinding(finding=finding, verdict=Verdict.SKIPPED, evidence="verification disabled")
                )
                continue
            verdict, evidence, v_time = verifier.verify(finding, contract_path)
            from hybridguard.models import VerifiedFinding

            vf = VerifiedFinding(finding=finding, verdict=verdict, evidence=evidence, verification_time_s=v_time)
            if verdict == Verdict.REFUTED:
                report.filtered_out.append(finding)
            else:
                report.findings.append(vf)
            report.verification_time_s += v_time
        return report

    def save_report(self, report: ScanReport) -> Path:
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{Path(report.path).stem}.json"
        out.write_text(json.dumps(self.report_to_dict(report), indent=2))
        return out

    @staticmethod
    def report_to_dict(report: ScanReport) -> dict:
        def finding_dict(vf):
            f = vf.finding
            return {
                "verdict": vf.verdict.value,
                "contract": f.contract,
                "function": f.function,
                "vuln_class": f.vuln_class,
                "severity": f.severity.value,
                "description": f.description,
                "attack_path": f.attack_path,
                "sink": f.sink,
                "confidence": f.confidence,
                "evidence": (vf.evidence or "")[-1500:],
                "verification_time_s": round(vf.verification_time_s, 3),
            }

        return {
            "path": report.path,
            "compile_errors": report.errors,
            "slices_selected": report.n_slices,
            "llm_findings": report.n_findings,
            "filtered_false_positives": len(report.filtered_out),
            "tokens": {"prompt": report.tokens.prompt_tokens, "completion": report.tokens.completion_tokens},
            "timing_s": {
                "slicing": round(report.slicing_time_s, 3),
                "llm": round(report.llm_time_s, 3),
                "verification": round(report.verification_time_s, 3),
            },
            "findings": [finding_dict(vf) for vf in report.findings],
            "filtered_out": [
                {"contract": f.contract, "function": f.function, "vuln_class": f.vuln_class, "description": f.description}
                for f in report.filtered_out
            ],
        }


def run_scan(contract_path: str | Path, config: Config | None = None, slicing: bool = True) -> ScanReport:
    return HybridGuardPipeline(config, slicing=slicing).scan(contract_path)


def _param_types_for(analysis: ContractAnalysis, finding) -> list[str]:

    for s in analysis.slices:
        if s.function == finding.function or s.function == f"{finding.function}({','.join(finding.params)})":
            return list(s.param_types)
    return []


def _ctor_types_for(analysis: ContractAnalysis, finding) -> list[str]:
    if finding.contract in analysis.constructor_params:
        return list(analysis.constructor_params[finding.contract])
    if len(analysis.constructor_params) == 1:
        return next(iter(analysis.constructor_params.values()))
    return []
