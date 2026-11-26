"""Stage 4b: Mythril-based symbolic verification of a flagged contract."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from hybridguard.models import LLMFinding, Verdict


class MythrilVerifier:
    """Runs `myth analyze` on the target file and cross-checks the LLM claim.

    Mythril performs real symbolic execution; if it reports an issue of the
    same class at the flagged function, the finding is CONFIRMED. If Mythril
    completes with no matching issue, the finding stays REFUTED (symbolic
    execution found no reachable exploit path up to the transaction budget).
    """

    def __init__(self, timeout_s: int = 120, tx_count: int = 2):
        self.timeout_s = timeout_s
        self.tx_count = tx_count
        self.myth = shutil.which("myth")

    def available(self) -> bool:
        return self.myth is not None

    def verify(self, finding: LLMFinding, contract_path: str | Path) -> tuple[Verdict, str, float]:
        if not self.available():
            return Verdict.SKIPPED, "myth binary not found (pip install mythril)", 0.0
        started = time.time()
        try:
            proc = subprocess.run(
                [
                    self.myth,
                    "analyze",
                    str(contract_path),
                    "--solv",
                    "0.8.20",
                    "--execution-timeout",
                    str(max(5, self.timeout_s // 2)),
                    "--max-depth",
                    "32",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            return Verdict.SKIPPED, f"myth analyze timed out after {self.timeout_s}s", time.time() - started
        except Exception as exc:
            return Verdict.SKIPPED, f"myth analyze failed: {exc}", time.time() - started
        output = (proc.stdout + "\n" + proc.stderr)[-4000:]
        elapsed = time.time() - started
        lowered = output.lower()
        if proc.returncode != 0 and "analysis results" not in lowered:
            return Verdict.SKIPPED, "myth analysis error:\n" + output, elapsed
        class_hint = finding.vuln_class.split("-")[0]
        if class_hint in lowered and finding.function.lower() in lowered:
            return Verdict.CONFIRMED, output, elapsed
        if "analysis results" in lowered or "no issues" in lowered:
            return Verdict.REFUTED, output, elapsed
        return Verdict.SKIPPED, "inconclusive mythril output:\n" + output, elapsed
