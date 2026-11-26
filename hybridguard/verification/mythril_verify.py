"""Stage 4b: Mythril-based symbolic verification of a flagged contract."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

from hybridguard.models import LLMFinding, Verdict

_SOLCX_DIR = Path.home() / ".solcx"


def _installed_solc_versions() -> list[tuple[int, int, int]]:
    versions = []
    for p in _SOLCX_DIR.glob("solc-v*"):
        try:
            parts = tuple(int(x) for x in p.name.replace("solc-v", "").split("."))
            if len(parts) == 3:
                versions.append(parts)  # type: ignore[arg-type]
        except ValueError:
            continue
    return sorted(versions)


def _solv_version(contract_path: str | Path) -> str:
    """Pick the highest locally installed solc version compatible with the target pragma."""
    installed = _installed_solc_versions()
    if not installed:
        return "0.8.20"
    try:
        head = Path(contract_path).read_text(errors="replace")[:2000]
    except OSError:
        return f"{installed[-1][0]}.{installed[-1][1]}.{installed[-1][2]}"
    upper = None
    for m in re.finditer(r"pragma solidity\s+([^;]+);", head):
        for v in re.finditer(r"(\d+)\.(\d+)\.(\d+)", m.group(1)):
            t = tuple(int(x) for x in v.groups())
            if upper is None or t > upper:
                upper = t
    if upper is None:
        upper = installed[-1]
    compatible = [v for v in installed if v <= upper and v[:2] == upper[:2]] or [
        v for v in installed if v <= upper
    ]
    chosen = compatible[-1] if compatible else installed[-1]
    return f"{chosen[0]}.{chosen[1]}.{chosen[2]}"


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
        solv = _solv_version(contract_path)
        try:
            proc = subprocess.run(
                [
                    self.myth,
                    "analyze",
                    str(contract_path),
                    "--solv",
                    solv,
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
