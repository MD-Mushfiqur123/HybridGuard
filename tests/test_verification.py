"""Symbolic verification tests - run for real when forge is installed, skip otherwise."""

import shutil

import pytest

from hybridguard.models import LLMFinding, Severity
from hybridguard.verification.foundry import FoundryVerifier, _harness, _signature

forge_missing = shutil.which("forge") is None
pytestmark = pytest.mark.skipif(forge_missing, reason="forge (Foundry) not installed")


def _verifier(tmp_path):
    return FoundryVerifier(workdir=tmp_path / "verify", fuzz_runs=32, timeout_s=180)


def test_reentrancy_claim_confirmed_on_vulnerable_contract(tmp_path):
    v = _verifier(tmp_path)
    f = LLMFinding(
        contract="ReentrancyVault",
        function="withdraw",
        vuln_class="reentrancy-eth",
        severity=Severity.CRITICAL,
        description="claim",
    )
    verdict, evidence, _ = v.verify(f, "tests/contracts/ReentrancyVault.sol")
    assert verdict.value == "confirmed"
    assert "[PASS]" in evidence


def test_hallucinated_reentrancy_refuted_on_safe_contract(tmp_path):
    v = _verifier(tmp_path)
    f = LLMFinding(
        contract="SafeVault",
        function="withdraw",
        vuln_class="reentrancy-eth",
        severity=Severity.CRITICAL,
        description="hallucination",
    )
    verdict, evidence, _ = v.verify(f, "tests/contracts/SafeVault.sol")
    assert verdict.value == "refuted"
    assert "failed" in evidence


def test_access_control_claim_confirmed(tmp_path):
    v = _verifier(tmp_path)
    f = LLMFinding(
        contract="BrokenTreasury",
        function="payout",
        vuln_class="access-control",
        severity=Severity.CRITICAL,
        description="unprotected payout",
        params=["address"],
    )
    verdict, _, _ = v.verify(f, "tests/contracts/BrokenTreasury.sol")
    assert verdict.value == "confirmed"


def test_harness_signature_building():
    assert _signature("payout", ["address"]) == "payout(address)"
    assert _signature("withdraw", []) == "withdraw()"


def test_harness_contains_inline_cheatcodes():
    src = _harness("X", "X", "withdraw", "reentrancy")
    assert "contract HgTest" in src
    assert "forge-std" not in src
