import pytest

from hybridguard.slicing.slicer import StaticSlicer, render_slice_context

CONTRACTS = {
    "reentrancy": "tests/contracts/ReentrancyVault.sol",
    "clean": "tests/contracts/SafeVault.sol",
    "access": "tests/contracts/BrokenTreasury.sol",
    "arith": "tests/contracts/UncheckedPool.sol",
}


@pytest.fixture(scope="module")
def slicer():
    return StaticSlicer()


def test_reentrancy_slice_ranks_highest(slicer):
    analysis = slicer.analyze(CONTRACTS["reentrancy"])
    assert analysis.compile_ok
    top = slicer.select_slices(analysis, max_slices=1, min_criticality=0)
    assert top[0].function == "withdraw"
    assert any("call" in r.lower() for r in top[0].reasons)
    assert top[0].external_calls and top[0].external_calls[0].value_transfer


def test_cei_violation_visible_in_ir(slicer):
    analysis = slicer.analyze(CONTRACTS["reentrancy"])
    withdraw = next(s for s in analysis.slices if s.function == "withdraw")
    assert any("LOW_LEVEL_CALL" in op for op in withdraw.ir_ops)
    assert any("balances" in op and ":= 0" in op for op in withdraw.ir_ops)


def test_clean_contract_withdraw_is_effect_before_interaction(slicer):
    analysis = slicer.analyze(CONTRACTS["clean"])
    withdraw = next(s for s in analysis.slices if s.function == "withdraw")
    rendered = render_slice_context(withdraw)
    assert "balance-like state" in rendered


def test_access_control_slice_flags_payout(slicer):
    analysis = slicer.analyze(CONTRACTS["access"])
    payout = next(s for s in analysis.slices if s.function == "payout")
    assert payout.criticality > 5
    assert "onlyOwner" not in payout.modifiers


def test_slice_context_is_compact(slicer):
    analysis = slicer.analyze(CONTRACTS["reentrancy"])
    rendered = render_slice_context(slicer.select_slices(analysis, 1, 0)[0])
    assert len(rendered) < 4000, "slice context must stay small enough for cheap LLM calls"


def test_compile_failure_is_graceful(slicer, tmp_path):
    bad = tmp_path / "Bad.sol"
    bad.write_text("pragma solidity ^0.9.99; contract X {}")
    analysis = slicer.analyze(bad)
    assert not analysis.compile_ok
    assert analysis.compile_error
