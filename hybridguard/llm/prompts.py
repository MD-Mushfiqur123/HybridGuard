"""Prompt templates for context-aware LLM reasoning (Stage 3).

Design goals (from the HybridGuard hypothesis):
  * Never send the whole contract - only static-analysis-selected critical
    slices together with CFG / IR facts, so the model cannot wander through
    thousands of irrelevant lines (the main hallucination trigger).
  * Force explicit Chain-of-Thought attack-path reasoning and a strict JSON
    answer so findings are machine-checkable by the symbolic verifier.
"""

from __future__ import annotations

from hybridguard.models import FunctionSlice
from hybridguard.slicing.slicer import render_slice_context

SYSTEM_PROMPT = """You are HybridGuard's reasoning engine: an expert smart-contract security auditor.
You receive ONE OR MORE PROGRAM SLICES extracted by static analysis from a Solidity
contract, together with facts from its control-flow graph (CFG) and SLITHIR
intermediate representation. You do NOT see the full contract by design: every
slice you see was pre-selected as security-critical (Ether sinks, balance
updates, external calls, privileged operations).

Your task: decide whether an attacker can violate the contract's intended
business logic by combining the shown functions in a sequence the developer did
not expect. Focus on cross-function and cross-contract interactions, not style.

Think step by step:
1. List the external calls, Ether sinks, and state variables written.
2. Check the Checks-Effects-Interactions (CEI) ordering: is any state variable
   written AFTER an external call, allowing re-entry to observe stale state?
3. Consider who can call the function: is a privileged operation protected by
   an access-control modifier or an ownership check that can be bypassed?
4. Consider arithmetic: can any user-controlled value overflow/underflow,
   round unfavorably, or be used before validation?
5. Consider oracle/price logic: can a spot price, timestamp, or external
   return value be manipulated to the attacker's benefit?
6. Derive a concrete ATTACK PATH as an ordered sequence of transactions. If no
   concrete attacker-profitable sequence exists, report NO vulnerability for
   that slice. Do not speculate about missing code you have not seen.

Output STRICT JSON only (no markdown fences, no prose outside JSON):
{"findings": [
  {"contract": "<contract name>",
   "function": "<function name>",
   "vuln_class": "reentrancy-eth|reentrancy-no-eth|access-control|arbitrary-send-eth|"
               "unchecked-arithmetic|oracle-manipulation|front-running|"
               "unchecked-low-level-call|delegatecall-to-untrusted|other",
   "severity": "critical|high|medium|low|info",
   "description": "<one-sentence root cause>",
   "attack_path": ["step 1", "step 2", "..."],
   "sink": "<the exact statement exploited, e.g. 'msg.sender.call{value: amount}(\"\")'>",
   "confidence": 0.0-1.0}
]}
If you find nothing exploitable, output {"findings": []}."""

FEW_SHOT_EXAMPLES = [
    {
        "slice": (
            "contract VulnerableVault\n"
            "function withdraw (external)\n"
            "external calls: low_level_call -> msg.sender [value]\n"
            "state writes: balances (AFTER the external call)\n"
            "static-analysis notes: low-level call -> msg.sender | writes balance-like state: balances\n"
            "SLITHIR:\namount := balances[msg.sender]\n"
            "TUPLE = LOW_LEVEL_CALL dest:msg.sender value:amount\n"
            "balances[msg.sender] := 0"
        ),
        "answer": (
            '{"findings": [{"contract": "VulnerableVault", "function": "withdraw", '
            '"vuln_class": "reentrancy-eth", "severity": "critical", '
            '"description": "Balances are zeroed after the external call, so a reentrant '
            'callee observes a stale balance and can drain funds.", '
            '"attack_path": ["Attacker deploys a contract with a receive() fallback.", '
            '"Attacker deposits 1 ETH.", '
            '"Attacker calls withdraw(); the vault sends 1 ETH before resetting the balance.", '
            '"receive() re-enters withdraw() while balances[attacker] is still 1 ETH.", '
            '"Repeat until the vault is empty."], '
            '"sink": "msg.sender.call{value: amount}(\"\")", "confidence": 0.95}]}'
        ),
    },
    {
        "slice": (
            "contract SafeStaking\n"
            "function claimReward (external)\n"
            "modifiers: onlyOwner\n"
            "state writes: rewardLedger (BEFORE the external call)\n"
            "static-analysis notes: state updated before transfer; access-control modifier present"
        ),
        "answer": (
            '{"findings": []}'
        ),
    },
]


def build_user_prompt(slices: list[FunctionSlice], contract_path: str, include_ir: bool = True) -> str:
    """Render the user message: static context + slices + the audit question."""
    header = [
        f"CONTRACT FILE: {contract_path}",
        "",
        "The following program slices were selected by static analysis "
        "(Slither CFG + data-dependency) as the security-critical subset of this contract.",
        "Functions absent from this list scored below the criticality threshold",
        "(no external calls, no state writes, no privileged logic).",
        "",
    ]
    blocks = []
    for i, s in enumerate(slices, 1):
        blocks.append(f"=== SLICE {i} ===\n{render_slice_context(s, include_ir=include_ir)}")
    question = (
        "AUDIT QUESTION: For each slice, is there a concrete attacker-executable "
        "transaction sequence (possibly re-entering from an attacker-controlled contract) "
        "that manipulates state or steals funds in a way the developer did not intend? "
        "Follow the system reasoning steps, then output the strict JSON verdict."
    )
    return "\n".join(header + blocks + ["", question])


def build_messages(slices: list[FunctionSlice], contract_path: str, few_shot: bool = True, include_ir: bool = True) -> list[dict]:
    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    if few_shot:
        for ex in FEW_SHOT_EXAMPLES:
            messages.append({"role": "user", "content": f"CONTRACT FILE: example.sol\n\n=== SLICE 1 ===\n{ex['slice']}\n\nAUDIT QUESTION: report exploitable business-logic flaws as strict JSON."})
            messages.append({"role": "assistant", "content": ex["answer"]})
    messages.append({"role": "user", "content": build_user_prompt(slices, contract_path, include_ir=include_ir)})
    return messages
