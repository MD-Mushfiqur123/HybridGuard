"""Stage 3: context-aware LLM reasoning over static-analysis slices."""

from __future__ import annotations

import time

from hybridguard.llm.client import build_backend, extract_json
from hybridguard.llm.prompts import build_messages
from hybridguard.models import FunctionSlice, LLMFinding, Severity, TokenUsage

VALID_CLASSES = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "access-control",
    "arbitrary-send-eth",
    "unchecked-arithmetic",
    "oracle-manipulation",
    "front-running",
    "denial-of-service",
    "bad-randomness",
    "unchecked-low-level-call",
    "delegatecall-to-untrusted",
    "other",
}

# Category bundles for multi-pass reasoning: a single prompt asking for all 10+
# classes makes models anchor on the best-known class (reentrancy) and go blind
# on the rest (see class-wise breakdown in results/). One pass per bundle asks
# the same slices through a narrower lens; findings are merged and deduped.
REASONING_BUNDLES: list[dict] = [
    {
        "name": "external-call-ordering",
        "focus": (
            "REENTRANCY and EXTERNAL-CALL ORDERING: check Checks-Effects-Interactions "
            "violations, re-entry during Ether/ERC token transfers, call-path DoS via revert "
            "loops, and push-vs-pull payment hazards."
        ),
        "classes": ["reentrancy-eth", "reentrancy-no-eth", "denial-of-service"],
    },
    {
        "name": "value-flow",
        "focus": (
            "ARITHMETIC and VALUE FLOW: user-controlled operands, overflow/underflow paths, "
            "rounding/precision loss, exchange-rate or oracle price manipulation, share "
            "inflation, and fee/bonus miscalculations."
        ),
        "classes": ["unchecked-arithmetic", "oracle-manipulation"],
    },
    {
        "name": "authority",
        "focus": (
            "AUTHORITY and ORDERING: access-control bypasses, unprotected privileged functions, "
            "delegatecall into untrusted code, arbitrary sends, front-running of pending "
            "transactions, and dependence on tx.origin/block timestamps/blockhash."
        ),
        "classes": ["access-control", "arbitrary-send-eth", "delegatecall-to-untrusted", "front-running", "bad-randomness"],
    },
]


def build_bundle_messages(slices: list[FunctionSlice], contract_path: str, bundle: dict, few_shot: bool = True, include_ir: bool = True) -> list[dict]:
    """Messages for one category-bundle pass: same slices, narrower lens."""
    allowed = "|".join(bundle["classes"])
    messages = build_messages(slices, contract_path, few_shot=few_shot, include_ir=include_ir)
    # tighten the lens: replace the open-ended audit question with the bundle focus
    focus = (
        f"CATEGORY FOCUS for this pass: {bundle['focus']} "
        f"Only report findings whose vuln_class is one of: {allowed}. "
        "If nothing in this category is exploitable, output {\"findings\": []}."
    )
    messages[-1] = {"role": "user", "content": messages[-1]["content"] + "\n\n" + focus}
    return messages


class LLMReasoner:
    def __init__(self, config):
        self.config = config
        self.backend = build_backend(config)

    def analyze_slices(self, slices: list[FunctionSlice], contract_path: str) -> tuple[list[LLMFinding], TokenUsage, float]:
        if not slices:
            return [], TokenUsage(), 0.0
        include_ir = getattr(self.config, "_include_ir", True)
        if getattr(self.config, "multipass", False):
            return self._analyze_multipass(slices, contract_path, include_ir)
        messages = build_messages(
            slices,
            contract_path,
            few_shot=True,
            include_ir=include_ir,
        )
        started = time.time()
        content, usage = self.backend.chat(
            messages,
            model=self.config.model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        elapsed = time.time() - started
        findings = self._parse(content)
        return findings, usage, elapsed

    def _analyze_multipass(
        self, slices: list[FunctionSlice], contract_path: str, include_ir: bool
    ) -> tuple[list[LLMFinding], TokenUsage, float]:
        """One pass per category bundle; merged and deduped findings."""
        findings: list[LLMFinding] = []
        usage = TokenUsage()
        started = time.time()
        for bundle in REASONING_BUNDLES:
            messages = build_bundle_messages(
                slices, contract_path, bundle, few_shot=True, include_ir=include_ir
            )
            content, pass_usage = self.backend.chat(
                messages,
                model=self.config.model,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
            usage.prompt_tokens += pass_usage.prompt_tokens
            usage.completion_tokens += pass_usage.completion_tokens
            findings.extend(self._parse(content))
        elapsed = time.time() - started
        seen = set()
        unique: list[LLMFinding] = []
        for f in findings:
            key = (f.contract, f.function, f.vuln_class, f.sink)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique, usage, elapsed

    def _parse(self, content: str) -> list[LLMFinding]:
        try:
            data = extract_json(content)
        except Exception:
            return []
        findings: list[LLMFinding] = []
        for raw in data.get("findings", []):
            if not isinstance(raw, dict):
                continue
            vuln_class = str(raw.get("vuln_class", "other")).strip().lower()
            if vuln_class not in VALID_CLASSES:
                vuln_class = "other"
            try:
                severity = Severity(str(raw.get("severity", "medium")).strip().lower())
            except ValueError:
                severity = Severity.MEDIUM
            try:
                confidence = min(1.0, max(0.0, float(raw.get("confidence", 0.0))))
            except (TypeError, ValueError):
                confidence = 0.0
            attack_path = raw.get("attack_path") or []
            if not isinstance(attack_path, list):
                attack_path = [str(attack_path)]
            findings.append(
                LLMFinding(
                    contract=str(raw.get("contract", "")),
                    function=str(raw.get("function", "")),
                    vuln_class=vuln_class,
                    severity=severity,
                    description=str(raw.get("description", "")),
                    attack_path=[str(step) for step in attack_path],
                    sink=str(raw.get("sink", "")),
                    confidence=confidence,
                    raw=raw,
                )
            )
        seen = set()
        unique: list[LLMFinding] = []
        for f in findings:
            key = (f.contract, f.function, f.vuln_class, f.sink)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
