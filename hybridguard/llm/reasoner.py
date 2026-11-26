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
    "unchecked-low-level-call",
    "delegatecall-to-untrusted",
    "other",
}


class LLMReasoner:
    def __init__(self, config):
        self.config = config
        self.backend = build_backend(config)

    def analyze_slices(self, slices: list[FunctionSlice], contract_path: str) -> tuple[list[LLMFinding], TokenUsage, float]:
        if not slices:
            return [], TokenUsage(), 0.0
        messages = build_messages(
            slices,
            contract_path,
            few_shot=True,
            include_ir=getattr(self.config, "_include_ir", True),
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
