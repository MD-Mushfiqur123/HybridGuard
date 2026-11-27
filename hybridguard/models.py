"""Core data model shared across the HybridGuard pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"      # exploit reproduced by symbolic execution / fuzzing
    REFUTED = "refuted"          # harness proved the exploit impossible -> filtered FP
    SKIPPED = "skipped"          # verifier unavailable or harness generation failed


@dataclass
class CallEdge:
    caller: str
    callee: str
    kind: str = "internal"  # internal | external | delegatecall | library


@dataclass
class ExternalCall:
    destination: str
    value_transfer: bool
    kind: str  # high_level_call | low_level_call | transfer | send | delegatecall


@dataclass
class FunctionSlice:
    """A critical program slice extracted from a contract by static analysis."""

    contract: str
    function: str
    visibility: str
    param_types: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    payable: bool = False
    criticality: float = 0.0
    reasons: list[str] = field(default_factory=list)   # why this slice was selected
    external_calls: list[ExternalCall] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    ir_ops: list[str] = field(default_factory=list)    # SLITHIR ops on the critical path
    cfg_edges: list[tuple[str, str]] = field(default_factory=list)  # (node.type, next node.type)
    call_chain: list[CallEdge] = field(default_factory=list)
    source_snippet: str = ""
    start_line: int = 0
    end_line: int = 0
    source_file: str = ""


@dataclass
class ContractAnalysis:
    """Full static-analysis view of one Solidity file."""

    path: str
    contracts: list[str] = field(default_factory=list)
    slices: list[FunctionSlice] = field(default_factory=list)
    call_graph: list[CallEdge] = field(default_factory=list)
    constructor_params: dict[str, list[str]] = field(default_factory=dict)
    compile_ok: bool = True
    compile_error: str = ""


@dataclass
class LLMFinding:
    """A candidate vulnerability reported by the LLM reasoner."""

    contract: str
    function: str
    vuln_class: str          # e.g. reentrancy-eth, access-control, unchecked-arithmetic
    severity: Severity
    description: str
    attack_path: list[str] = field(default_factory=list)  # CoT attack trace
    sink: str = ""           # the exploited statement (external call / state write)
    params: list[str] = field(default_factory=list)  # canonical param types, filled by the pipeline
    ctor_params: list[str] = field(default_factory=list)  # target constructor types, filled by the pipeline
    confidence: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerifiedFinding:
    """An LLM finding that passed (or failed) symbolic verification."""

    finding: LLMFinding
    verdict: Verdict
    harness: str = ""        # generated Foundry test path or mythril cmd
    evidence: str = ""       # verifier output excerpt
    verification_time_s: float = 0.0


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class ScanReport:
    """Result of running the HybridGuard pipeline on one contract file."""

    path: str
    slicing_time_s: float = 0.0
    llm_time_s: float = 0.0
    verification_time_s: float = 0.0
    n_slices: int = 0
    n_findings: int = 0
    findings: list[VerifiedFinding] = field(default_factory=list)
    filtered_out: list[LLMFinding] = field(default_factory=list)  # LLM FPs removed by verification
    tokens: TokenUsage = field(default_factory=TokenUsage)
    errors: list[str] = field(default_factory=list)

    def confirmed(self) -> list[VerifiedFinding]:
        return [f for f in self.findings if f.verdict == Verdict.CONFIRMED]
