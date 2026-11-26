"""Static program slicing for Solidity contracts using the Slither Python API.

Stage 2 of the HybridGuard pipeline:
  1. Compile the contract and build the contract-level call graph.
  2. Extract per-function critical paths: external calls, state writes
     (balance-like mappings), arithmetic on user input, delegatecalls.
  3. Score each function's criticality and emit the top-K slices that are
     sent to the LLM instead of the whole contract.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from slither.core.cfg.node import NodeType
from slither.core.declarations import Function
from slither.core.variables import Variable
from slither.slither import Slither
from slither.slithir.operations import (
    Assignment,
    Binary,
    HighLevelCall,
    Index,
    InternalCall,
    LowLevelCall,
    Member,
    Send,
    SolidityCall,
    Transfer,
)

from hybridguard.models import (
    CallEdge,
    ContractAnalysis,
    ExternalCall,
    FunctionSlice,
)

try:
    from slither.slithir.operations import Balance  # newer slither
except ImportError:  # pragma: no cover
    Balance = None

try:
    from slither.slithir.variables import Constant
except ImportError:  # pragma: no cover
    Constant = None


BALANCE_HINT = re.compile(r"balance|shares|staked|supply|vault|claim|reward|withdraw|mint|burn|unwrap|swap", re.IGNORECASE)

_PRAGMA_RE = re.compile(r"pragma solidity\s+[^;]*?(\d+)\.(\d+)\.(\d+)\s*;")
_PRAGMA_MAX_RE = re.compile(r"[<>\^]?=?\s*(\d+)\.(\d+)\.(\d+)")


def _required_pragma_version(path: str) -> str | None:
    """Highest compiler version the file's pragma allows, for solc_version override."""
    try:
        head = Path(path).read_text(errors="replace")[:2000]
    except OSError:
        return None
    best = None
    for m in _PRAGMA_RE.finditer(head):
        for v in _PRAGMA_MAX_RE.finditer(m.group(0)):
            triple = tuple(int(x) for x in v.groups())
            if best is None or triple > best:
                best = triple
    return ".".join(str(x) for x in best) if best else None


def _auto_remaps(path: str) -> list[str]:
    """Foundry-style remaps (forge-std etc.) when the target lives in a repo with lib/."""
    p = Path(path).resolve()
    for base in p.parents:
        lib = base / "lib"
        if lib.is_dir():
            remaps = []
            for dep in sorted(lib.iterdir()):
                src = dep / "src"
                if src.is_dir():
                    remaps.append(f"{dep.name}/={src}/")
            return remaps
        if (base / ".git").exists() or base == base.parent:
            break
    return []


def _resolve_solc_binary(version: str) -> str | None:
    """Prefer a solc-select artifact for the required version, else fall back to PATH solc."""
    home = Path.home() / ".solc-select" / "artifacts" / f"solc-{version}" / f"solc-{version}"
    if home.exists():
        return str(home)
    return shutil.which("solc")


IR_FETCH_OPS = {"ASSIGNMENT", "BINARY", "UNARY", "INDEX", "MEMBER", "RETURN"}


class StaticSlicer:
    def __init__(self, include_ir: bool = True, include_source: bool = True, max_source_lines: int = 120):
        self.include_ir = include_ir
        self.include_source = include_source
        self.max_source_lines = max_source_lines

    def analyze(self, path: str | Path, solc_version: str | None = None) -> ContractAnalysis:
        path = str(path)
        analysis = ContractAnalysis(path=path)
        try:
            kwargs = {}
            version = solc_version or _required_pragma_version(path)
            binary = _resolve_solc_binary(version) if version else None
            if binary:
                kwargs["solc"] = binary
            remaps = _auto_remaps(path)
            if remaps:
                kwargs["solc_remaps"] = remaps
                kwargs["compile_force_framework"] = "solc"
            sl = Slither(path, **kwargs)
        except Exception as exc:  # compile failure, unsupported pragma, ...
            analysis.compile_ok = False
            analysis.compile_error = str(exc).splitlines()[0] if str(exc) else repr(exc)
            return analysis

        target_file = Path(path).resolve()
        for contract in sl.contracts:
            if contract.is_interface or contract.is_library:
                continue
            analysis.contracts.append(contract.name)
            if not self._declared_in(contract, target_file):
                continue
            ctor_params = [
                _canonical_type(v.type)
                for ctor in contract.constructors
                for v in ctor.parameters
            ]
            if ctor_params:
                analysis.constructor_params[contract.name] = ctor_params
            for fn in contract.functions_declared:
                if fn.is_constructor or fn.name in ("receive", "fallback"):
                    # constructors and fallbacks are still reachable via the call graph
                    pass
                analysis.call_graph.extend(self._edges_from(fn))

        for contract in sl.contracts:
            if contract.is_interface or contract.is_library:
                continue
            if not self._declared_in(contract, target_file):
                continue
            for fn in contract.functions_declared:
                analysis.slices.append(self._slice_function(contract.name, fn))

        analysis.slices.sort(key=lambda s: s.criticality, reverse=True)
        return analysis

    # ------------------------------------------------------------------ #
    # Slicing
    # ------------------------------------------------------------------ #

    def _slice_function(self, contract_name: str, fn: Function) -> FunctionSlice:
        slice_ = FunctionSlice(
            contract=contract_name,
            function=fn.name,
            visibility=fn.visibility,
            param_types=[_canonical_type(p.type) for p in fn.parameters],
            modifiers=[m.name for m in getattr(fn, "modifiers", [])],
            payable=bool(fn.payable),
            source_file=fn.source_mapping.filename.short if fn.source_mapping else "",
            start_line=fn.source_mapping.lines[0] if fn.source_mapping and fn.source_mapping.lines else 0,
            end_line=fn.source_mapping.lines[-1] if fn.source_mapping and fn.source_mapping.lines else 0,
        )

        criticality = 0.0
        for node in fn.nodes:
            for sv in node.state_variables_written:
                name = str(sv)
                slice_.state_writes.append(name)
                if BALANCE_HINT.search(name):
                    slice_.reasons.append(f"writes balance-like state: {name}")
            for sv in node.state_variables_read:
                name = str(sv)
                if BALANCE_HINT.search(name):
                    slice_.state_reads.append(name)
            for ir in node.irs:
                self._inspect_ir(ir, slice_)
            slice_.cfg_edges.append((node.type.name, next(iter(n.type.name for n in node.sons), "EXIT")))
            if node.type == NodeType.ENTRYPOINT:
                continue

        criticality += self._score(slice_)
        slice_.criticality = criticality

        if self.include_ir:
            seen: list[str] = []
            for node in fn.nodes:
                for ir in node.irs:
                    text = str(ir)
                    if text not in seen:
                        seen.append(text)
            slice_.ir_ops = seen[:80]
        slice_.call_chain = self._edges_from(fn)

        if self.include_source and fn.source_mapping:
            slice_.source_snippet = self._extract_source(fn)
        return slice_

    def _inspect_ir(self, ir, slice_: FunctionSlice) -> None:
        if isinstance(ir, HighLevelCall):
            value_transfer = bool(getattr(ir, "call_value", None))
            slice_.external_calls.append(
                ExternalCall(
                    destination=str(ir.function_name) if hasattr(ir, "function_name") else str(ir.destination),
                    value_transfer=value_transfer,
                    kind="high_level_call",
                )
            )
            slice_.reasons.append(f"external high-level call -> {ir.function_name if hasattr(ir, 'function_name') else ir.destination}")
            if value_transfer:
                slice_.reasons.append("external call carries msg.value (Ether sink)")
        elif isinstance(ir, LowLevelCall):
            slice_.external_calls.append(
                ExternalCall(
                    destination=str(ir.destination),
                    value_transfer=bool(getattr(ir, "call_value", None)),
                    kind="low_level_call",
                )
            )
            slice_.reasons.append(f"low-level call -> {ir.destination}")
        elif isinstance(ir, (Transfer, Send)):
            slice_.external_calls.append(
                ExternalCall(destination=str(ir.call_value) if hasattr(ir, "call_value") else str(ir.destination), value_transfer=True, kind=type(ir).__name__.lower())
            )
            slice_.reasons.append(f"{type(ir).__name__} transfers Ether to untrusted destination")
        elif isinstance(ir, SolidityCall) and "selfdestruct" in str(getattr(ir, "function", "")):
            slice_.reasons.append("selfdestruct reachable")
        elif isinstance(ir, Assignment):
            lvalue = str(ir.lvalue)
            slice_.state_writes.append(lvalue)
        elif isinstance(ir, Binary) and ir.type in ("ADDITION", "SUBTRACTION", "MULTIPLICATION", "EXPONENTIATION"):
            operand = str(ir.variable_right if hasattr(ir, "variable_right") else ir.variable_left)
            slice_.reasons.append(f"arithmetic ({ir.type.lower()}) on {operand}")
        elif isinstance(ir, (Index, Member)):
            if isinstance(ir.variable_left, Variable) and BALANCE_HINT.search(str(ir.variable_left)):
                slice_.state_reads.append(str(ir.variable_left))

    @staticmethod
    def _score(slice_: FunctionSlice) -> float:
        score = 0.0
        for call in slice_.external_calls:
            if call.kind == "low_level_call":
                score += 6.0
            elif call.kind in ("transfer", "send"):
                score += 4.0
            else:
                score += 5.0
            if call.value_transfer:
                score += 3.0
        for write in slice_.state_writes:
            score += 2.5 if BALANCE_HINT.search(write) else 1.0
        score += min(2.0, len(slice_.reasons) * 0.3)
        if slice_.payable:
            score += 1.0
        if any(m in ("onlyOwner", "onlyAdmin", "authorized", "requiresAuth") for m in slice_.modifiers):
            score += 1.5
        if "delegatecall" in " ".join(slice_.reasons).lower():
            score += 6.0
        return round(score, 2)

    def _extract_source(self, fn: Function) -> str:
        try:
            mapping = fn.source_mapping
            raw = Path(mapping.filename.absolute).read_text(errors="replace")
            lines = raw.splitlines()
            first, last = mapping.lines[0], mapping.lines[-1]
            lo = max(first - 1, 0)
            hi = min(last, len(lines))
            snippet = lines[lo:hi]
            if len(snippet) > self.max_source_lines:
                snippet = snippet[: self.max_source_lines] + ["// ... (truncated)"]
            return "\n".join(snippet)
        except Exception:
            return ""

    @staticmethod
    def _declared_in(contract, target_file: Path) -> bool:
        try:
            src = Path(contract.source_mapping.filename.absolute).resolve()
        except Exception:
            return True
        return src == target_file

    def _edges_from(self, fn: Function) -> list[CallEdge]:
        edges: list[CallEdge] = []
        for node in fn.nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) and ir.function:
                    edges.append(CallEdge(caller=fn.full_name, callee=ir.function.full_name, kind="internal"))
                elif isinstance(ir, HighLevelCall) and hasattr(ir, "function_name"):
                    edges.append(
                        CallEdge(
                            caller=fn.full_name,
                            callee=f"{ir.destination}.{ir.function_name}",
                            kind="external",
                        )
                    )
                elif isinstance(ir, LowLevelCall):
                    edges.append(CallEdge(caller=fn.full_name, callee=f"raw_call({ir.destination})", kind="external"))
        return edges

    # ------------------------------------------------------------------ #
    # Top-K selection for the LLM stage
    # ------------------------------------------------------------------ #

    def select_slices(self, analysis: ContractAnalysis, max_slices: int, min_criticality: float) -> list[FunctionSlice]:
        selected = [s for s in analysis.slices if s.criticality >= min_criticality]
        selected.sort(key=lambda s: s.criticality, reverse=True)
        return selected[:max_slices]


def _canonical_type(t) -> str:
    text = str(t).replace("payable", "").strip().replace(" ", "")
    if text == "uint":
        return "uint256"
    if text == "int":
        return "int256"
    return text


def render_slice_context(slice_: FunctionSlice, include_ir: bool = True) -> str:
    """Render a compact, LLM-readable context block for one program slice."""
    parts = [
        f"contract {slice_.contract}",
        f"function {slice_.function} ({slice_.visibility}{' payable' if slice_.payable else ''})",
        f"modifiers: {', '.join(slice_.modifiers) or 'none'}",
        f"lines {slice_.start_line}-{slice_.end_line} in {slice_.source_file}",
    ]
    if slice_.external_calls:
        parts.append(
            "external calls: " + "; ".join(
                f"{c.kind} -> {c.destination}{' [value]' if c.value_transfer else ''}" for c in slice_.external_calls
            )
        )
    if slice_.state_writes:
        parts.append("state writes: " + ", ".join(dict.fromkeys(slice_.state_writes)))
    if slice_.state_reads:
        parts.append("state reads: " + ", ".join(dict.fromkeys(slice_.state_reads)))
    if slice_.call_chain:
        parts.append("call graph edges: " + "; ".join(f"{e.caller} -> {e.callee}" for e in slice_.call_chain[:12]))
    parts.append("static-analysis notes: " + (" | ".join(slice_.reasons) if slice_.reasons else "none"))
    if include_ir and slice_.ir_ops:
        parts.append("SLITHIR (control-flow order):\n" + "\n".join(slice_.ir_ops[:60]))
    if slice_.source_snippet:
        parts.append("source:\n```solidity\n" + slice_.source_snippet + "\n```")
    return "\n".join(parts)
