"""Dataset discovery and ground-truth label extraction.

Supported sources (all public, free):
  smartbugs     - SmartBugs Curated: dataset/smartbugs-curated/<vuln-class>/<name>.sol
  defihacklabs  - DeFiHackLabs: test/<year-mm>/<Project>/*.sol (PoC exploit + target)
  clean         - a directory of verified-safe contracts (OpenZeppelin etc.)
  raw           - any directory of .sol files; labels empty unless path hints exist

Ground-truth labels are inferred from the SmartBugs class directory name and,
for DeFiHackLabs, from the repo's per-project README/exploit naming; when no
label can be inferred the contract is treated as unlabelled (excluded from
P/R/F1 but still usable for case studies).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SMARTBUGS_CLASSES = {
    "arbitrary_send",
    "arbitrary_send_erfc",
    "attribute_selector",
    "bad_randomness",
    "block_timestamp",
    "constant_function",
    "control_field_manipulation",
    "delegatecall_to_user_supplied_address",
    "dex",
    "do_while_false",
    "for_loop_iter_over_dynamic_array",
    "hidden_state_update",
    "incorrect_equality",
    "incorrect_strict_equality",
    "integer_overflow",
    "integer_underflow",
    "locked_ether",
    "msg_value_in_loop",
    "name_spread_require",
    "non_payable_fallback",
    "odds_and_ends",
    "old_balance_dependency",
    "over_leaky",
    "proxy_storage_collision",
    "random_number_generator",
    "reentrancy",
    "reentrancy_dao",
    "reentrancy_eth",
    "reentrancy_no_eth",
    "shadowing_abstract",
    "shadowing_builtins",
    "shadowing_local",
    "short_addresses",
    "storage_injection",
    "suicidal",
    "swc_registry",
    "tolerant_math",
    "tx_origin",
    "typecast_constructor",
    "unhandled_exception",
    "uninitialized_storage_pointer",
    " unprotected",
    "unprotected_upgradeable",
    "wrong_constructor_name",
}

DEFIHACK_LABEL_HINT = re.compile(
    r"reentranc|access.?control|oracle|price.?manip|flash.?loan|arbitrary|overflow|"
    r"underflow|logic|error|race|front.?run|signature|approve|callback|drain|steal",
    re.IGNORECASE,
)


@dataclass
class DatasetContract:
    path: Path
    labels: list[str] = field(default_factory=list)
    source: str = "raw"

    @property
    def stem(self) -> str:
        return self.path.stem


def discover(root: str | Path, source: str = "auto") -> list[DatasetContract]:
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"dataset root not found: {root}")
    kind = source
    if kind == "auto":
        if (root / "dataset" / "smartbugs-curated").exists() or (root / "smartbugs-curated").exists():
            kind = "smartbugs"
        elif any(root.glob("test")) and any(root.glob("test/2*")):
            kind = "defihacklabs"
        else:
            kind = "raw"
    loader = {
        "smartbugs": _load_smartbugs,
        "defihacklabs": _load_defihacklabs,
        "clean": _load_clean,
        "raw": _load_raw,
    }[kind]
    return loader(root)


def load_contracts(root: str | Path, source: str = "auto", limit: int | None = None) -> list[DatasetContract]:
    contracts = discover(root, source)
    if limit:
        contracts = contracts[:limit]
    return contracts


def _load_smartbugs(root: Path) -> list[DatasetContract]:
    base = root / "dataset" / "smartbugs-curated"
    if not base.exists():
        base = root / "smartbugs-curated"
    if not base.exists():
        # official layout: dataset/<vuln-class>/<name>.sol
        base = root / "dataset"
    if not base.exists():
        # single class dir passed directly (e.g. .../dataset/reentrancy)
        base = root
    out: list[DatasetContract] = []
    class_dirs = sorted(p for p in base.iterdir() if p.is_dir())
    if not class_dirs and any(base.glob("*.sol")):
        class_dirs = [base]
    for class_dir in class_dirs:
        label = class_dir.name.strip().lower()
        for sol in sorted(class_dir.rglob("*.sol")):
            if "node_modules" in sol.parts:
                continue
            out.append(DatasetContract(path=sol, labels=[label], source="smartbugs"))
    return out


VENDORED_DIRS = {"lib", "node_modules", "out", "cache", "broadcast"}


def _load_defihacklabs(root: Path) -> list[DatasetContract]:
    out: list[DatasetContract] = []
    for sol in sorted(root.rglob("*.sol")):
        parts = sol.parts
        if any(p.startswith(".") for p in parts):
            continue
        if VENDORED_DIRS & set(parts):
            continue
        labels: list[str] = []
        if DEFIHACK_LABEL_HINT.search(sol.stem) or DEFIHACK_LABEL_HINT.search(sol.parent.name):
            labels = ["business-logic"]
        out.append(DatasetContract(path=sol, labels=labels, source="defihacklabs"))
    return out


def _load_clean(root: Path) -> list[DatasetContract]:
    return [
        DatasetContract(path=sol, labels=[], source="clean")
        for sol in sorted(root.rglob("*.sol"))
        if "node_modules" not in sol.parts
    ]


def _load_raw(root: Path) -> list[DatasetContract]:
    return [
        DatasetContract(path=sol, labels=[], source="raw")
        for sol in sorted(root.rglob("*.sol"))
        if "node_modules" not in sol.parts
    ]
