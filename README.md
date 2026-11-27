# HybridGuard

**Mitigating Hallucinations in LLM-Based Smart Contract Auditing via Static Control-Flow Graphs and Symbolic Execution**

HybridGuard is a research prototype implementing a neuro-symbolic pipeline for smart-contract
vulnerability detection. Instead of feeding a whole contract to an LLM (which causes hallucinated,
high-false-positive findings on large call graphs), HybridGuard:

1. **Slices statically** (Stage 2) — uses the [Slither](https://github.com/crytic/slither) Python API
   to extract CFG edges, data dependencies, and security-critical program slices (Ether sinks,
   balance-like state writes, external/delegate calls, privileged paths), ranked by a criticality score.
2. **Reasons with context** (Stage 3) — sends only those compact slices (plus SLITHIR and call-graph
   facts) to an open-source code LLM with Chain-of-Thought + few-shot prompts, forcing a strict-JSON
   attack-path verdict.
3. **Verifies symbolically** (Stage 4) — synthesizes a Foundry exploit harness for every LLM finding
   and runs `forge test`. Exploits that reproduce are **CONFIRMED**; harnesses that prove the exploit
   impossible **REFUTE** the finding, filtering LLM hallucinations. Mythril symbolic execution is
   available as an alternative backend.
4. **Evaluates** (Stage 5) — Precision / Recall / F1 vs. baselines (Slither-only, LLM-only, full
   HybridGuard), false-positive reduction rate, and token/time efficiency, with 300-DPI matplotlib
   figures ready for a paper.

```
Solidity file ──▶ Slither (AST/CFG/IR) ──▶ top-K critical slices ──▶ LLM (CoT, few-shot, strict JSON)
                                                                          │ candidate findings
                                                                          ▼
                                              Foundry harness synthesis + forge test (or Mythril)
                                                                          │
                                              CONFIRMED (exploit reproduced) / REFUTED (hallucination filtered)
```

## Current results (mock-LLM pipeline runs)

| Experiment | Dataset | Precision | Recall | F1 | FP | Verification coverage |
|---|---|---|---|---|---|---|
| Mythril-verified (reentrancy) | SmartBugs reentrancy (31) | **1.00** | 0.45 | **0.62** | **0** | 100% |
| Detection (sliced) | SmartBugs curated (143) | 0.19 | 0.15 | 0.17 | 93 | n/a |
| Ablation: no slicing | SmartBugs curated (143) | 0.16 | 0.15 | 0.16 | 115 | n/a |
| Clean baseline (FP-rate) | OpenZeppelin (100) | — | — | — | 12 raw | — |

- **False-positive reduction**: raw 22 → 14 kept (36%) with Mythril verification, ending at FP = 0.
- **Token efficiency**: program slicing halves prompt tokens on the clean corpus (201k → 104k for
  100 contracts; 840 vs 2,033 avg tokens/contract on SmartBugs).
- Raw summaries in `results/`, publication figures in `results/figures/`.

## Real-LLM results (Groq API, free tier) with tool-only baselines

Tool-only baselines (`scripts/run_baselines.py`, per-pragma solc resolution) and real-LLM runs on
the Groq free tier (`HYBRIDGUARD_API_KEY`):

| Experiment | Backend | Dataset | Precision | Recall | F1 | FP |
|---|---|---|---|---|---|---|
| Slither-only | Slither detectors | SmartBugs reentrancy (31) | 1.00 | **0.74** | **0.85** | 0 |
| Mythril-only | Mythril symbolic exec. | SmartBugs reentrancy (31) | see results JSON | | | |
| Reentrancy + Mythril | `gpt-oss-120b` | SmartBugs reentrancy (31) | **1.00** | 0.45 | 0.62 | **0** |
| Reentrancy + Mythril (replication) | `gpt-oss-120b` | SmartBugs reentrancy (31) | **1.00** | 0.45 | 0.62 | **0** |
| Detection (sliced) | `gpt-oss-20b` | SmartBugs curated (143) | **0.67** | 0.18 | 0.29 | 13 |
| Clean baseline | `qwen3.8-27b` | OpenZeppelin (100, 47 sliced) | — | — | — | **0** |
| Real-incident (exploratory) | `qwen3.8-27b` | DeFiHackLabs (30, 16 ran) | — | — | — | 3 raw |

**Honest reading (per our own strict review):**
- On the single-class reentrancy subset **Slither alone is stronger (F1 0.85 vs 0.62)** — pattern
  detectors win on well-studied bug classes. HybridGuard's value is complementary: every finding is
  individually symbolically verified with an explicit attack path, and the LLM can reason about
  classes pattern tools cannot express.
- **Class-wise breakdown** (`results/sb_groq_detection_class_breakdown.json`): reentrancy 21/30
  contracts hit with 0 FP, but arithmetic/access-control/randomness classes are near-blind spots.
- **Clean-code 0 FP applies to the 47 slice-bearing contracts** the LLM actually reasoned about
  (53/100 are interfaces/libraries that by design reach no LLM call).
- All runs are single runs (no variance estimates); DeFiHackLabs numbers are exploratory (1 labeled
  contract, PoC comments may contaminate findings). The reentrancy single-pass configuration was
  repeated on an independent API key and reproduced exactly (TP=14, FP=0, F1=0.62) — the one
  replicated configuration so far.
- Raw summaries: `results/*_groq_*.json`, class breakdown: `results/sb_groq_detection_class_breakdown.json`.

## Layout

- `hybridguard/slicing/` — Slither-based static analysis, call graph, program slices
- `hybridguard/llm/` — provider-agnostic reasoning stage (CoT prompts, mock + API providers)
- `hybridguard/verification/` — Foundry auto-harness exploit tests, Mythril symbolic verification
- `hybridguard/evaluation/` — P/R/F1, FP-reduction, token efficiency, figures
- `scripts/run_experiment.py` — one-command benchmark entry point
- `tests/` — end-to-end pipeline tests (27 tests)

## Usage

```bash
pip install -e .
python scripts/run_experiment.py <name> <dataset> --source smartbugs \
    --provider mock --verification mythril
```

Datasets: [SmartBugs Curated](https://github.com/smartbugs/SmartBugs),
[DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs),
[OpenZeppelin contracts](https://github.com/OpenZeppelin/openzeppelin-contracts).

## Requirements

Python 3.12, `slither-analyzer`, `mythril`, Foundry (`forge`) — all free and open source.
Runs fully offline (mock provider) or against free-tier LLM APIs (Groq / OpenRouter / HF).
