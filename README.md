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

## Repository layout

```
hybridguard/            Python package
├── slicing/slicer.py   Slither-based program slicer + criticality ranking
├── llm/prompts.py      CoT + few-shot prompt templates (strict JSON contract)
├── llm/client.py       OpenAI-compatible client (Groq / OpenRouter / Gemini / Ollama / mock)
├── llm/reasoner.py     Stage-3 orchestration + robust JSON parsing
├── verification/foundry.py       Foundry exploit-harness synthesis + verdict parsing
├── verification/mythril_verify.py Mythril symbolic-execution backend
├── datasets/loader.py  SmartBugs / DeFiHackLabs / clean-contract loaders with ground-truth labels
├── evaluation/metrics.py  P/R/F1, FP-reduction, token efficiency, publication figures
├── pipeline.py         End-to-end orchestration
└── cli.py              `hybridguard scan | benchmark | init-config`
tests/                  pytest suite (real Slither; Foundry tests auto-skip if forge is absent)
scripts/download_datasets.sh   fetch SmartBugs Curated, DeFiHackLabs, OpenZeppelin
config/default.json     pipeline configuration
```

## Quickstart

```bash
pip install -e ".[dev]"
make test          # 27 tests: slicer, prompts/JSON parsing, metrics, full pipeline
make smoke         # full pipeline on a vulnerable vault (mock LLM, no API key needed)
```

Audit one contract with a real free-tier LLM (Groq) and Foundry verification:

```bash
export GROQ_API_KEY=...        # free key from console.groq.com
hybridguard scan MyContract.sol \
    --provider groq --model llama-3.3-70b-versatile --verification foundry --save
```

No Foundry? `--verification mythril` (pip install mythril) or `--verification none`.

## Benchmarking (the paper's experiment matrix)

```bash
bash scripts/download_datasets.sh datasets        # ~3 public datasets

# 1. Baseline easy bugs (SmartBugs Curated, 143 labelled contracts)
hybridguard benchmark datasets/smartbugs-curated --source smartbugs --provider groq

# 2. Complex real-world business-logic hacks (DeFiHackLabs)
hybridguard benchmark datasets/DeFiHackLabs --source defihacklabs --provider groq --limit 100

# 3. Clean contracts -> False Positive Rate (OpenZeppelin)
hybridguard benchmark datasets/openzeppelin-contracts/contracts --source clean --provider groq

# 4. Ablation: LLM-only baseline (no slicing, no verification)
hybridguard benchmark datasets/smartbugs-curated --source smartbugs --provider groq \
    --no-slicing --verification none
```

Outputs land in `.hybridguard/results/`:
`benchmark_summary.json`, per-contract JSON reports,
`fig_precision_recall_f1.png` (300 DPI, grouped P/R/F1 bars per tool),
plus FP-reduction and token-efficiency figures via
`hybridguard.evaluation.metrics.fp_reduction_chart` / `efficiency_chart`.

## Free resources used

| Purpose | Resource |
| --- | --- |
| Static analysis | Slither (Python API for AST/CFG/SLITHIR), solc |
| Symbolic verification | Foundry (`forge` fuzzing + cheatcodes), Mythril |
| LLM inference (free tiers) | Groq API (Llama-3.3-70B), OpenRouter (DeepSeek-Coder, Qwen-2.5-Coder), Google AI Studio (Gemini), Ollama (local), Google Colab / Kaggle free GPUs |
| Vulnerable datasets | SmartBugs Curated, DeFiHackLabs, Solodit / Code4rena reports (case studies) |
| Clean contracts | OpenZeppelin contracts, Etherscan-verified sources |
| Writing | Overleaf (IEEE/ACM templates), Zotero, draw.io / Excalidraw for the architecture diagram |

## Why this runs on a laptop

Solidity sources are tiny (5–50 KB); the whole dataset is tens of MB. No model training happens —
the LLM is used inference-only through free API tiers or free Colab/Kaggle GPUs. Slither processes a
contract in well under a second; Foundry harness runs take ~0.1 s each. Everything in this repo was
developed and tested on CPU only.

## Configuration

Edit `config/default.json` (see `hybridguard init-config`): slice budget (`max_slices`,
`min_criticality`), LLM provider/model/temperature/seed, verification backend and fuzz runs.
API keys are read from the environment variable named by `llm.api_key_env`
(`GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`; Ollama needs none).
`provider: "mock"` gives a deterministic offline LLM for tests and CI.

## Threats to validity (for the paper)

* Harness synthesis covers the main exploit classes (reentrancy, access control, arithmetic);
  findings outside these classes fall back to a generic probe and are reported as `skipped`,
  not silently confirmed.
* `REFUTED` means "no exploit found up to the fuzz budget / symbolic depth", which is bounded
  verification, not mathematical proof.
* Ground-truth label matching uses the SmartBugs class taxonomy (`_LABEL_ALIASES` in
  `hybridguard/evaluation/metrics.py`); extend it when adding datasets.
