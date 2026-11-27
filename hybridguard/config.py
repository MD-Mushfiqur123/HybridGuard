"""Pipeline configuration (defaults + JSON override file)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

CONFIG_FILE = Path("config/default.json")


@dataclass
class SlicingConfig:
    max_slices: int = 8                 # top-K critical functions sent to the LLM
    min_criticality: float = 3.0        # discard functions below this score
    include_ir: bool = True             # include SLITHIR ops in the slice context
    include_source: bool = True         # include raw source snippet
    max_source_lines: int = 120         # cap snippet size sent to the LLM


@dataclass
class LLMConfig:
    provider: str = "mock"              # groq | openrouter | gemini | openai | ollama | custom | mock
    model: str = "mock-hybridguard"
    temperature: float = 0.1
    max_tokens: int = 2048
    base_url: str = ""                  # override for custom OpenAI-compatible endpoints
    api_key_env: str = "HYBRIDGUARD_API_KEY"
    seed: int | None = 42


@dataclass
class VerificationConfig:
    backend: str = "foundry"            # foundry | mythril | none
    fuzz_runs: int = 256
    timeout_s: int = 120
    workdir: str = ".hybridguard/verify"


@dataclass
class Config:
    slicing: SlicingConfig = field(default_factory=SlicingConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    output_dir: str = ".hybridguard/results"

    def save(self, path: Path | str = CONFIG_FILE) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path: Path | str | None = None) -> Config:
        cfg = cls()
        p = Path(path) if path else CONFIG_FILE
        if p.exists():
            data = json.loads(p.read_text())
            for section, values in data.items():
                if not hasattr(cfg, section):
                    continue
                if isinstance(values, dict) and hasattr(cfg, section):
                    current = getattr(cfg, section)
                    for k, v in values.items():
                        if hasattr(current, k):
                            setattr(current, k, v)
                else:
                    setattr(cfg, section, values)
        return cfg


DEFAULT_CONFIG_JSON = {
    "slicing": {"max_slices": 8, "min_criticality": 3.0},
    "llm": {
        "provider": "groq",
        "model": "llama-3.3-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
    },
    "verification": {"backend": "foundry", "fuzz_runs": 256},
}


def write_default_config() -> None:
    Path(CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(CONFIG_FILE).write_text(json.dumps(DEFAULT_CONFIG_JSON, indent=2))
