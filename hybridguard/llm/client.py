"""OpenAI-compatible chat client with free-tier providers and a mock backend.

Providers (all usable for free):
  groq        - https://api.groq.com/openai/v1      (Llama-3.3-70B, Qwen, ...)
  openrouter  - https://openrouter.ai/api/v1         (DeepSeek-Coder, Qwen-2.5-Coder, ...)
  gemini      - https://generativelanguage.googleapis.com/v1beta/openai
  openai      - https://api.openai.com/v1
  ollama      - http://localhost:11434/v1            (local, no key)
  custom      - any OpenAI-compatible base_url
  mock        - deterministic offline backend for tests/CI
"""

from __future__ import annotations

import json
import os
import re
from typing import Protocol

import requests

from hybridguard.models import TokenUsage

PROVIDER_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",
}


class ChatBackend(Protocol):
    def chat(self, messages: list[dict], *, model: str, temperature: float, max_tokens: int) -> tuple[str, TokenUsage]:
        ...


class OpenAICompatClient:
    """Thin client over any OpenAI-compatible /chat/completions endpoint."""

    def __init__(self, base_url: str, api_key: str | None = None, timeout: int = 120, seed: int | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.seed = seed

    def chat(self, messages: list[dict], *, model: str, temperature: float, max_tokens: int) -> tuple[str, TokenUsage]:
        payload: dict = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self.seed is not None:
            payload["seed"] = self.seed
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {}) or {}
        tokens = TokenUsage(
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
        )
        return content, tokens


class MockLLM:
    """Deterministic offline backend.

    Rule-based: flags a reentrancy finding when the slice context shows an
    external call with value followed by a balance write (the classic CEI
    violation that the static slicer highlights). Used by tests and CI so the
    full pipeline runs without any API key.
    """

    def chat(self, messages: list[dict], *, model: str, temperature: float, max_tokens: int) -> tuple[str, TokenUsage]:
        user = messages[-1]["content"]
        findings: list[dict] = []
        contract = self._extract_contract(user)
        for block in user.split("=== SLICE ")[1:]:
            name = self._extract_function(block)
            has_value_call = "external calls:" in block and "[value]" in block
            if has_value_call:
                findings.append(
                    {
                        "contract": contract,
                        "function": name,
                        "vuln_class": "reentrancy-eth",
                        "severity": "critical",
                        "description": "External call carrying value with state update order allowing re-entry (mock heuristic).",
                        "attack_path": ["mock: deposit", "mock: re-enter during external call"],
                        "sink": "external call with value",
                        "confidence": 0.6,
                    }
                )
            elif "arbitrary" in block.lower() or ("delegatecall" in block.lower() and "onlyOwner" not in block):
                findings.append(
                    {
                        "contract": contract,
                        "function": name,
                        "vuln_class": "delegatecall-to-untrusted",
                        "severity": "critical",
                        "description": "Unprotected delegatecall (mock heuristic).",
                        "attack_path": ["mock: call with attacker-controlled target"],
                        "sink": "delegatecall",
                        "confidence": 0.5,
                    }
                )
        content = json.dumps({"findings": findings})
        tokens = TokenUsage(prompt_tokens=len(user) // 4, completion_tokens=len(content) // 4)
        return content, tokens

    @staticmethod
    def _extract_contract(text: str) -> str:
        m = re.search(r"contract (\w+)", text)
        return m.group(1) if m else "Unknown"

    @staticmethod
    def _extract_function(block: str) -> str:
        m = re.search(r"function (\S+)", block)
        return m.group(1) if m else "unknown"


def build_backend(llm_config) -> ChatBackend:
    provider = llm_config.provider.lower()
    if provider == "mock":
        return MockLLM()
    base_url = llm_config.base_url or PROVIDER_BASE_URLS.get(provider)
    if not base_url:
        raise ValueError(f"Unknown provider {provider!r} and no base_url configured")
    api_key = os.environ.get(llm_config.api_key_env, "")
    if provider != "ollama" and not api_key:
        raise ValueError(
            f"API key for provider {provider!r} not found in env var {llm_config.api_key_env!r}; "
            "set it or use provider='mock' for offline testing"
        )
    return OpenAICompatClient(base_url=base_url, api_key=api_key or None, seed=llm_config.seed)


def extract_json(text: str) -> dict:
    """Robustly pull the JSON object out of an LLM response."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object found in LLM response")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : i + 1])
    raise ValueError("unterminated JSON object in LLM response")
