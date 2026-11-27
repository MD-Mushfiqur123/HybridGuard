import json

from hybridguard.config import LLMConfig
from hybridguard.llm.client import MockLLM, extract_json
from hybridguard.llm.reasoner import LLMReasoner
from hybridguard.slicing.slicer import StaticSlicer


def test_extract_json_plain():
    assert extract_json('{"findings": []}') == {"findings": []}


def test_extract_json_fenced():
    text = 'Sure, here you go:\n```json\n{"findings": [{"a": 1}]}\n```'
    assert extract_json(text)["findings"][0]["a"] == 1


def test_extract_json_with_trailing_prose():
    text = '{"findings": []}\nI hope this helps!'
    assert extract_json(text) == {"findings": []}


def test_reasoner_parses_mock_output():
    reasoner = LLMReasoner(LLMConfig(provider="mock", model="mock"))
    analysis = StaticSlicer().analyze("tests/contracts/ReentrancyVault.sol")
    slices = [s for s in analysis.slices if s.function == "withdraw"]
    findings, usage, _ = reasoner.analyze_slices(slices, "tests/contracts/ReentrancyVault.sol")
    assert len(findings) == 1
    assert findings[0].vuln_class == "reentrancy-eth"
    assert usage.total > 0


def test_reasoner_tolerates_garbage_output():
    class Garbage:
        def chat(self, *a, **k):
            return "not json at all", None

    reasoner = LLMReasoner(LLMConfig(provider="mock", model="mock"))
    reasoner.backend = Garbage()
    findings, usage, _ = reasoner.analyze_slices([], "x.sol")
    assert findings == []


def test_mock_llm_flags_value_call_only():
    mock = MockLLM()
    content, _ = mock.chat(
        [
            {
                "role": "user",
                "content": "contract C\n=== SLICE 1 ===\nfunction withdraw\n"
                "external calls: low_level_call -> x [value]\nstate writes: balances",
            }
        ],
        model="m",
        temperature=0,
        max_tokens=100,
    )
    data = json.loads(content)
    assert data["findings"][0]["vuln_class"] == "reentrancy-eth"
