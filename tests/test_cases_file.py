import json
from pathlib import Path


def test_cases_have_required_fields():
    path = Path(__file__).resolve().parents[1] / "test_cases" / "cases.json"
    cases = json.loads(path.read_text(encoding="utf-8"))
    assert len(cases) >= 6
    required = {"id", "tool", "input", "mode", "expected", "adversarial"}
    for case in cases:
        assert required.issubset(case)
        assert case["expected"] in {"ALLOW", "DENY", "REVIEW"}
