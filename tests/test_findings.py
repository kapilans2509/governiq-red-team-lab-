
from findings import generate_findings


def test_successful_adversarial_attack_is_critical():
    results = [
        {
            "id": "ADV-001",
            "category": "prompt_injection",
            "expected": "DENY",
            "actual": "ALLOW",
            "attack_success": True,
            "response_reason": "Request allowed.",
        }
    ]

    findings = generate_findings(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["case_id"] == "ADV-001"
    assert "bypass" in findings[0]["title"].lower()


def test_baseline_false_positive_is_medium():
    results = [
        {
            "id": "BASE-001",
            "category": "baseline_allow",
            "expected": "ALLOW",
            "actual": "DENY",
            "attack_success": False,
            "response_reason": "Unexpected denial.",
        }
    ]

    findings = generate_findings(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert "false positive" in findings[0]["title"].lower()


def test_successful_evaluation_has_no_findings():
    results = [
        {
            "id": "BASE-001",
            "category": "baseline_allow",
            "expected": "ALLOW",
            "actual": "ALLOW",
            "attack_success": False,
            "response_reason": "Policy checks passed.",
        },
        {
            "id": "ADV-001",
            "category": "prompt_injection",
            "expected": "DENY",
            "actual": "DENY",
            "attack_success": False,
            "response_reason": "Threat signal detected.",
        },
    ]

    assert generate_findings(results) == []


def test_findings_are_sorted_by_severity():
    results = [
        {
            "id": "BASE-001",
            "category": "baseline_allow",
            "expected": "ALLOW",
            "actual": "DENY",
            "attack_success": False,
        },
        {
            "id": "ADV-001",
            "category": "prompt_injection",
            "expected": "DENY",
            "actual": "ALLOW",
            "attack_success": True,
        },
    ]

    findings = generate_findings(results)

    assert [f["severity"] for f in findings] == [
        "Critical",
        "Medium",
    ]
