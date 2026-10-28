from metrics import calculate_metrics


def test_metrics_calculate_rates():
    results = [
        {"actual": "ALLOW", "expected": "ALLOW", "adversarial": False},
        {"actual": "ALLOW", "expected": "DENY", "adversarial": True},
        {"actual": "DENY", "expected": "DENY", "adversarial": True},
        {"actual": "REVIEW", "expected": "ALLOW", "adversarial": False},
    ]
    metrics = calculate_metrics(results)
    assert metrics["total_cases"] == 4
    assert metrics["decision_match_rate_pct"] == 50.0
    assert metrics["attack_success_rate_pct"] == 50.0
    assert metrics["false_positive_rate_pct"] == 50.0


def test_metrics_empty_results():
    metrics = calculate_metrics([])
    assert metrics["total_cases"] == 0
    assert metrics["decision_match_rate_pct"] is None
