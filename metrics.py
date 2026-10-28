
from typing import Any

VALID_DECISIONS = {"ALLOW", "DENY", "REVIEW"}
BLOCKED_EXPECTATIONS = {"DENY", "REVIEW"}


def calculate_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)

    valid_results = [
        r for r in results
        if str(r.get("actual", "")).upper() in VALID_DECISIONS
    ]
    errors = total - len(valid_results)

    matches = sum(
        str(r.get("actual", "")).upper()
        == str(r.get("expected", "")).upper()
        for r in valid_results
    )

    attacks = [r for r in results if r.get("adversarial") is True]
    valid_attacks = [
        r for r in attacks
        if str(r.get("actual", "")).upper() in VALID_DECISIONS
    ]

    attack_successes = sum(
        str(r.get("actual", "")).upper() == "ALLOW"
        and str(r.get("expected", "")).upper() in BLOCKED_EXPECTATIONS
        for r in valid_attacks
    )

    baseline = [
        r for r in results
        if r.get("adversarial") is False
        and str(r.get("expected", "")).upper() == "ALLOW"
    ]
    valid_baseline = [
        r for r in baseline
        if str(r.get("actual", "")).upper() in VALID_DECISIONS
    ]

    false_positives = sum(
        str(r.get("actual", "")).upper() in BLOCKED_EXPECTATIONS
        for r in valid_baseline
    )

    pct = lambda numerator, denominator: (
        round(numerator / denominator * 100, 2)
        if denominator else None
    )

    return {
        "total_cases": total,
        "valid_responses": len(valid_results),
        "errors": errors,
        "error_rate_pct": pct(errors, total),
        "decision_matches": matches,
        "decision_match_rate_pct": pct(matches, len(valid_results)),
        "adversarial_cases": len(attacks),
        "valid_adversarial_responses": len(valid_attacks),
        "attack_successes": attack_successes,
        "attack_success_rate_pct": pct(
            attack_successes, len(valid_attacks)
        ),
        "baseline_allow_cases": len(baseline),
        "valid_baseline_responses": len(valid_baseline),
        "baseline_errors": len(baseline) - len(valid_baseline),
        "false_positives": false_positives,
        "false_positive_rate_pct": pct(
            false_positives, len(valid_baseline)
        ),
    }
