
"""Rule-based security findings for GovernIQ evaluation results."""

from typing import Any


def generate_findings(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert evaluation results into actionable security findings."""

    findings: list[dict[str, Any]] = []

    for row in results:
        case_id = str(row.get("id", "UNKNOWN"))
        category = str(row.get("category", "uncategorized"))
        expected = str(row.get("expected", "")).upper()
        actual = str(row.get("actual", "")).upper()
        reason = str(row.get("response_reason", "No reason provided."))
        error = row.get("error") or row.get("error_type")
        attack_success = row.get("attack_success") is True

        def add_finding(
            severity: str,
            title: str,
            description: str,
            recommendation: str,
        ) -> None:
            findings.append(
                {
                    "case_id": case_id,
                    "category": category,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "observed_result": (
                        f"Expected: {expected or 'N/A'}; "
                        f"Actual: {actual or 'N/A'}"
                    ),
                    "response_reason": reason,
                    "recommendation": recommendation,
                }
            )

        # A confirmed test-defined attack success takes priority.
        if attack_success or (
            category != "baseline_allow"
            and expected in {"DENY", "REVIEW"}
            and actual == "ALLOW"
        ):
            add_finding(
                "Critical",
                "Potential adversarial policy bypass",
                "An adversarial test received ALLOW when a restrictive "
                "decision was expected. Investigate whether the request "
                "bypassed the intended controls.",
                "Reproduce the case, inspect gateway policy enforcement "
                "and tool permissions, then add a regression test.",
            )
            continue

        # Errors make the security result inconclusive.
        if error or actual not in {"ALLOW", "DENY", "REVIEW"}:
            add_finding(
                "High",
                "Evaluation result is unreliable",
                "The case returned an error or an invalid decision. "
                "Its security outcome cannot be trusted.",
                "Inspect the HTTP status, gateway logs, response schema, "
                "timeouts and authentication configuration; rerun the case.",
            )
            continue

        # A benign test was unexpectedly blocked or escalated.
        if expected == "ALLOW" and actual in {"DENY", "REVIEW"}:
            add_finding(
                "Medium",
                "Potential false positive",
                "A baseline case expected to be allowed was denied "
                "or routed for review.",
                "Check the policy rules and confirm that legitimate "
                "requests remain usable without weakening security controls.",
            )
            continue

        # Decision mismatches that did not allow the adversarial request.
        if expected and actual != expected:
            add_finding(
                "Medium",
                "Unexpected policy decision",
                "The gateway decision differs from the expected decision. "
                "This may indicate policy inconsistency.",
                "Review the expected outcome and gateway policy, then "
                "document the intended behavior in a regression test.",
            )

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
    }
    findings.sort(
        key=lambda finding: severity_order[finding["severity"]]
    )

    return findings
