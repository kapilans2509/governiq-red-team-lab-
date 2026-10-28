
"""Run the test corpus against the configured governance gateway."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from client import evaluate_case
from metrics import calculate_metrics
from report_writer import write_reports


ROOT = Path(__file__).resolve().parent
CASES_FILE = ROOT / "test_cases" / "cases.json"
REPORTS = ROOT / "reports"

VALID_DECISIONS = {"ALLOW", "DENY", "REVIEW"}
BLOCKED_EXPECTATIONS = {"DENY", "REVIEW"}


def run_evaluation() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Evaluate every configured case and calculate metrics."""

    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))

    if not isinstance(cases, list):
        raise ValueError("The test corpus must be a JSON list.")

    results: list[dict[str, Any]] = []

    for case in cases:
        row: dict[str, Any] = {
            **case,
            "run_at_utc": datetime.now(timezone.utc).isoformat(),
        }

        try:
            response = evaluate_case(case)

            if not isinstance(response, dict):
                raise ValueError(
                    "Gateway response was not a JSON object."
                )

            decision = str(response.get("decision", "")).upper()

            row["actual"] = (
                decision if decision in VALID_DECISIONS else "ERROR"
            )

            row["response_reason"] = str(
                response.get(
                    "reason",
                    response.get("message", ""),
                )
            )[:1000]

            row["http_status"] = response.get("http_status")
            row["error_type"] = response.get("error_type")

            if row["actual"] == "ERROR" and not row["error_type"]:
                row["error_type"] = "InvalidDecision"

        except Exception as exc:
            row["actual"] = "ERROR"
            row["response_reason"] = (
                f"{type(exc).__name__}: {exc}"
            )[:1000]
            row["http_status"] = None
            row["error_type"] = type(exc).__name__

        expected = str(row.get("expected", "")).upper()
        actual = row["actual"]
        is_adversarial = row.get("adversarial") is True

        # A decision match measures agreement with the test expectation.
        row["match"] = (
            actual == expected
            if actual in VALID_DECISIONS
            else None
        )

        # Count an attack as successful when an adversarial case
        # expected DENY/REVIEW but the gateway returned ALLOW.
        row["attack_success"] = bool(
            is_adversarial
            and expected in BLOCKED_EXPECTATIONS
            and actual == "ALLOW"
        )

        # Explicitly preserve the test classification for reporting.
        row["adversarial"] = is_adversarial

        results.append(row)

    metrics = calculate_metrics(results)
    return results, metrics


def main() -> None:
    """Run evaluation, write reports, and print summary metrics."""

    results, metrics = run_evaluation()

    paths = write_reports(
        results=results,
        metrics=metrics,
        reports_dir=REPORTS,
    )

    print(json.dumps(metrics, indent=2))

    print("\nReports written:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    if metrics.get("errors", 0):
        print(
            "\nSome cases did not return valid decisions. "
            "Check gateway availability, authentication, timeouts, "
            "HTTP status codes, and response formats."
        )

    successful_attacks = [
        row for row in results if row["attack_success"]
    ]

    if successful_attacks:
        print("\nPotential successful adversarial cases:")
        for row in successful_attacks:
            print(
                f"  {row['id']}: expected={row['expected']}, "
                f"actual={row['actual']}"
            )


if __name__ == "__main__":
    main()
