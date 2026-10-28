
import json

import pandas as pd

from report_writer import write_reports


def test_all_reports_use_the_same_evaluation_data(tmp_path):
    results = [
        {
            "id": "BASE-001",
            "expected": "ALLOW",
            "actual": "ALLOW",
            "match": True,
            "attack_success": False,
        },
        {
            "id": "ADV-001",
            "expected": "DENY",
            "actual": "DENY",
            "match": True,
            "attack_success": False,
        },
    ]

    metrics = {
        "total_cases": 2,
        "decision_matches": 2,
        "decision_match_rate_pct": 100.0,
        "attack_successes": 0,
    }

    paths = write_reports(results, metrics, tmp_path)

    # All four artifacts should exist.
    assert len(paths) == 4
    assert all(path.exists() for path in paths.values())

    latest_csv = pd.read_csv(paths["latest_csv"])
    timestamped_csv = pd.read_csv(paths["timestamped_csv"])

    latest_json = json.loads(paths["latest_json"].read_text("utf-8"))
    timestamped_json = json.loads(
        paths["timestamped_json"].read_text("utf-8")
    )

    assert latest_csv.to_dict("records") == timestamped_csv.to_dict("records")
    assert latest_json["metrics"] == metrics
    assert timestamped_json["metrics"] == metrics
    assert latest_json["results"] == timestamped_json["results"]
    assert latest_json["results"] == results


def test_latest_reports_are_replaced_on_each_run(tmp_path):
    first = [{"id": "BASE-001", "actual": "ALLOW"}]
    second = [{"id": "ADV-001", "actual": "DENY"}]

    write_reports(first, {"total_cases": 1}, tmp_path)
    paths = write_reports(second, {"total_cases": 1}, tmp_path)

    latest_json = json.loads(paths["latest_json"].read_text("utf-8"))
    latest_csv = pd.read_csv(paths["latest_csv"])

    assert latest_json["results"] == second
    assert latest_csv["id"].tolist() == ["ADV-001"]
