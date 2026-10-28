
"""Write consistent timestamped and latest evaluation reports."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_reports(
    results: list[dict[str, Any]],
    metrics: dict[str, Any],
    reports_dir: Path,
) -> dict[str, Path]:
    """Write evaluation results to timestamped and latest CSV/JSON files."""

    reports_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    generated_at = now.isoformat()
    stamp = now.strftime("%Y%m%dT%H%M%S%fZ")

    report = {
        "generated_at_utc": generated_at,
        "metrics": metrics,
        "results": results,
    }

    # Collect every result field in a consistent column order.
    columns = list(dict.fromkeys(
        key for result in results for key in result.keys()
    ))

    paths = {
        "timestamped_csv": reports_dir / f"results_{stamp}.csv",
        "timestamped_json": reports_dir / f"summary_{stamp}.json",
        "latest_csv": reports_dir / "latest_results.csv",
        "latest_json": reports_dir / "latest_summary.json",
    }

    # Write CSV directly so True/False values are preserved explicitly.
    for csv_path in (
        paths["timestamped_csv"],
        paths["latest_csv"],
    ):
        with csv_path.open(
            "w", newline="", encoding="utf-8-sig"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=columns,
                extrasaction="ignore",
            )
            writer.writeheader()

            for result in results:
                row = {}
                for column in columns:
                    value = result.get(column, "")
                    if isinstance(value, bool):
                        value = str(value)
                    elif value is None:
                        value = ""
                    row[column] = value
                writer.writerow(row)

    json_data = json.dumps(
        report, indent=2, ensure_ascii=False
    )

    paths["timestamped_json"].write_text(
        json_data, encoding="utf-8"
    )
    paths["latest_json"].write_text(
        json_data, encoding="utf-8"
    )

    return paths
