
"""GovernIQ Red Team Lab security evaluation dashboard."""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from findings import generate_findings
from run_eval import run_evaluation
from report_writer import write_reports


ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
CASES_FILE = ROOT / "test_cases" / "cases.json"

st.set_page_config(
    page_title="GovernIQ Red Team Lab",
    page_icon="🛡️",
    layout="wide",
)

st.title("GovernIQ Red Team Lab")
st.caption(
    "Adversarial evaluation for an authorized governance gateway. "
    "Findings are rule-based triage signals, not proof of exploitability."
)


def display_percent(value):
    """Format an optional percentage."""
    return f"{value}%" if value is not None else "N/A"


def load_test_cases():
    """Load the configured test corpus safely."""
    try:
        with CASES_FILE.open("r", encoding="utf-8") as file:
            cases = json.load(file)

        if not isinstance(cases, list):
            raise ValueError("The test corpus must be a JSON list.")

        return cases

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        st.error(f"Could not load the test corpus: {exc}")
        return []


# Run evaluation
if st.button("Run live evaluation", type="primary"):
    try:
        with st.spinner("Evaluating test cases against the configured gateway..."):
            results, metrics = run_evaluation()
            findings = generate_findings(results)

            report_paths = write_reports(
                results=results,
                metrics=metrics,
                reports_dir=REPORTS,
            )

        st.session_state["results"] = results
        st.session_state["metrics"] = metrics
        st.session_state["findings"] = findings

        st.success(
            f"Evaluation completed: {len(results)} cases, "
            f"{len(findings)} findings."
        )

    except Exception as exc:
        st.error(f"Evaluation failed: {exc}")


# Initial screen
if "results" not in st.session_state:
    st.info(
        "Run an evaluation to populate the dashboard. "
        "Configure GOVERNIQ_API_URL and, if required, "
        "GOVERNIQ_API_KEY in your .env file."
    )

    cases = load_test_cases()

    if cases:
        st.subheader("Test corpus preview")
        preview = pd.DataFrame(cases)

        columns = [
            column
            for column in [
                "id",
                "category",
                "description",
                "mode",
                "expected",
            ]
            if column in preview.columns
        ]

        st.dataframe(
            preview[columns],
            use_container_width=True,
            hide_index=True,
        )


# Results screen
else:
    results = st.session_state["results"]
    metrics = st.session_state["metrics"]
    findings = st.session_state.get("findings", [])

    st.header("Evaluation overview")

    columns = st.columns(4)

    columns[0].metric(
        "Test cases",
        metrics.get("total_cases", len(results)),
    )
    columns[1].metric(
        "Decision match rate",
        display_percent(metrics.get("decision_match_rate_pct")),
    )
    columns[2].metric(
        "Attack success rate",
        display_percent(metrics.get("attack_success_rate_pct")),
    )
    columns[3].metric(
        "False-positive rate",
        display_percent(metrics.get("false_positive_rate_pct")),
    )

    st.subheader("Evaluation health")

    health_columns = st.columns(3)

    health_columns[0].metric(
        "Valid responses",
        metrics.get("valid_responses", 0),
    )
    health_columns[1].metric(
        "Evaluation errors",
        metrics.get("errors", 0),
    )
    health_columns[2].metric(
        "Adversarial cases",
        metrics.get("adversarial_cases", 0),
    )

    # Security findings
    st.header("Security findings")
    st.caption(
        "Findings are generated from evaluation outcomes using "
        "configured rules. An empty list means no configured rule "
        "was triggered; it does not prove the system is secure."
    )

    severity_order = ["Critical", "High", "Medium", "Low"]

    severity_counts = {
        severity: sum(
            finding.get("severity") == severity
            for finding in findings
        )
        for severity in severity_order
    }

    severity_columns = st.columns(4)

    for column, severity in zip(severity_columns, severity_order):
        column.metric(
            f"{severity} findings",
            severity_counts[severity],
        )

    if findings:
        findings_df = pd.DataFrame(findings)

        st.subheader("Findings and remediation")

        finding_columns = [
            "case_id",
            "severity",
            "title",
            "description",
            "observed_result",
            "recommendation",
        ]

        st.dataframe(
            findings_df[finding_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download findings CSV",
            data=findings_df.to_csv(index=False).encode("utf-8"),
            file_name="governiq_security_findings.csv",
            mime="text/csv",
        )

        findings_json = json.dumps(
            findings,
            indent=2,
            ensure_ascii=False,
        )

        st.download_button(
            "Download findings JSON",
            data=findings_json.encode("utf-8"),
            file_name="governiq_security_findings.json",
            mime="application/json",
        )

    else:
        st.success(
            "No findings were generated by the current rules "
            "for this evaluation."
        )

    # Case filters
    st.header("Case results")

    df = pd.DataFrame(results)

    if df.empty:
        st.warning("The evaluation returned no test results.")
    else:
        for column, default in [
            ("category", "uncategorized"),
            ("actual", "UNKNOWN"),
        ]:
            if column not in df.columns:
                df[column] = default

        if "match" not in df.columns:
            df["match"] = False

        filter_columns = st.columns(3)

        categories = sorted(
            df["category"].fillna("uncategorized").astype(str).unique()
        )
        decisions = sorted(
            df["actual"].fillna("UNKNOWN").astype(str).unique()
        )

        selected_category = filter_columns[0].selectbox(
            "Category",
            ["All"] + categories,
        )

        selected_decision = filter_columns[1].selectbox(
            "Actual decision",
            ["All"] + decisions,
        )

        selected_match = filter_columns[2].selectbox(
            "Expected-decision match",
            ["All", "Match", "Mismatch"],
        )

        filtered = df.copy()

        if selected_category != "All":
            filtered = filtered[
                filtered["category"].fillna("uncategorized").astype(str)
                == selected_category
            ]

        if selected_decision != "All":
            filtered = filtered[
                filtered["actual"].fillna("UNKNOWN").astype(str)
                == selected_decision
            ]

        if selected_match == "Match":
            filtered = filtered[filtered["match"] == True]  # noqa: E712
        elif selected_match == "Mismatch":
            filtered = filtered[filtered["match"] == False]  # noqa: E712

        result_columns = [
            column
            for column in [
                "id",
                "category",
                "mode",
                "expected",
                "actual",
                "match",
                "attack_success",
                "response_reason",
            ]
            if column in filtered.columns
        ]

        st.dataframe(
            filtered[result_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download filtered results CSV",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="governiq_red_team_results.csv",
            mime="text/csv",
        )

        full_report = {
            "metrics": metrics,
            "results": results,
            "findings": findings,
        }

        st.download_button(
            "Download full evaluation JSON",
            data=json.dumps(
                full_report,
                indent=2,
                ensure_ascii=False,
            ).encode("utf-8"),
            file_name="governiq_red_team_report.json",
            mime="application/json",
        )

    st.warning(
        "An ALLOW decision on an adversarial case is a potential finding "
        "to investigate, not proof of exploitability. Passing this test "
        "corpus does not establish security."
    )
