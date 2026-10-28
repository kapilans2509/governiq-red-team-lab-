
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from client import evaluate_case
from metrics import calculate_metrics
from run_eval import run_evaluation

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
CASES_FILE = ROOT / "test_cases" / "cases.json"
API_URL = "https://governiq-agent-governance.onrender.com"

st.set_page_config(
    page_title="GovernIQ | AI Governance",
    page_icon="🛡️",
    layout="wide",
)

st.title("GovernIQ")
st.caption("AI Agent Governance and Adversarial Security Evaluation")

dashboard_tab, playground_tab, reports_tab = st.tabs(
    ["Dashboard", "Live Playground", "Reports"]
)

# ---------------- DASHBOARD ----------------

with dashboard_tab:
    st.subheader("Red Team Evaluation")

    if st.button("Run live evaluation", type="primary"):
        with st.spinner("Evaluating test cases against GovernIQ..."):
            results, metrics = run_evaluation()

            REPORTS.mkdir(exist_ok=True)
            df = pd.DataFrame(results)
            df.to_csv(REPORTS / "latest_results.csv", index=False)

            report = {
                "metrics": metrics,
                "results": results,
            }
            (REPORTS / "latest_summary.json").write_text(
                json.dumps(report, indent=2),
                encoding="utf-8",
            )

            st.session_state["results"] = results
            st.session_state["metrics"] = metrics

    if "metrics" not in st.session_state:
        summary_path = REPORTS / "latest_summary.json"

        if summary_path.exists():
            try:
                saved = json.loads(
                    summary_path.read_text(encoding="utf-8")
                )
                st.session_state["metrics"] = saved.get(
                    "metrics", saved
                )
                st.session_state["results"] = saved.get("results", [])
            except (ValueError, OSError):
                st.warning("Could not read the saved summary report.")

    metrics = st.session_state.get("metrics", {})
    results = st.session_state.get("results", [])

    if metrics:
        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Test Cases", metrics.get("total_cases", 0))
        c2.metric(
            "Decision Agreement",
            f"{metrics.get('decision_match_rate_pct', 0)}%",
        )
        c3.metric(
            "Attack Success Rate",
            f"{metrics.get('attack_success_rate_pct', 0)}%",
        )
        c4.metric(
            "API Errors",
            metrics.get("errors", 0),
        )

        c5, c6, c7 = st.columns(3)
        c5.metric(
            "Adversarial Cases",
            metrics.get("adversarial_cases", 0),
        )
        c6.metric(
            "Successful Attacks",
            metrics.get("attack_successes", 0),
        )
        c7.metric(
            "False Positive Rate",
            f"{metrics.get('false_positive_rate_pct', 0)}%",
        )

        if results:
            df = pd.DataFrame(results)

            st.subheader("Decision Distribution")
            if "actual" in df.columns:
                counts = df["actual"].value_counts()
                st.bar_chart(counts)

            st.subheader("Recent Evaluation Results")
            columns = [
                c for c in [
                    "id", "category", "mode", "expected",
                    "actual", "match", "response_reason"
                ] if c in df.columns
            ]
            st.dataframe(
                df[columns],
                width="stretch",
                hide_index=True,
            )
    else:
        st.info(
            "No saved metrics found. Select 'Run live evaluation' "
            "to evaluate the test suite."
        )

    st.caption(
        "Metrics describe the configured test suite only; "
        "they do not prove complete real-world security."
    )

# ---------------- LIVE PLAYGROUND ----------------

with playground_tab:
    st.subheader("Test a Prompt")
    st.write(
        "Submit a prompt to the deployed GovernIQ API. "
        "The gateway evaluates the request and returns a decision."
    )

    with st.form("governance_form"):
        tool = st.selectbox(
            "Tool",
            [
                "search_policy",
                "read_status",
                "draft_report",
                "shell_exec",
                "delete_database",
                "send_external_data",
            ],
        )

        prompt = st.text_area(
            "Prompt",
            placeholder="Example: Find public information about AI governance policy.",
            height=140,
        )

        mode = st.selectbox(
            "Governance Mode",
            ["Open", "Standard", "Strict", "Locked"],
            index=1,
        )

        approved = st.checkbox(
            "Approval has been granted for this request"
        )

        submitted = st.form_submit_button(
            "Evaluate Request",
            type="primary",
        )

    if submitted:
        if not prompt.strip():
            st.warning("Enter a prompt before submitting.")
        else:
            case = {
                "id": "playground",
                "tool": tool,
                "input": prompt.strip(),
                "mode": mode,
                "approved": approved,
            }

            with st.spinner("Contacting GovernIQ..."):
                result = evaluate_case(case, base_url=API_URL)

            decision = result.get("decision", "ERROR")

            if decision == "ALLOW":
                st.success("Decision: ALLOW")
            elif decision == "REVIEW":
                st.warning("Decision: REVIEW")
            elif decision == "DENY":
                st.error("Decision: DENY")
            else:
                st.error("The gateway request failed.")

            st.write("**Reason**")
            st.write(result.get("reason", "No reason returned."))

            st.write("**Response details**")
            st.json(result)

            if decision == "ALLOW":
                st.info(
                    "ALLOW means the gateway permitted this request. "
                    "It does not mean the underlying action was executed."
                )

# ---------------- REPORTS ----------------

with reports_tab:
    st.subheader("Evaluation Reports")

    csv_path = REPORTS / "latest_results.csv"
    json_path = REPORTS / "latest_summary.json"

    if csv_path.exists():
        try:
            df = pd.read_csv(csv_path)
            st.dataframe(df, width="stretch", hide_index=True)

            st.download_button(
                "Download CSV Results",
                data=csv_path.read_bytes(),
                file_name="governiq_results.csv",
                mime="text/csv",
            )
        except (ValueError, OSError) as exc:
            st.error(f"Could not read CSV report: {exc}")
    else:
        st.info("No CSV report found. Run the evaluation first.")

    if json_path.exists():
        st.download_button(
            "Download JSON Summary",
            data=json_path.read_bytes(),
            file_name="governiq_summary.json",
            mime="application/json",
        )
