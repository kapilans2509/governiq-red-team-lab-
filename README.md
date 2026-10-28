# GovernIQ Red Team Lab

A small, reproducible evaluation harness for testing an AI-tool governance API you own or are authorized to assess. It compares expected decisions with actual decisions and exports evidence to CSV/JSON.

## What it tests
- Allowed baseline requests
- Requests that should be denied or sent for review
- Prompt-injection-style text
- Attempts to request sensitive information
- Approval-state assumptions (reported as a test, not proof of a secure approval workflow)

**Important:** The current gateway uses simulated tools and pattern-based policies. Passing this suite is not proof of security. The suite measures behavior against the supplied test cases only. Run against systems you own or have permission to test.

## Setup (Windows PowerShell)
```powershell
cd F:\AI-Safety-Portfolio\governiq-red-team-lab
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `GOVERNIQ_API_URL` to your gateway URL. If your gateway requires an API key, set `GOVERNIQ_API_KEY` locally. Do not commit secrets.

## Run the evaluation
```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe run_eval.py
.\.venv\Scripts\streamlit.exe run dashboard.py
```

Reports are written to `reports/` as CSV and JSON. The dashboard can also run in local-only demo mode if the API is unavailable.

## Metrics
- **Decision match rate:** cases whose actual decision equals the expected decision.
- **Attack success rate:** adversarial cases that were allowed when their expected outcome was DENY or REVIEW. This is a test-suite metric, not a universal security score.
- **False-positive rate:** baseline cases expected to ALLOW that instead received DENY or REVIEW.

## Expected API shape
`POST /evaluate` JSON body:
```json
{"tool":"read_public_record","input":"Summarize public information","mode":"Standard","session_id":"redteam-001","approved":false}
```
The runner expects a JSON response containing a `decision` field with `ALLOW`, `DENY`, or `REVIEW`. Adjust `client.py` if your API contract changes.
## Screenshots

### Evaluation Dashboard
![GovernIQ Dashboard](screenshots/dashboard.png)

### Live Governance Playground
![GovernIQ Playground](screenshots/playground.png)

### Red Team Evaluation Results
![Red Team Results](screenshots/reports.png)
