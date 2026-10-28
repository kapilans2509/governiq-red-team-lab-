
"""HTTP client for the GovernIQ governance gateway."""

import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv(
    "GOVERNIQ_API_URL",
    "https://governiq-agent-governance.onrender.com",
).rstrip("/")

API_KEY = os.getenv("GOVERNIQ_API_KEY", "").strip()
TIMEOUT = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "45"))

VALID_DECISIONS = {"ALLOW", "DENY", "REVIEW"}


def evaluate_case(
    case: dict[str, Any],
    base_url: str = BASE_URL,
) -> dict[str, Any]:
    """Evaluate one test case and preserve transport/API error details."""

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if API_KEY:
        headers["X-API-Key"] = API_KEY

    payload = {
        "tool": case["tool"],
        "input": case["input"],
        "mode": case.get("mode", "Standard"),
        "session_id": f"redteam-{case['id']}",
        "approved": bool(case.get("approved", False)),
    }

    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/evaluate",
            json=payload,
            headers=headers,
            timeout=TIMEOUT,
        )
    except requests.Timeout as exc:
        return {
            "decision": "ERROR",
            "reason": f"Request timed out after {TIMEOUT:g} seconds",
            "error_type": type(exc).__name__,
            "http_status": None,
        }
    except requests.RequestException as exc:
        return {
            "decision": "ERROR",
            "reason": str(exc)[:1000],
            "error_type": type(exc).__name__,
            "http_status": None,
        }

    status = response.status_code

    try:
        data = response.json()
    except ValueError:
        return {
            "decision": "ERROR",
            "reason": (
                f"Gateway returned non-JSON content "
                f"(HTTP {status})"
            ),
            "http_status": status,
        }

    if not response.ok:
        reason = (
            data.get("detail", data.get("message", ""))
            if isinstance(data, dict)
            else str(data)
        )
        return {
            "decision": "ERROR",
            "reason": f"HTTP {status}: {str(reason)[:900]}",
            "http_status": status,
        }

    if not isinstance(data, dict):
        return {
            "decision": "ERROR",
            "reason": "Gateway response was not a JSON object",
            "http_status": status,
        }

    decision = str(data.get("decision", "")).upper()

    if decision not in VALID_DECISIONS:
        return {
            "decision": "ERROR",
            "reason": (
                "Gateway response contained a missing or "
                "unrecognized decision"
            ),
            "http_status": status,
        }

    return {
        **data,
        "decision": decision,
        "http_status": status,
    }
