"""Helpers for the Nova-Sonic assistant.

This module centralises the data gathering logic required by the
Nova-Sonic agent.  The agent combines cost, compliance and security
context for the currently selected AWS account so that the language
model can provide grounded responses.

The helpers intentionally avoid any direct dependency on the request
payload so they can be exercised in isolation (for example in tests)
when the surrounding Flask application context is available.
"""

from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import dataclass
from datetime import date
from typing import Any

from flask import current_app, session

from ..models.models import Accounts, Users
from ..py_scripts.s3Connection import download_from_s3
from .compliance import S3_REPORT_PREFIX, generate_reports_data
from .services import (
    fetch_and_cache_billing_data,
    generate_summary_data,
    get_date_ranges,
)


@dataclass(slots=True)
class NovaSonicContext:
    """Collected intelligence for the Nova-Sonic agent."""

    account_alias: str
    cost_summary: dict[str, Any]
    compliance_summary: list[dict[str, Any]]
    security_summary: dict[str, Any]

    def to_prompt_dict(self) -> dict[str, Any]:
        """Return a serialisable representation for prompt construction."""

        return {
            "account_alias": self.account_alias,
            "cost_summary": self.cost_summary,
            "compliance_summary": self.compliance_summary,
            "security_summary": self.security_summary,
        }


def _normalise_prefix(key: str | None) -> tuple[str | None, str]:
    """Return a tuple of ``(key, active_prefix)`` for a stored S3 key."""

    if not key:
        return None, S3_REPORT_PREFIX.rstrip("/") + "/"

    base_prefix = S3_REPORT_PREFIX.rstrip("/") + "/"
    normalised = key if key.startswith(base_prefix) else f"{base_prefix}{key.lstrip('/')}"
    active_prefix = normalised.rsplit("/", 1)[0] + "/" if "/" in normalised else base_prefix
    return normalised, active_prefix


def _gather_cost_summary(account: Accounts) -> dict[str, Any]:
    """Build a consolidated cost picture for *account*."""

    if not all([account.access_key_id, account.secret_access_key, account.default_region_name]):
        return {
            "available": False,
            "details": "Account is missing billing credentials or region information.",
        }

    today = date.today()
    date_ranges = get_date_ranges(today)

    monthly_data = fetch_and_cache_billing_data(
        account.access_key_id,
        account.secret_access_key,
        account.default_region_name,
        date_ranges["monthly_start"],
        date_ranges["end"],
        granularity="MONTHLY",
    ) or []

    daily_data = fetch_and_cache_billing_data(
        account.access_key_id,
        account.secret_access_key,
        account.default_region_name,
        date_ranges["daily_start"],
        date_ranges["end"],
        granularity="DAILY",
    ) or []

    if not monthly_data and not daily_data:
        return {
            "available": False,
            "details": "No cost and usage data was retrieved for the selected date ranges.",
        }

    summary = generate_summary_data(monthly_data, daily_data, date_ranges, today)
    top_services = sorted(
        summary.get("services_breakdown", []),
        key=lambda item: item.get("y", 0),
        reverse=True,
    )[:5]

    return {
        "available": True,
        "total_cost_last_12_months": summary.get("total_cost"),
        "months": summary.get("months", []),
        "monthly_costs": summary.get("monthly_costs", []),
        "mtd_cost": summary.get("mtd_cost"),
        "forecasted_cost": summary.get("forecasted_cost"),
        "last_month_total_cost": summary.get("last_month_total_cost"),
        "last_month_same_period_cost": summary.get("last_month_same_period_cost"),
        "top_services": top_services,
        "highest_service": summary.get("highest_service"),
    }


def _load_compliance_summary(account: Accounts, user: Users) -> list[dict[str, Any]]:
    """Return a compliance overview using cached data when possible."""

    cached = session.get("compliance_report")
    if isinstance(cached, list) and cached:
        return [
            {
                "framework": item.get("finding_name"),
                "total_findings": item.get("total_findings"),
                "passed": item.get("passed"),
                "failed": item.get("failed"),
                "compliance_percentage": item.get("compliance_percentage"),
            }
            for item in cached
        ]

    stored_keys = account.aws_prowler_compliance_report
    if not stored_keys:
        return []

    if not account.s3_bucket:
        return []

    try:
        key_mapping = json.loads(stored_keys)
    except json.JSONDecodeError:
        current_app.logger.warning("Stored compliance report keys are not valid JSON")
        return []

    json_key_raw = key_mapping.get("json_report") if isinstance(key_mapping, dict) else None
    json_key, active_prefix = _normalise_prefix(json_key_raw)
    if not json_key:
        return []

    file_content, error_message, status_code = download_from_s3(
        account.s3_bucket,
        json_key,
        account.id,
        user.id,
        f"{user.id}_{account.alias}",
        aws_access_key_id=getattr(account, "access_key_id", None),
        aws_secret_access_key=getattr(account, "secret_access_key", None),
        aws_session_token=getattr(account, "session_token", None)
        or getattr(account, "aws_session_token", None),
        region=getattr(account, "default_region_name", None),
    )

    if status_code != 200 or not file_content:
        current_app.logger.warning(
            "Unable to fetch compliance report from S3", extra={"error": error_message}
        )
        return []

    try:
        report_data = json.loads(file_content)
    except json.JSONDecodeError:
        current_app.logger.warning("Compliance report JSON could not be decoded")
        return []

    compliance_report = generate_reports_data(
        report_data,
        "prowler_reports",
        account.alias,
        user.id,
        storage_prefix=active_prefix,
    )

    # Cache for later requests within the session for consistency with the
    # compliance view.
    session["compliance_report"] = compliance_report

    return [
        {
            "framework": item.get("finding_name"),
            "total_findings": item.get("total_findings"),
            "passed": item.get("passed"),
            "failed": item.get("failed"),
            "compliance_percentage": item.get("compliance_percentage"),
        }
        for item in compliance_report
    ]


def _decode_security_findings(content: bytes | None) -> list[dict[str, Any]]:
    """Attempt to decode ``content`` that stores security findings JSON."""

    if not content:
        return []

    encodings = ["utf-8", "utf-16", "utf-32", "latin-1"]
    for encoding in encodings:
        try:
            text = content.decode(encoding)
            findings = json.loads(text)
            if isinstance(findings, list):
                return findings
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    return []


def _build_security_summary(account: Accounts, user: Users) -> dict[str, Any]:
    """Return severity totals and highlighted findings."""

    s3_bucket = account.s3_bucket
    if not s3_bucket:
        return {
            "available": False,
            "details": "No S3 bucket is configured for Security Hub findings.",
        }

    key = f"{user.email}~{account.alias}.json"
    file_content, error_message, status_code = download_from_s3(
        s3_bucket,
        key,
        account.id,
        user.id,
        f"{user.id}_{account.alias}",
        aws_access_key_id=getattr(account, "access_key_id", None),
        aws_secret_access_key=getattr(account, "secret_access_key", None),
        aws_session_token=getattr(account, "session_token", None)
        or getattr(account, "aws_session_token", None),
        region=getattr(account, "default_region_name", None),
    )

    if status_code == 404:
        # Attempt to use a locally packaged sample so the agent can still reply.
        try:
            from pathlib import Path

            sample_path = Path(current_app.root_path) / "sample_data" / "sample_vulnerabilities.json"
            file_content = sample_path.read_bytes()
        except OSError:
            file_content = None
    elif status_code != 200:
        current_app.logger.warning(
            "Unable to fetch security findings from S3", extra={"error": error_message}
        )
        return {
            "available": False,
            "details": "Security Hub findings could not be retrieved at this time.",
        }

    findings = _decode_security_findings(file_content)
    if not findings:
        return {
            "available": False,
            "details": "No security findings are available for analysis.",
        }

    severity_counter = Counter()
    for finding in findings:
        severity = str(finding.get("Severity", "UNKNOWN")).upper()
        severity_counter[severity] += 1

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        findings,
        key=lambda item: severity_order.get(str(item.get("Severity", "")).upper(), 99),
    )
    highlights: list[dict[str, Any]] = []
    for finding in sorted_findings[:5]:
        highlights.append(
            {
                "title": finding.get("Title"),
                "resource": finding.get("Resource"),
                "severity": finding.get("Severity"),
                "description": finding.get("Description"),
                "recommendation": finding.get("RecommendationUrl"),
                "last_observed": finding.get("LastObservedAt"),
            }
        )

    return {
        "available": True,
        "total_findings": len(findings),
        "severity_counts": dict(severity_counter),
        "highlights": highlights,
    }


def build_nova_sonic_context(account: Accounts, user: Users) -> NovaSonicContext:
    """Collect contextual data for *account* and *user*.

    The returned :class:`NovaSonicContext` is designed to be fed directly to the
    Nova-Sonic LLM prompt.  All individual sections handle failures
    gracefully, ensuring the agent can still reply with partial data when some
    sources are unavailable.
    """

    cost_summary = _gather_cost_summary(account)
    compliance_summary = _load_compliance_summary(account, user)
    security_summary = _build_security_summary(account, user)

    return NovaSonicContext(
        account_alias=account.alias,
        cost_summary=cost_summary,
        compliance_summary=compliance_summary,
        security_summary=security_summary,
    )


def encode_audio_bytes(chunks: list[bytes]) -> str:
    """Utility for tests – base64 encode audio chunks."""

    return base64.b64encode(b"".join(chunks)).decode("utf-8")

