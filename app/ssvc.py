"""Small SSVC-inspired response action helper.

This is not a full CISA SSVC implementation. It maps ASM-Lite P1~P4 priority
into practical response actions while considering KEV and validated findings.
"""
from __future__ import annotations

from typing import Any


def determine_response_action(
    priority: str,
    *,
    kev_count: int = 0,
    has_validated_vulnerability: bool = False,
    has_candidate_vulnerability: bool = False,
    max_cvss: float = 0.0,
    max_epss: float = 0.0,
    max_epss_percentile: float = 0.0,
) -> str:
    priority = (priority or "P4").upper()
    if priority == "P1" or kev_count > 0:
        return "immediate"
    if has_validated_vulnerability and (max_cvss >= 7.0 or max_epss >= 0.30 or max_epss_percentile >= 0.95):
        return "out-of-cycle"
    if priority == "P2":
        return "out-of-cycle"
    if has_candidate_vulnerability and (max_cvss >= 7.0 or max_epss_percentile >= 0.90):
        return "scheduled"
    if priority == "P3":
        return "scheduled"
    return "track"


def action_to_korean(action: str) -> str:
    return {
        "immediate": "즉시 조치",
        "out-of-cycle": "우선 조치",
        "scheduled": "계획 조치",
        "track": "관찰/참고",
    }.get(action, "관찰/참고")
