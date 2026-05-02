"""
Risk policy configuration for ASM-Lite.

This module keeps operational scoring constants outside the main risk engine.
A JSON override can be placed at config/risk_policy.json or passed by the
ASM_RISK_POLICY_PATH environment variable. No external YAML dependency is used.
"""
from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_RISK_POLICY: dict[str, Any] = {
    "ports": {
        "20": 15,
        "21": 25,
        "22": 15,
        "23": 55,
        "25": 10,
        "53": 8,
        "80": 5,
        "110": 15,
        "135": 25,
        "139": 30,
        "143": 10,
        "443": 5,
        "445": 45,
        "1433": 40,
        "1521": 40,
        "2375": 65,
        "2376": 35,
        "3306": 40,
        "3389": 50,
        "5432": 40,
        "5900": 40,
        "6379": 45,
        "8000": 8,
        "8080": 10,
        "8443": 10,
        "9200": 45,
        "11211": 45,
        "27017": 45,
    },
    "admin_ports": [22, 3389, 5900, 8080, 8443, 10000, 2375, 2376],
    "database_ports": [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017],
    "legacy_or_clear_text_ports": [21, 23, 110, 143],
    "severity_score": {
        "info": 0,
        "unknown": 0,
        "low": 5,
        "medium": 15,
        "high": 35,
        "critical": 60,
    },
    "criticality_multiplier": {
        "1": 0.80,
        "2": 0.90,
        "3": 1.00,
        "4": 1.20,
        "5": 1.40,
    },
    "cvss_score": {
        "critical_min": 9.0,
        "high_min": 7.0,
        "medium_min": 4.0,
        "critical_points": 40,
        "high_points": 30,
        "medium_points": 15,
        "low_points": 5,
    },
    "epss_score": {
        "very_high_min": 0.70,
        "high_min": 0.30,
        "medium_min": 0.10,
        "very_high_points": 35,
        "high_points": 20,
        "medium_points": 10,
        "low_points": 3,
    },
    "epss_percentile": {
        "very_high_min": 0.95,
        "high_min": 0.90,
        "medium_min": 0.80,
        "very_high_points": 20,
        "high_points": 12,
        "medium_points": 5,
    },
    "kev": {
        "points": 40,
        "p1_cvss_min": 7.0,
        "p1_epss_min": 0.10,
    },
    "candidate_guardrails": {
        "nmap_nvd_default_confidence": 0.65,
        "score_cap": 35,
        "promotion_score_cap": 89,
        "validated_sources": ["nuclei", "manual", "verified"],
        "candidate_sources": ["nmap_nvd", "banner_nvd", "service_nvd"],
    },
    "priority_sla_hours": {
        "P1": 24,
        "P2": 72,
        "P3": 336,
        "P4": 720,
    },
    "risk_levels": {
        "critical_min": 90,
        "high_min": 70,
        "medium_min": 30,
    },
    "priority": {
        "p1_score_min": 90,
        "p1_cvss_min": 9.0,
        "p1_epss_min": 0.70,
        "p1_combo_score_min": 80,
        "p2_score_min": 70,
        "p2_cvss_min": 7.0,
        "p2_epss_min": 0.30,
        "p2_percentile_min": 0.95,
        "p3_score_min": 30,
    },
    "ssvc": {
        "actions": {
            "P1": "immediate",
            "P2": "out-of-cycle",
            "P3": "scheduled",
            "P4": "track",
        }
    },
}


def _deep_update(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def _policy_path() -> Path:
    custom = os.getenv("ASM_RISK_POLICY_PATH", "").strip()
    if custom:
        return Path(custom)
    return BASE_DIR / "config" / "risk_policy.json"


def load_risk_policy() -> dict[str, Any]:
    policy = deepcopy(DEFAULT_RISK_POLICY)
    path = _policy_path()
    if path.exists():
        try:
            override = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(override, dict):
                _deep_update(policy, override)
        except Exception:
            # Runtime should never fail because a policy file is malformed.
            pass
    return policy


RISK_POLICY = load_risk_policy()
