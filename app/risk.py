"""
Risk scoring engine for ASM-Lite.

Scope for role #4:
- Convert scan evidence into risk_score, risk_level, priority(P1-P4), SLA and reasons.
- Inputs are intentionally plain dict/list objects so the module stays testable.
- The function calculate_risk() is kept for backward compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from app.risk_policy_config import RISK_POLICY
from app.ssvc import determine_response_action


def _policy_int_map(name: str) -> dict[int, int]:
    return {int(k): int(v) for k, v in (RISK_POLICY.get(name) or {}).items()}


def _policy_float_map(name: str) -> dict[int, float]:
    return {int(k): float(v) for k, v in (RISK_POLICY.get(name) or {}).items()}


# Port exposure scoring. These are not CVE scores; they represent exposure risk.
PORT_RISK_SCORE: dict[int, int] = _policy_int_map("ports")

ADMIN_PORTS = {int(x) for x in RISK_POLICY.get("admin_ports", [])}
DATABASE_PORTS = {int(x) for x in RISK_POLICY.get("database_ports", [])}
LEGACY_OR_CLEAR_TEXT_PORTS = {int(x) for x in RISK_POLICY.get("legacy_or_clear_text_ports", [])}

SEVERITY_SCORE: dict[str, int] = {str(k).lower(): int(v) for k, v in (RISK_POLICY.get("severity_score") or {}).items()}
CRITICALITY_MULTIPLIER: dict[int, float] = _policy_float_map("criticality_multiplier")
PRIORITY_SLA_HOURS = {str(k): int(v) for k, v in (RISK_POLICY.get("priority_sla_hours") or {}).items()}

# Policy guardrails for service-version based CVE candidates.
# Nmap/NVD matching is useful for prioritization, but it is not a verified
# exploit finding. Keep it below validated nuclei/KEV evidence.
_CANDIDATE_POLICY = RISK_POLICY.get("candidate_guardrails", {}) or {}
NMAP_NVD_CANDIDATE_SCORE_CAP = int(_CANDIDATE_POLICY.get("score_cap", 35))
NMAP_NVD_PROMOTION_SCORE_CAP = int(_CANDIDATE_POLICY.get("promotion_score_cap", 89))
NMAP_NVD_DEFAULT_CONFIDENCE = float(_CANDIDATE_POLICY.get("nmap_nvd_default_confidence", 0.65))
CANDIDATE_SOURCES = {str(x).lower() for x in _CANDIDATE_POLICY.get("candidate_sources", ["nmap_nvd"])}
VALIDATED_SOURCES = {str(x).lower() for x in _CANDIDATE_POLICY.get("validated_sources", ["nuclei", "manual", "verified"])}


@dataclass
class Reason:
    category: str
    severity: str
    score: int
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "score": int(self.score),
            "message": self.message,
        }


def _get_value(row: Any, key: str, default: Any = None) -> Any:
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return getattr(row, key, default)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(str(value).strip()))
    except Exception:
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(str(value).strip())
    except Exception:
        return default


def _weighted_score(score: int, confidence: float) -> int:
    """Apply confidence to candidate evidence while preserving validated evidence."""
    try:
        conf = float(confidence)
    except Exception:
        conf = 1.0
    conf = max(0.0, min(conf, 1.0))
    if score <= 0:
        return 0
    return max(1, int(round(score * conf)))


def _scale_reasons_to_cap(reasons: list[Reason], cap: int) -> list[Reason]:
    """Scale a candidate evidence reason set so its total score does not exceed cap."""
    total = sum(max(0, int(r.score)) for r in reasons)
    if total <= cap or total <= 0:
        return reasons

    scaled: list[Reason] = []
    remaining = cap
    scored_indices = [i for i, r in enumerate(reasons) if int(r.score) > 0]
    last_scored = scored_indices[-1] if scored_indices else -1
    ratio = cap / float(total)

    for i, reason in enumerate(reasons):
        score = int(reason.score)
        if score <= 0:
            scaled.append(reason)
            continue
        if i == last_scored:
            adjusted = max(0, remaining)
        else:
            adjusted = max(1, int(round(score * ratio)))
            adjusted = min(adjusted, remaining)
            remaining -= adjusted
        scaled.append(
            Reason(
                reason.category,
                reason.severity,
                adjusted,
                f"{reason.message} [policy-adjusted from +{score}; candidate evidence cap +{cap}]",
            )
        )
    return scaled


def _split_cves(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        raw = []
        for item in value:
            raw.extend(_split_cves(item))
        return sorted(set(raw))
    text = str(value).replace(";", ",").replace(" ", ",")
    cves = [x.strip().upper() for x in text.split(",") if x.strip().upper().startswith("CVE-")]
    return sorted(set(cves))


def score_cvss(cvss: Any) -> int:
    """Convert CVSS base score into an operational score contribution.

    Thresholds follow the official CVSS severity bands; point values are
    project policy values documented in risk_policy.md / risk_policy_config.py.
    """
    value = _as_float(cvss, 0.0)
    policy = RISK_POLICY.get("cvss_score", {}) or {}
    if value >= float(policy.get("critical_min", 9.0)):
        return int(policy.get("critical_points", 40))
    if value >= float(policy.get("high_min", 7.0)):
        return int(policy.get("high_points", 30))
    if value >= float(policy.get("medium_min", 4.0)):
        return int(policy.get("medium_points", 15))
    if value > 0.0:
        return int(policy.get("low_points", 5))
    return 0


def score_epss(epss: Any) -> int:
    """Convert EPSS probability into an operational score contribution."""
    value = _as_float(epss, 0.0)
    policy = RISK_POLICY.get("epss_score", {}) or {}
    if value >= float(policy.get("very_high_min", 0.70)):
        return int(policy.get("very_high_points", 35))
    if value >= float(policy.get("high_min", 0.30)):
        return int(policy.get("high_points", 20))
    if value >= float(policy.get("medium_min", 0.10)):
        return int(policy.get("medium_points", 10))
    if value > 0.0:
        return int(policy.get("low_points", 3))
    return 0


def score_epss_percentile(percentile: Any) -> int:
    """Convert EPSS percentile into a small supporting score contribution."""
    value = _as_float(percentile, 0.0)
    policy = RISK_POLICY.get("epss_percentile", {}) or {}
    if value >= float(policy.get("very_high_min", 0.95)):
        return int(policy.get("very_high_points", 20))
    if value >= float(policy.get("high_min", 0.90)):
        return int(policy.get("high_points", 12))
    if value >= float(policy.get("medium_min", 0.80)):
        return int(policy.get("medium_points", 5))
    return 0


def grade(score: int) -> str:
    score = _as_int(score, 0)
    levels = RISK_POLICY.get("risk_levels", {}) or {}
    if score >= int(levels.get("critical_min", 90)):
        return "Critical"
    if score >= int(levels.get("high_min", 70)):
        return "High"
    if score >= int(levels.get("medium_min", 30)):
        return "Medium"
    return "Low"


def priority_from_score(
    score: int,
    max_cvss: float = 0.0,
    max_epss: float = 0.0,
    kev_count: int = 0,
    max_epss_percentile: float = 0.0,
) -> str:
    score = _as_int(score, 0)
    max_cvss = _as_float(max_cvss, 0.0)
    max_epss = _as_float(max_epss, 0.0)
    max_epss_percentile = _as_float(max_epss_percentile, 0.0)
    kev_count = _as_int(kev_count, 0)
    policy = RISK_POLICY.get("priority", {}) or {}
    kev_policy = RISK_POLICY.get("kev", {}) or {}

    if score >= int(policy.get("p1_score_min", 90)):
        return "P1"
    if kev_count > 0 and (
        max_epss >= float(kev_policy.get("p1_epss_min", 0.10))
        or max_cvss >= float(kev_policy.get("p1_cvss_min", 7.0))
    ):
        return "P1"
    # CVSS+EPSS can promote to P1, but only when the combined score is
    # already high enough. This prevents unvalidated service-version CVE
    # candidates from becoming P1 on their own.
    if (
        score >= int(policy.get("p1_combo_score_min", 80))
        and max_cvss >= float(policy.get("p1_cvss_min", 9.0))
        and max_epss >= float(policy.get("p1_epss_min", 0.70))
    ):
        return "P1"
    if score >= int(policy.get("p2_score_min", 70)):
        return "P2"
    if max_cvss >= float(policy.get("p2_cvss_min", 7.0)) and (
        max_epss >= float(policy.get("p2_epss_min", 0.30))
        or max_epss_percentile >= float(policy.get("p2_percentile_min", 0.95))
    ):
        return "P2"
    if score >= int(policy.get("p3_score_min", 30)):
        return "P3"
    return "P4"


def _change_type(change: Any) -> tuple[str, str]:
    if isinstance(change, dict):
        ctype = str(change.get("type") or change.get("change_type") or "")
        detail = str(change.get("detail") or change.get("message") or "")
        return ctype, detail
    text = str(change)
    ctype, _, detail = text.partition(":")
    return ctype, detail


def _port_reason(port: int, service: str, product: str) -> Reason | None:
    base = PORT_RISK_SCORE.get(port, 2)
    label = f"{port}/tcp"
    if service:
        label += f" {service}"
    if product:
        label += f" {product}"

    severity = "info"
    if base >= 45:
        severity = "high"
    elif base >= 25:
        severity = "medium"
    elif base >= 10:
        severity = "low"

    return Reason("port", severity, base, f"Exposed service detected: {label} (+{base})")


def calculate_risk_detail(
    ports: Iterable[Any],
    findings: Iterable[Any],
    changes: Iterable[Any] | None = None,
    criticality: int = 3,
) -> dict[str, Any]:
    """
    Calculate enterprise-style risk detail.

    Returns a dict with:
    - score: 0~100
    - level: Low/Medium/High/Critical
    - priority: P1~P4
    - sla_hours: recommended remediation SLA
    - max_cvss, max_epss, kev_count
    - reasons: explainable score contributions
    """
    reasons: list[Reason] = []
    raw_score = 0
    max_cvss = 0.0
    max_epss = 0.0
    max_epss_percentile = 0.0
    kev_count = 0

    seen_ports: set[int] = set()
    for row in ports or []:
        port = _as_int(_get_value(row, "port", 0), 0)
        if not port or port in seen_ports:
            continue
        seen_ports.add(port)

        service = str(_get_value(row, "service", "") or "")
        product = str(_get_value(row, "product", "") or "")
        version = str(_get_value(row, "version", "") or "")
        cpe = str(_get_value(row, "cpe", "") or "")

        reason = _port_reason(port, service, product)
        if reason:
            reasons.append(reason)
            raw_score += reason.score

        if port in ADMIN_PORTS:
            reasons.append(Reason("exposure", "medium", 15, f"Administrative service exposed externally on port {port} (+15)"))
            raw_score += 15
        if port in DATABASE_PORTS:
            reasons.append(Reason("exposure", "high", 25, f"Database/infrastructure service exposed externally on port {port} (+25)"))
            raw_score += 25
        if port in LEGACY_OR_CLEAR_TEXT_PORTS:
            reasons.append(Reason("exposure", "medium", 15, f"Legacy or clear-text service exposed on port {port} (+15)"))
            raw_score += 15
        if version:
            reasons.append(Reason("service", "info", 2, f"Service version identified for port {port}: {version} (+2)"))
            raw_score += 2
        if cpe:
            reasons.append(Reason("service", "info", 3, f"CPE fingerprint available for port {port}: {cpe} (+3)"))
            raw_score += 3

    seen_findings: set[str] = set()
    nmap_nvd_candidate_reasons: list[Reason] = []
    nmap_nvd_candidate_score = 0
    has_nmap_nvd_candidate = False
    has_validated_vulnerability = False

    for finding in findings or []:
        template_id = str(_get_value(finding, "template_id", "") or "")
        target = str(_get_value(finding, "target", "") or "")
        matched_at = str(_get_value(finding, "matched_at", "") or "")
        key = str(_get_value(finding, "dedupe_key", "") or "") or f"{template_id}|{target}|{matched_at}"
        if key in seen_findings:
            continue
        seen_findings.add(key)

        severity = str(_get_value(finding, "severity", "info") or "info").lower()
        source = str(_get_value(finding, "source", "nuclei") or "nuclei").lower()
        default_confidence = NMAP_NVD_DEFAULT_CONFIDENCE if source in CANDIDATE_SOURCES else 1.0
        confidence = _as_float(_get_value(finding, "confidence", default_confidence), default_confidence)
        is_candidate = source in CANDIDATE_SOURCES
        evidence_label = "Nmap/NVD service CVE candidate" if is_candidate else "Nuclei finding"

        target_reasons = nmap_nvd_candidate_reasons if is_candidate else reasons

        def add_finding_reason(reason: Reason) -> None:
            nonlocal raw_score, nmap_nvd_candidate_score
            target_reasons.append(reason)
            if is_candidate:
                nmap_nvd_candidate_score += int(reason.score)
            else:
                raw_score += int(reason.score)

        sev_score = _weighted_score(SEVERITY_SCORE.get(severity, 0), confidence)
        if sev_score:
            add_finding_reason(Reason(source, severity, sev_score, f"{evidence_label} severity={severity}: {template_id or target} (+{sev_score}, confidence={confidence:.2f})"))

        cvss = _as_float(_get_value(finding, "cvss_score", 0), 0.0)
        epss = _as_float(_get_value(finding, "epss_score", 0), 0.0)
        epss_percentile = _as_float(_get_value(finding, "epss_percentile", 0), 0.0)
        kev = bool(_get_value(finding, "kev", False) or _get_value(finding, "is_kev", False))
        cve_text = _get_value(finding, "cve_id", "") or _get_value(finding, "cve", "")
        cves = _split_cves(cve_text)

        if is_candidate and (cves or cvss > 0 or epss > 0):
            has_nmap_nvd_candidate = True
        if (not is_candidate) and source in VALIDATED_SOURCES and (cves or cvss > 0 or epss > 0 or kev) and severity in {"medium", "high", "critical"}:
            has_validated_vulnerability = True

        max_cvss = max(max_cvss, cvss)
        max_epss = max(max_epss, epss)
        max_epss_percentile = max(max_epss_percentile, epss_percentile)

        cvss_score = _weighted_score(score_cvss(cvss), confidence)
        if cvss_score:
            cve_label = ",".join(cves) if cves else template_id
            add_finding_reason(Reason("cvss", "high" if cvss >= 7 else "medium", cvss_score, f"CVSS {cvss:.1f} for {cve_label} (+{cvss_score}, confidence={confidence:.2f})"))

        epss_score = _weighted_score(score_epss(epss), confidence)
        if epss_score:
            cve_label = ",".join(cves) if cves else template_id
            add_finding_reason(Reason("epss", "high" if epss >= 0.30 else "medium", epss_score, f"EPSS {epss:.4f} exploitation probability for {cve_label} (+{epss_score}, confidence={confidence:.2f})"))

        epss_pct_score = _weighted_score(score_epss_percentile(epss_percentile), confidence)
        if epss_pct_score:
            cve_label = ",".join(cves) if cves else template_id
            add_finding_reason(Reason("epss_percentile", "high" if epss_percentile >= 0.95 else "medium", epss_pct_score, f"EPSS percentile {epss_percentile:.4f} for {cve_label} (+{epss_pct_score}, confidence={confidence:.2f})"))

        if kev:
            kev_count += 1
            cve_label = ",".join(cves) if cves else template_id
            kev_score = _weighted_score(40, confidence)
            add_finding_reason(Reason("kev", "critical", kev_score, f"{cve_label} is listed in CISA KEV catalog (+{kev_score}, confidence={confidence:.2f})"))

    if nmap_nvd_candidate_score:
        if nmap_nvd_candidate_score > NMAP_NVD_CANDIDATE_SCORE_CAP:
            adjusted_candidate_reasons = _scale_reasons_to_cap(nmap_nvd_candidate_reasons, NMAP_NVD_CANDIDATE_SCORE_CAP)
            adjusted_total = sum(int(r.score) for r in adjusted_candidate_reasons)
            reasons.extend(adjusted_candidate_reasons)
            reasons.append(
                Reason(
                    "policy",
                    "info",
                    0,
                    f"Nmap/NVD service-version CVE candidate evidence capped at +{NMAP_NVD_CANDIDATE_SCORE_CAP} because it is not a validated vulnerability (+0)",
                )
            )
            raw_score += adjusted_total
        else:
            reasons.extend(nmap_nvd_candidate_reasons)
            raw_score += nmap_nvd_candidate_score

    for change in changes or []:
        ctype, detail = _change_type(change)
        if ctype == "new_open_port":
            port = _as_int(detail, 0)
            bonus = 20
            sev = "high" if port in DATABASE_PORTS or port in ADMIN_PORTS or port in {23, 445} else "medium"
            if port in DATABASE_PORTS or port in ADMIN_PORTS or port in {23, 445}:
                bonus = 35
            reasons.append(Reason("change", sev, bonus, f"New exposed port detected: {detail or port} (+{bonus})"))
            raw_score += bonus
        elif ctype == "service_changed":
            reasons.append(Reason("change", "medium", 10, f"Service fingerprint changed: {detail} (+10)"))
            raw_score += 10
        elif ctype == "new_finding":
            reasons.append(Reason("change", "high", 30, f"New vulnerability finding detected: {detail} (+30)"))
            raw_score += 30
        elif ctype == "baseline_created":
            # First scan: not a vulnerability by itself.
            reasons.append(Reason("change", "info", 0, "Baseline scan created; future scans will detect drift (+0)"))

    criticality_int = min(max(_as_int(criticality, 3), 1), 5)
    multiplier = CRITICALITY_MULTIPLIER.get(criticality_int, 1.0)
    adjusted = int(round(raw_score * multiplier))
    score = min(max(adjusted, 0), 100)

    # If a scan becomes Critical only due to unvalidated nmap/NVD candidate
    # evidence, keep it at High/P2 until a validated nuclei finding or KEV
    # confirms the vulnerability.
    if has_nmap_nvd_candidate and not has_validated_vulnerability and kev_count == 0 and score >= 90:
        score = min(score, NMAP_NVD_PROMOTION_SCORE_CAP)
        reasons.append(
            Reason(
                "policy",
                "info",
                0,
                f"Candidate-only Nmap/NVD evidence cannot promote a target above {NMAP_NVD_PROMOTION_SCORE_CAP}/High without validated CVE or KEV evidence (+0)",
            )
        )

    level = grade(score)
    priority = priority_from_score(score, max_cvss=max_cvss, max_epss=max_epss, kev_count=kev_count, max_epss_percentile=max_epss_percentile)
    ssvc_action = determine_response_action(
        priority,
        kev_count=kev_count,
        has_validated_vulnerability=has_validated_vulnerability,
        has_candidate_vulnerability=has_nmap_nvd_candidate,
        max_cvss=max_cvss,
        max_epss=max_epss,
        max_epss_percentile=max_epss_percentile,
    )

    if multiplier != 1.0:
        reasons.append(
            Reason(
                "asset_criticality",
                "info",
                0,
                f"Asset criticality={criticality_int} multiplier applied: x{multiplier:.2f}",
            )
        )

    top_reasons = sorted(reasons, key=lambda r: r.score, reverse=True)
    return {
        "score": score,
        "raw_score": raw_score,
        "level": level,
        "priority": priority,
        "sla_hours": PRIORITY_SLA_HOURS.get(priority, 30 * 24),
        "max_cvss": round(max_cvss, 2),
        "max_epss": round(max_epss, 6),
        "max_epss_percentile": round(max_epss_percentile, 6),
        "kev_count": kev_count,
        "ssvc_action": ssvc_action,
        "has_validated_vulnerability": has_validated_vulnerability,
        "has_candidate_vulnerability": has_nmap_nvd_candidate,
        "criticality": criticality_int,
        "criticality_multiplier": multiplier,
        "reasons": [r.as_dict() for r in top_reasons],
    }


def calculate_risk(ports: list[dict], findings: list[dict], changes: list[str], criticality: int = 3) -> int:
    """Backward compatible score-only function used by existing code."""
    return int(calculate_risk_detail(ports, findings, changes, criticality).get("score", 0))
