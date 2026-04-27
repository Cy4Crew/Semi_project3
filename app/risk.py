EXPOSED_PORT_SCORE = {
    21: 15,
    23: 45,
    25: 10,
    53: 5,
    80: 5,
    110: 15,
    135: 20,
    139: 20,
    143: 10,
    443: 5,
    445: 35,
    1433: 30,
    1521: 30,
    2375: 60,
    2376: 35,
    3306: 25,
    3389: 40,
    5432: 25,
    5900: 30,
    6379: 35,
    9200: 30,
    11211: 35,
    27017: 30,
}

SEVERITY_SCORE = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 35,
    "critical": 60,
}


def _get_value(row, key, default=None):
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default


def calculate_risk(ports: list[dict], findings: list[dict], changes: list[str], criticality: int = 3) -> int:
    score = max(0, int(criticality) - 1) * 5

    seen_ports = set()
    for row in ports:
        port = int(_get_value(row, "port", 0) or 0)
        if port in seen_ports:
            continue
        seen_ports.add(port)

        score += EXPOSED_PORT_SCORE.get(port, 2)

        version = _get_value(row, "version", "")
        cpe = _get_value(row, "cpe", "")
        if version:
            score += 2
        if cpe:
            score += 3

    seen_findings = set()
    for finding in findings:
        template_id = str(_get_value(finding, "template_id", ""))
        target = str(_get_value(finding, "target", ""))
        matched_at = str(_get_value(finding, "matched_at", ""))
        key = str(_get_value(finding, "dedupe_key", "")) or f"{template_id}|{target}|{matched_at}"

        if key in seen_findings:
            continue
        seen_findings.add(key)

        severity = str(_get_value(finding, "severity", "info")).lower()
        score += SEVERITY_SCORE.get(severity, 0)

    for change in changes:
        if isinstance(change, dict):
            change_type = str(change.get("type") or change.get("change_type") or "")
        else:
            change_type = str(change).split(":", 1)[0]

        if change_type == "new_open_port":
            score += 10
        elif change_type == "service_changed":
            score += 5
        elif change_type == "new_finding":
            score += 8

    return min(score, 100)


def grade(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Info"
