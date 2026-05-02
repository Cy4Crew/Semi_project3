import json
import subprocess
from pathlib import Path
from typing import Any

from app.cve_api import extract_cve_ids

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000, 9000}


def build_web_targets(host: str, ports: list[int]) -> list[str]:
    urls = []
    for port in ports:
        if port not in WEB_PORTS:
            continue
        scheme = "https" if port in {443, 8443} else "http"
        if port in {80, 443}:
            urls.append(f"{scheme}://{host}")
        else:
            urls.append(f"{scheme}://{host}:{port}")
    return urls


def _first_non_empty(*values: Any, default: Any = "") -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


def _cvss_from_classification(classification: dict) -> float:
    for key in ("cvss-score", "cvss_score", "cvss", "cvss-score-v3", "cvss_score_v3"):
        value = classification.get(key)
        if value not in (None, ""):
            try:
                return float(value)
            except Exception:
                continue
    return 0.0


def _normalize_cve_text(value: Any, fallback_text: str = "") -> str:
    cves = extract_cve_ids(value)
    if not cves and fallback_text:
        cves = extract_cve_ids(fallback_text)
    return ",".join(cves)


def run_nuclei(host: str, ports: list[int], scan_id: int) -> list[dict]:
    DATA_DIR.mkdir(exist_ok=True)
    targets = build_web_targets(host, ports)
    if not targets:
        return []

    target_file = DATA_DIR / f"nuclei_targets_{scan_id}.txt"
    output_file = DATA_DIR / f"nuclei_scan_{scan_id}.jsonl"
    target_file.write_text("\n".join(targets), encoding="utf-8")

    cmd = ["nuclei", "-l", str(target_file), "-jsonl", "-o", str(output_file), "-silent"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if not output_file.exists():
        return []

    findings = []
    for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        description = info.get("description", "") or ""
        name = info.get("name", "") or ""
        cve_value = _first_non_empty(
            classification.get("cve-id"),
            classification.get("cve_id"),
            classification.get("cve"),
            info.get("tags"),
            default="",
        )
        cve_id = _normalize_cve_text(cve_value, fallback_text=f"{name} {description}")
        cvss_score = _cvss_from_classification(classification)

        template_id = item.get("template-id", "")
        target = item.get("host", "") or item.get("matched-at", "")
        matched_at = item.get("matched-at", "") or target
        dedupe_key = f"{template_id}|{target}|{matched_at}|{cve_id}"

        findings.append(
            {
                "target": target,
                "template_id": template_id,
                "name": name,
                "severity": info.get("severity", "info"),
                "matched_at": matched_at,
                "description": description,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "epss_score": 0.0,
                "kev": False,
                "dedupe_key": dedupe_key,
            }
        )
    return findings
