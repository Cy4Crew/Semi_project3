import json
import subprocess
from pathlib import Path

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


def run_nuclei(host: str, ports: list[int], scan_id: int) -> list[dict]:
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
        findings.append(
            {
                "target": item.get("host", ""),
                "template_id": item.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "info"),
                "matched_at": item.get("matched-at", ""),
                "description": info.get("description", ""),
            }
        )
    return findings
