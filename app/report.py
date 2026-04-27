from pathlib import Path
from app.database import get_conn
from app.risk import grade

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)


def generate_report(scan_id: int) -> Path:
    conn = get_conn()
    scan = conn.execute(
        "SELECT scans.*, targets.value, targets.label FROM scans JOIN targets ON scans.target_id = targets.id WHERE scans.id = ?",
        (scan_id,),
    ).fetchone()
    ports = conn.execute("SELECT * FROM ports WHERE scan_id = ? ORDER BY port", (scan_id,)).fetchall()
    findings = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    changes = conn.execute("SELECT * FROM changes WHERE scan_id = ?", (scan_id,)).fetchall()
    tech_rows = conn.execute("SELECT * FROM tech_detections WHERE scan_id = ?", (scan_id,)).fetchall()
    screenshots = conn.execute("SELECT * FROM screenshots WHERE scan_id = ?", (scan_id,)).fetchall()
    recommendations = conn.execute("SELECT * FROM recommendations WHERE scan_id = ?", (scan_id,)).fetchall()
    conn.close()
    if not scan:
        raise ValueError("scan not found")
    path = REPORT_DIR / f"scan_{scan_id}_report.md"
    lines = [
        f"# ASM-Lite Scan Report #{scan_id}",
        "",
        f"- Target: `{scan['value']}`",
        f"- Label: {scan['label']}",
        f"- Status: {scan['status']}",
        "- Note: partial_success means core scan data was saved but an optional enrichment step was skipped or failed." if scan['status'] == 'partial_success' else "",
        f"- Risk Score: {scan['risk_score']} ({grade(int(scan['risk_score']))})",
        f"- Started At: {scan['started_at']}",
        f"- Finished At: {scan['finished_at']}",
        "",
        "## Open Ports",
        "",
        "| Port | Service | Product | Version | CPE | Source |",
        "|---:|---|---|---|---|---|",
    ]
    for p in ports:
        lines.append(f"| {p['port']} | {p['service']} | {p['product']} | {p['version']} | {p['cpe']} | {p['source']} |")
    lines += ["", "## Changes", ""]
    for c in changes:
        lines.append(f"- {c['change_type']}: {c['detail']}")
    lines += ["", "## Nuclei Findings", "", "| Severity | Template | Name | Target |", "|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f['severity']} | {f['template_id']} | {f['name']} | {f['target']} |")
    lines += ["", "## Technology Detection", "", "| URL | Technology | Evidence |", "|---|---|---|"]
    for t in tech_rows:
        lines.append(f"| {t['url']} | {t['technology']} | {t['evidence']} |")

    lines += ["", "## Screenshots", ""]
    for s in screenshots:
        lines.append(f"- {s['url']} - {s['status']} - {s['path'] or s['error']}")

    lines += ["", "## Remediation Recommendations", ""]
    for rec in recommendations:
        lines.append(f"- **[{rec['severity']}] {rec['title']}**: {rec['recommendation']}")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
