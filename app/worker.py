import asyncio
from datetime import datetime

from app.database import get_conn, safe_execute
from app.scanner import tcp_scan
from app.nmap_runner import run_nmap
from app.nuclei_runner import run_nuclei
from app.diff import detect_changes
from app.risk import calculate_risk
from app.alerts import send_alert
from app.web_enrichment import run_web_enrichment_sync
from app.recommendations import build_recommendations
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = BASE_DIR / 'app' / 'static' / 'screenshots'

def update_job_progress(job_id: int, progress: int, stage: str, message: str):
    try:
        safe_execute(
            "UPDATE scan_jobs SET progress = ?, stage = ?, message = ? WHERE id = ?",
            (progress, stage, message, job_id),
        )
    except Exception:
        pass


def update_job_status(job_id: int, status: str, message: str, scan_id: int | None = None, progress: int = 100, stage: str = "done"):
    safe_execute(
        "UPDATE scan_jobs SET status = ?, message = ?, scan_id = ?, progress = ?, stage = ? WHERE id = ?",
        (status, message, scan_id, progress, stage, job_id),
    )



async def run_scan_job(job_id: int) -> int:
    conn = get_conn()
    job = conn.execute(
        "SELECT scan_jobs.*, targets.value, targets.criticality FROM scan_jobs JOIN targets ON scan_jobs.target_id = targets.id WHERE scan_jobs.id = ?",
        (job_id,),
    ).fetchone()
    if not job:
        conn.close()
        raise ValueError("scan job not found")

    target_id = int(job["target_id"])
    target_value = job["value"]
    criticality = int(job["criticality"] or 3)

    now = datetime.utcnow().isoformat(timespec="seconds")
    conn.execute(
        "UPDATE scan_jobs SET status = 'running', started_at = ?, message = ?, progress = 10, stage = ? WHERE id = ?",
        (now, "scan started", "starting", job_id),
    )
    cur = conn.execute(
        "INSERT INTO scans(target_id, status, summary) VALUES (?, 'running', ?)",
        (target_id, f"job_id={job_id}"),
    )
    scan_id = cur.lastrowid
    conn.execute("UPDATE scan_jobs SET scan_id = ? WHERE id = ?", (scan_id, job_id))
    conn.commit()
    conn.close()

    try:
        update_job_progress(job_id, 20, "tcp_scan", "running TCP scan")

        open_ports = await tcp_scan(target_value)
        update_job_progress(job_id, 40, "nmap", "running nmap service detection")

        nmap_rows = await asyncio.to_thread(run_nmap, target_value, open_ports, scan_id)

        if not nmap_rows:
            nmap_rows = [
                {
                    "port": p,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "unknown",
                    "product": "",
                    "version": "",
                    "cpe": "",
                    "source": "tcp",
                }
                for p in open_ports
            ]

        conn = get_conn()
        for row in nmap_rows:
            conn.execute(
                """
                INSERT INTO ports(scan_id, port, protocol, state, service, product, version, cpe, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    row["port"],
                    row.get("protocol", "tcp"),
                    row.get("state", "open"),
                    row.get("service", ""),
                    row.get("product", ""),
                    row.get("version", ""),
                    row.get("cpe", ""),
                    row.get("source", ""),
                ),
            )
        conn.commit()
        conn.close()

        update_job_progress(job_id, 65, "nuclei", "running nuclei scan")

        nuclei_findings = await asyncio.to_thread(
            run_nuclei,
            target_value,
            [int(r["port"]) for r in nmap_rows],
            scan_id,
        )

        conn = get_conn()
        seen = set()
        for finding in nuclei_findings:
            key = (
                finding.get("dedupe_key")
                or f"{finding.get('template_id', '')}|{finding.get('target', '')}|{finding.get('matched_at', '')}"
            )
            if key in seen:
                continue
            seen.add(key)
            conn.execute(
                """
                INSERT INTO findings(scan_id, target, template_id, name, severity, matched_at, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding.get("target", ""),
                    finding.get("template_id", ""),
                    finding.get("name", ""),
                    finding.get("severity", ""),
                    finding.get("matched_at", ""),
                    finding.get("description", ""),
                ),
            )
        conn.commit()
        conn.close()

        
        update_job_progress(job_id, 82, "enrichment", "running web enrichment")

        tech_rows, screenshot_rows = await asyncio.to_thread(
            run_web_enrichment_sync,
            target_value,
            [int(r["port"]) for r in nmap_rows],
            scan_id,
            SCREENSHOT_DIR,
        )

        recommendations = build_recommendations(nmap_rows, nuclei_findings)

        conn = get_conn()
        for tech in tech_rows:
            conn.execute(
                "INSERT INTO tech_detections(scan_id, url, technology, evidence) VALUES (?, ?, ?, ?)",
                (scan_id, tech.get("url", ""), tech.get("technology", ""), tech.get("evidence", "")),
            )
        for shot in screenshot_rows:
            conn.execute(
                "INSERT INTO screenshots(scan_id, url, path, status, error) VALUES (?, ?, ?, ?, ?)",
                (scan_id, shot.get("url", ""), shot.get("path", ""), shot.get("status", ""), shot.get("error", "")),
            )
        for rec in recommendations:
            conn.execute(
                "INSERT INTO recommendations(scan_id, severity, title, recommendation, source) VALUES (?, ?, ?, ?, ?)",
                (scan_id, rec.get("severity", ""), rec.get("title", ""), rec.get("recommendation", ""), rec.get("source", "")),
            )
        conn.commit()
        conn.close()

        changes = detect_changes(target_id, scan_id)

        conn = get_conn()
        for change in changes:
            if isinstance(change, dict):
                change_type = change.get("type") or change.get("change_type") or "change"
                detail = change.get("detail", "")
            else:
                change_type, _, detail = str(change).partition(":")
            conn.execute(
                "INSERT INTO changes(scan_id, change_type, detail) VALUES (?, ?, ?)",
                (scan_id, change_type, detail),
            )

        update_job_progress(job_id, 95, "finalizing", "calculating risk and finalizing report")

        risk_score = calculate_risk(nmap_rows, nuclei_findings, changes, criticality)
        if risk_score >= 70:
            await send_alert(
                f"High risk scan result: {target_value}",
                f"Risk score={risk_score}, open_ports={len(nmap_rows)}, findings={len(nuclei_findings)}",
                "high",
            )

        finished = datetime.utcnow().isoformat(timespec="seconds")
        summary = f"open_ports={len(nmap_rows)}, findings={len(seen)}, tech={len(tech_rows)}, screenshots={len(screenshot_rows)}, recommendations={len(recommendations)}, changes={len(changes)}"

        screenshot_errors = [s for s in screenshot_rows if s.get("status") in {"failed", "skipped"}]
        scan_status = "partial_success" if screenshot_errors else "done"
        job_status = scan_status
        status_message = f"completed: {summary}"
        if screenshot_errors:
            status_message += "; screenshot capture skipped/failed"

        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ?, risk_score = ?, summary = ? WHERE id = ?",
            (scan_status, finished, risk_score, summary, scan_id),
        )
        conn.execute(
            "UPDATE scan_jobs SET status = ?, finished_at = ?, message = ?, scan_id = ?, progress = 100, stage = ? WHERE id = ?",
            (job_status, finished, status_message, scan_id, "done", job_id),
        )
        conn.commit()
        conn.close()
        return int(scan_id)

    except Exception as exc:
        finished = datetime.utcnow().isoformat(timespec="seconds")
        conn = get_conn()
        port_count = conn.execute("SELECT COUNT(*) c FROM ports WHERE scan_id = ?", (scan_id,)).fetchone()["c"]
        finding_count = conn.execute("SELECT COUNT(*) c FROM findings WHERE scan_id = ?", (scan_id,)).fetchone()["c"]
        recoverable_status = "partial_success" if port_count or finding_count else "failed"
        message = f"{recoverable_status}: {str(exc)}"
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ?, summary = ? WHERE id = ?",
            (recoverable_status, finished, message, scan_id),
        )
        conn.execute(
            "UPDATE scan_jobs SET status = ?, finished_at = ?, message = ?, scan_id = ?, progress = 100, stage = ? WHERE id = ?",
            (recoverable_status, finished, message, scan_id, recoverable_status, job_id),
        )
        conn.commit()
        conn.close()
        return int(scan_id)
