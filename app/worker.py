import asyncio
from datetime import datetime, timedelta

from app.database import get_conn, safe_execute
from app.scanner import tcp_scan
from app.nmap_runner import run_nmap
from app.nuclei_runner import run_nuclei
from app.diff import detect_changes
from app.risk import calculate_risk_detail, score_cvss, score_epss, score_epss_percentile, SEVERITY_SCORE
from app.cve_api import enrich_findings_with_intel, query_nvd, query_epss_batch, is_cisa_kev
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



def _build_service_keywords(nmap_rows: list[dict], limit: int = 5) -> list[str]:
    """Build conservative NVD keyword queries from nmap service fingerprints."""
    generic_products = {"", "unknown", "tcpwrapped"}
    keywords: list[str] = []
    seen: set[str] = set()

    for row in nmap_rows or []:
        product = str(row.get("product") or "").strip()
        version = str(row.get("version") or "").strip()
        service = str(row.get("service") or "").strip()

        if product.lower() in generic_products:
            continue

        # Versionless keyword searches are too noisy. Require product+version.
        keyword = f"{product} {version}".strip()
        if not version or len(keyword) < 4:
            continue

        if keyword.lower() not in seen:
            keywords.append(keyword)
            seen.add(keyword.lower())

        # Add a fallback service+product+version keyword for common ambiguous banners.
        if service and service.lower() not in product.lower():
            keyword2 = f"{service} {product} {version}".strip()
            if keyword2.lower() not in seen:
                keywords.append(keyword2)
                seen.add(keyword2.lower())

        if len(keywords) >= limit:
            break

    return keywords[:limit]


async def enrich_service_cves_from_nmap(nmap_rows: list[dict]) -> list[dict]:
    """
    Build CVE candidate findings from nmap service/version fingerprints.

    These are candidate enrichment findings, not validated exploit findings.
    They are marked source=nmap_nvd and confidence=0.65 so the risk engine
    reflects uncertainty and does not overstate keyword search results.
    """
    keywords = _build_service_keywords(nmap_rows, limit=5)
    if not keywords:
        return []

    try:
        nvd_results = await asyncio.gather(
            *(query_nvd(keyword, limit=3) for keyword in keywords),
            return_exceptions=True,
        )
    except Exception:
        return []

    cve_rows: list[tuple[str, str, dict]] = []
    cve_ids: list[str] = []
    for keyword, rows in zip(keywords, nvd_results):
        if isinstance(rows, Exception):
            continue
        for row in rows or []:
            cve_id = str(row.get("cve") or "").upper()
            if not cve_id.startswith("CVE-"):
                continue
            cve_rows.append((keyword, cve_id, row))
            cve_ids.append(cve_id)

    if not cve_rows:
        return []

    try:
        epss_map = await asyncio.to_thread(query_epss_batch, cve_ids)
    except Exception:
        epss_map = {}

    enriched: list[dict] = []
    seen: set[str] = set()
    for keyword, cve_id, row in cve_rows:
        key = f"nmap_nvd|{keyword}|{cve_id}"
        if key in seen:
            continue
        seen.add(key)
        cvss = float(row.get("score") or 0.0)
        epss = float(epss_map.get(cve_id, {}).get("epss") or 0.0)
        epss_percentile = float(epss_map.get(cve_id, {}).get("percentile") or 0.0)
        enriched.append(
            {
                "target": keyword,
                "template_id": "nmap-nvd-service-cve",
                "name": f"Service/version CVE candidate: {cve_id}",
                "severity": str(row.get("severity") or "unknown").lower(),
                "matched_at": keyword,
                "description": str(row.get("title") or "")[:500],
                "cve_id": cve_id,
                "cvss_score": cvss,
                "epss_score": epss,
                "epss_percentile": epss_percentile,
                "kev": is_cisa_kev(cve_id),
                "source": "nmap_nvd",
                "confidence": 0.65,
                "dedupe_key": key,
            }
        )

    return enriched


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
        nuclei_findings = await asyncio.to_thread(enrich_findings_with_intel, nuclei_findings)

        # Role #4 Risk Scoring enrichment:
        # If nuclei does not return CVE IDs, use nmap service/version fingerprints
        # to query NVD and enrich risk scoring with CVSS/EPSS candidate context.
        try:
            service_cve_findings = await enrich_service_cves_from_nmap(nmap_rows)
        except Exception:
            service_cve_findings = []
        if service_cve_findings:
            nuclei_findings.extend(service_cve_findings)

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
            sev = str(finding.get("severity", "info") or "info").lower()
            cvss = float(finding.get("cvss_score") or 0)
            epss = float(finding.get("epss_score") or 0)
            epss_percentile = float(finding.get("epss_percentile") or 0)
            finding_priority_score = min(
                int(SEVERITY_SCORE.get(sev, 0) + score_cvss(cvss) + score_epss(epss) + score_epss_percentile(epss_percentile) + (40 if finding.get("kev") else 0)),
                100,
            )
            if finding_priority_score >= 90 or (cvss >= 9 and epss >= 0.7) or finding.get("kev"):
                finding_priority_level = "P1"
            elif finding_priority_score >= 70:
                finding_priority_level = "P2"
            elif finding_priority_score >= 40:
                finding_priority_level = "P3"
            else:
                finding_priority_level = "P4"

            conn.execute(
                """
                INSERT INTO findings(
                    scan_id, target, template_id, name, severity, matched_at, description,
                    cve_id, cvss_score, epss_score, kev, priority_score, priority_level,
                    epss_percentile, source, confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding.get("target", ""),
                    finding.get("template_id", ""),
                    finding.get("name", ""),
                    finding.get("severity", ""),
                    finding.get("matched_at", ""),
                    finding.get("description", ""),
                    finding.get("cve_id", ""),
                    cvss,
                    epss,
                    1 if finding.get("kev") else 0,
                    finding_priority_score,
                    finding_priority_level,
                    epss_percentile,
                    finding.get("source", ""),
                    float(finding.get("confidence") or 1.0),
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

        risk_detail = calculate_risk_detail(nmap_rows, nuclei_findings, changes, criticality)
        risk_score = int(risk_detail["score"])
        risk_level = str(risk_detail["level"])
        priority_level = str(risk_detail["priority"])
        sla_hours = int(risk_detail.get("sla_hours") or 0)

        conn.execute("DELETE FROM risk_reasons WHERE scan_id = ?", (scan_id,))
        for reason in risk_detail.get("reasons", []):
            conn.execute(
                """
                INSERT INTO risk_reasons(scan_id, category, severity, score_delta, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    reason.get("category", ""),
                    reason.get("severity", ""),
                    int(reason.get("score") or 0),
                    reason.get("message", ""),
                ),
            )

        if priority_level in {"P1", "P2"} or risk_score >= 70:
            await send_alert(
                f"{priority_level} risk scan result: {target_value}",
                f"Risk score={risk_score}, level={risk_level}, open_ports={len(nmap_rows)}, findings={len(nuclei_findings)}",
                "high" if priority_level in {"P1", "P2"} else "medium",
            )

        finished = datetime.utcnow().isoformat(timespec="seconds")
        summary = f"open_ports={len(nmap_rows)}, findings={len(seen)}, tech={len(tech_rows)}, screenshots={len(screenshot_rows)}, recommendations={len(recommendations)}, changes={len(changes)}, priority={priority_level}, level={risk_level}"

        screenshot_errors = [s for s in screenshot_rows if s.get("status") in {"failed", "skipped"}]
        scan_status = "partial_success" if screenshot_errors else "done"
        job_status = scan_status
        status_message = f"completed: {summary}"
        if screenshot_errors:
            status_message += "; screenshot capture skipped/failed"

        conn.execute(
            """
            UPDATE scans
            SET status = ?, finished_at = ?, risk_score = ?, risk_level = ?, priority_level = ?,
                max_cvss = ?, max_epss = ?, kev_count = ?, sla_hours = ?,
                max_epss_percentile = ?, ssvc_action = ?, has_validated_cve = ?, has_candidate_cve = ?,
                summary = ?
            WHERE id = ?
            """,
            (
                scan_status,
                finished,
                risk_score,
                risk_level,
                priority_level,
                float(risk_detail.get("max_cvss") or 0),
                float(risk_detail.get("max_epss") or 0),
                int(risk_detail.get("kev_count") or 0),
                sla_hours,
                float(risk_detail.get("max_epss_percentile") or 0),
                str(risk_detail.get("ssvc_action") or ""),
                1 if risk_detail.get("has_validated_vulnerability") else 0,
                1 if risk_detail.get("has_candidate_vulnerability") else 0,
                summary,
                scan_id,
            ),
        )

        if priority_level in {"P1", "P2", "P3"}:
            due_at = (datetime.utcnow() + timedelta(hours=sla_hours or 720)).isoformat(timespec="seconds")
            top_reason = ""
            if risk_detail.get("reasons"):
                top_reason = str(risk_detail["reasons"][0].get("message", ""))
            conn.execute(
                """
                INSERT INTO risk_issues(scan_id, target_id, title, priority, risk_level, risk_score, status, sla_hours, due_at, reason, first_seen, last_seen, times_seen, ssvc_action)
                VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, 1, ?)
                """,
                (scan_id, target_id, f"{priority_level} risk detected for {target_value}", priority_level, risk_level, risk_score, sla_hours, due_at, top_reason, finished, finished, str(risk_detail.get("ssvc_action") or "")),
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
