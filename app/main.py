from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, File, Query, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from pathlib import Path

from app.database import init_db, get_conn
from app.scanner import expand_target, parse_port_input, SCAN_PROFILES, PROFILE_DESCRIPTIONS, DEFAULT_PORTS
from app.worker import run_scan_job
from app.scheduler import start_scheduler, get_scheduler_status
from app.report import generate_report
from app.risk import grade
from app.port_guides import get_port_guide
from app.intelligence import map_cves, exposure_decision
from app.cve_api import query_nvd
from app.auth import (
    init_auth_table, rate_limit,
    verify_api_key, require_admin,
    check_total_target_limit,
    issue_api_key, revoke_api_key,
    get_session, create_session, require_session,
    require_admin_session, SESSION_COOKIE,
)
BASE_DIR = Path(__file__).resolve().parent.parent
app = FastAPI(title="ASM-Lite", version="1.2.0")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")


@app.on_event("startup")
def startup():
    init_db()
    init_auth_table()
    start_scheduler()


@app.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    q: str = Query("", description="target search"),
    status: str = Query("", description="scan status"),
    risk: str = Query("", description="risk grade"),
):
    user = get_session(request)
    if not user:
        return RedirectResponse("/admin")
    conn = get_conn()

    target_where = []
    target_params = []
    if q:
        target_where.append("(value LIKE ? OR label LIKE ?)")
        target_params.extend([f"%{q}%", f"%{q}%"])

    target_sql = "SELECT * FROM targets"
    if target_where:
        target_sql += " WHERE " + " AND ".join(target_where)
    target_sql += " ORDER BY id DESC"

    targets = conn.execute(target_sql, target_params).fetchall()

    scan_where = []
    scan_params = []
    if q:
        scan_where.append("(targets.value LIKE ? OR targets.label LIKE ?)")
        scan_params.extend([f"%{q}%", f"%{q}%"])
    if status:
        scan_where.append("scans.status = ?")
        scan_params.append(status)

    scan_sql = """
        SELECT scans.*, targets.value
        FROM scans JOIN targets ON scans.target_id = targets.id
    """
    if scan_where:
        scan_sql += " WHERE " + " AND ".join(scan_where)
    scan_sql += " ORDER BY scans.id DESC LIMIT 100"

    scan_rows = conn.execute(scan_sql, scan_params).fetchall()
    scans = []
    for row in scan_rows:
        row_dict = dict(row)
        if not risk or grade(int(row_dict.get("risk_score", 0))).lower() == risk.lower():
            scans.append(row_dict)

    jobs = conn.execute(
        """
        SELECT scan_jobs.*, targets.value
        FROM scan_jobs JOIN targets ON scan_jobs.target_id = targets.id
        ORDER BY scan_jobs.id DESC LIMIT 30
        """
    ).fetchall()

    stats = {
        "targets": conn.execute("SELECT COUNT(*) c FROM targets").fetchone()["c"],
        "scans": conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"],
        "ports": conn.execute("SELECT COUNT(*) c FROM ports").fetchone()["c"],
        "findings": conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"],
        "queued": conn.execute("SELECT COUNT(*) c FROM scan_jobs WHERE status = 'queued'").fetchone()["c"],
        "running": conn.execute("SELECT COUNT(*) c FROM scan_jobs WHERE status = 'running'").fetchone()["c"],
    }
    conn.close()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "targets": targets,
            "scans": scans,
            "jobs": jobs,
            "stats": stats,
            "grade": grade,
            "filters": {"q": q, "status": status, "risk": risk},
            "scheduler": get_scheduler_status(),
            "scan_profiles": SCAN_PROFILES,
            "profile_descriptions": PROFILE_DESCRIPTIONS,
        },
    )


@app.post("/targets")
def create_target(value: str = Form(...), label: str = Form(""), criticality: int = Form(3)):
    check_total_target_limit()
    conn = get_conn()
    for item in expand_target(value):
        conn.execute(
            "INSERT OR IGNORE INTO targets(value, label, criticality) VALUES (?, ?, ?)",
            (item.strip(), label.strip(), criticality),
        )
    conn.commit()
    conn.close()
    return RedirectResponse("/", status_code=303)


@app.post("/targets/upload")
async def upload_targets(file: UploadFile = File(...)):
    body = (await file.read()).decode("utf-8", errors="ignore")
    conn = get_conn()
    for line in body.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        for item in expand_target(value):
            conn.execute("INSERT OR IGNORE INTO targets(value) VALUES (?)", (item,))
    conn.commit()
    conn.close()
    return RedirectResponse("/", status_code=303)


@app.post("/scan/{target_id}")
async def scan_target(
    target_id: int,
    scan_mode: str = Form("quick"),
    custom_ports: str = Form(""),
    _=Depends(rate_limit("scan")),
):
    conn = get_conn()
    target = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(404, "target not found")

    # 포트 목록 결정
    try:
        if custom_ports.strip():
            ports = parse_port_input(custom_ports)
        else:
            ports = parse_port_input(scan_mode)
    except ValueError as exc:
        conn.close()
        raise HTTPException(400, f"포트 입력 오류: {exc}")

    port_spec = custom_ports.strip() if custom_ports.strip() else scan_mode
    cur = conn.execute(
        "INSERT INTO scan_jobs(target_id, job_type, status, message) VALUES (?, 'manual', 'queued', 'created by user')",
        (target_id,),
    )
    job_id = cur.lastrowid
    conn.commit()
    conn.close()

    scan_id = await run_scan_job(int(job_id), ports=ports, port_spec=port_spec)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(
    request: Request,
    scan_id: int,
    severity: str = Query("", description="finding severity filter"),
    port: str = Query("", description="port filter"),
):
    conn = get_conn()
    scan = conn.execute(
        "SELECT scans.*, targets.value, targets.label FROM scans JOIN targets ON scans.target_id = targets.id WHERE scans.id = ?",
        (scan_id,),
    ).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(404, "scan not found")

    port_where = "WHERE scan_id = ?"
    port_params = [scan_id]
    if port:
        port_where += " AND CAST(port AS TEXT) LIKE ?"
        port_params.append(f"%{port}%")
    ports = conn.execute(f"SELECT * FROM ports {port_where} ORDER BY port", port_params).fetchall()

    finding_where = "WHERE scan_id = ?"
    finding_params = [scan_id]
    if severity:
        finding_where += " AND lower(severity) = lower(?)"
        finding_params.append(severity)
    findings = conn.execute(f"SELECT * FROM findings {finding_where} ORDER BY severity", finding_params).fetchall()
    severity_counts = conn.execute(
        "SELECT lower(severity) sev, COUNT(*) c FROM findings WHERE scan_id = ? GROUP BY lower(severity)",
        (scan_id,),
    ).fetchall()

    changes = conn.execute("SELECT * FROM changes WHERE scan_id = ?", (scan_id,)).fetchall()
    tech_rows = conn.execute("SELECT * FROM tech_detections WHERE scan_id = ? ORDER BY technology", (scan_id,)).fetchall()
    screenshots = conn.execute("SELECT * FROM screenshots WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
    recommendations = conn.execute("SELECT * FROM recommendations WHERE scan_id = ? ORDER BY severity", (scan_id,)).fetchall()
    job = conn.execute("SELECT * FROM scan_jobs WHERE scan_id = ? ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
    conn.close()

    return templates.TemplateResponse(
        "scan.html",
        {
            "request": request,
            "scan": scan,
            "ports": ports,
            "findings": findings,
            "severity_counts": severity_counts,
            "changes": changes,
            "tech_rows": tech_rows,
            "screenshots": screenshots,
            "recommendations": recommendations,
            "job": job,
            "grade": grade,
            "filters": {"severity": severity, "port": port},
        },
    )


@app.get("/reports/{scan_id}")
def report(scan_id: int):
    path = generate_report(scan_id)
    return FileResponse(path, media_type="text/markdown", filename=path.name)




@app.get("/ports/{port}", response_class=HTMLResponse)
async def port_detail(request: Request, port: int):
    guide = get_port_guide(port)
    cves = []
    decision = exposure_decision(port)
    online_cves = []

    conn = get_conn()
    recent = conn.execute(
        """
        SELECT scans.id AS scan_id, scans.started_at, scans.risk_score, scans.status,
               targets.value, ports.service, ports.product, ports.version
        FROM ports
        JOIN scans ON ports.scan_id = scans.id
        JOIN targets ON scans.target_id = targets.id
        WHERE ports.port = ?
        ORDER BY scans.id DESC
        LIMIT 20
        """,
        (port,),
    ).fetchall()
    if recent:
        sample = recent[0]
        keyword = " ".join([str(sample["product"] or ""), str(sample["version"] or "")]).strip()
        online_cves = await query_nvd(keyword)
    conn.close()

    return templates.TemplateResponse(
        "port_detail.html",
        {
            "request": request,
            "port": port,
            "guide": guide,
            "recent": recent,
            "cves": cves,
            "online_cves": online_cves,
            "decision": decision,
            "grade": grade,
        },
    )


@app.get("/api/scheduler")
def api_scheduler():
    from datetime import datetime

    payload = {
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "running",
        "next_run": None,
        "next_run_time": None,
    }

    try:
        status = get_scheduler_status()
        if isinstance(status, dict):
            payload.update(status)
            if "server_time" not in status:
                payload["server_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass

    return payload

# ── API 보호 엔드포인트 ──────────────────────────────────
@app.get("/api/jobs")
def api_jobs(user=Depends(verify_api_key)):
    conn = get_conn()
    jobs = conn.execute(
        """
        SELECT scan_jobs.*, targets.value
        FROM scan_jobs JOIN targets ON scan_jobs.target_id = targets.id
        ORDER BY scan_jobs.id DESC LIMIT 50
        """
    ).fetchall()
    conn.close()
    return [dict(j) for j in jobs]


@app.get("/api/history")
def api_history(limit: int = 20, user=Depends(verify_api_key)):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT scans.id, scans.started_at, scans.risk_score, scans.summary, targets.value
        FROM scans JOIN targets ON scans.target_id = targets.id
        WHERE scans.status = 'done'
        ORDER BY scans.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return list(reversed([dict(r) for r in rows]))


# ── Admin 전용 API Key 관리 ──────────────────────────────
@app.get("/api/keys")
def list_keys(user=Depends(require_admin_session)):
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, name, role, created_at, active FROM api_keys ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/keys")
def create_key(name: str = Form(...), role: str = Form("user"), user=Depends(require_admin_session)):
    raw = issue_api_key(name, role)
    return {"name": name, "role": role, "api_key": raw, "message": "안전한 곳에 보관하세요"}


@app.delete("/api/keys/{key_id}")
def delete_key(key_id: int, user=Depends(require_admin_session)):
    revoke_api_key(key_id)
    return {"message": f"Key {key_id} 비활성화 완료"}


# ── Admin 페이지 ─────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})

@app.post("/api/login")
async def login(request: Request, api_key: str = Form(...)):
    from app.auth import _lookup_key
    user = _lookup_key(api_key)
    if not user:
        raise HTTPException(403, "유효하지 않은 Key입니다.")
    if user["role"] == "admin":
        resp = RedirectResponse("/admin/manage", status_code=303)
    else:
        resp = RedirectResponse("/", status_code=303)
    create_session(resp, user)
    return resp

@app.get("/logout")
def logout():
    resp = RedirectResponse("/admin", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp

@app.get("/admin/manage", response_class=HTMLResponse)
def admin_manage(request: Request):
    user = get_session(request)
    if not user:
        return RedirectResponse("/admin")
    if user["role"] != "admin":
        return RedirectResponse("/")
    conn = get_conn()
    keys = conn.execute(
        "SELECT id, name, role, created_at, active FROM api_keys ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return templates.TemplateResponse("admin_manage.html", {
        "request": request,
        "user": user,
        "keys": [dict(k) for k in keys],
    })