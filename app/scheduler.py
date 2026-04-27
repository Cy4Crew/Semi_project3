import asyncio
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

from app.database import get_conn
from app.worker import run_scan_job

scheduler = BackgroundScheduler(timezone="Asia/Seoul")


def create_scan_job(asset_id: int, job_type: str = "scheduled") -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO scan_jobs(asset_id, status, job_type, message) VALUES (?, 'queued', ?, ?)",
        (asset_id, job_type, "created by scheduler"),
    )
    job_id = cur.lastrowid
    conn.commit()
    conn.close()
    return int(job_id)


def run_job_sync(job_id: int) -> None:
    asyncio.run(run_scan_job(job_id))


def run_all_active_assets_scan() -> None:
    conn = get_conn()
    assets = conn.execute("SELECT id FROM assets WHERE active = 1 ORDER BY id").fetchall()
    conn.close()

    for asset in assets:
        job_id = create_scan_job(int(asset["id"]), "scheduled")
        run_job_sync(job_id)


def start_scheduler() -> None:
    if scheduler.running:
        return

    scheduler.add_job(
        run_all_active_assets_scan,
        "cron",
        hour=9,
        minute=0,
        id="daily_asset_scan",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()


def get_scheduler_status() -> dict:
    jobs = []
    if scheduler.running:
        for job in scheduler.get_jobs():
            jobs.append(
                {
                    "id": job.id,
                    "next_run_time": job.next_run_time.isoformat() if job.next_run_time else "",
                }
            )
    return {
        "running": scheduler.running,
        "server_time": datetime.now().isoformat(timespec="seconds"),
        "jobs": jobs,
    }
