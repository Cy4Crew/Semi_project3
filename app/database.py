import sqlite3
import os
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "asm_lite.db"
DATA_DIR.mkdir(exist_ok=True)


def get_conn():
    if os.path.dirname(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False,
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def safe_execute(sql: str, params: tuple = (), retries: int = 5, delay: float = 0.25):
    last_error = None
    for attempt in range(retries):
        conn = None
        try:
            conn = get_conn()
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(sql, params)
            conn.commit()
            return
        except sqlite3.OperationalError as exc:
            last_error = exc
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            if "locked" not in str(exc).lower():
                raise
            time.sleep(delay * (attempt + 1))
        finally:
            if conn:
                conn.close()
    raise last_error


def safe_executemany(sql: str, rows: list[tuple], retries: int = 5, delay: float = 0.25):
    last_error = None
    for attempt in range(retries):
        conn = None
        try:
            conn = get_conn()
            conn.execute("BEGIN IMMEDIATE;")
            conn.executemany(sql, rows)
            conn.commit()
            return
        except sqlite3.OperationalError as exc:
            last_error = exc
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            if "locked" not in str(exc).lower():
                raise
            time.sleep(delay * (attempt + 1))
        finally:
            if conn:
                conn.close()
    raise last_error



def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL UNIQUE,
            label TEXT DEFAULT '',
            criticality INTEGER DEFAULT 3,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            job_type TEXT DEFAULT 'manual',
            status TEXT DEFAULT 'queued',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            finished_at TEXT,
            message TEXT DEFAULT '',
            progress INTEGER DEFAULT 0,
            stage TEXT DEFAULT 'queued',
            scan_id INTEGER,
            FOREIGN KEY(target_id) REFERENCES targets(id)
        );

CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            started_at TEXT DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            status TEXT DEFAULT 'running',
            risk_score INTEGER DEFAULT 0,
            summary TEXT DEFAULT '',
            FOREIGN KEY(target_id) REFERENCES targets(id)
        );

        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            state TEXT DEFAULT 'open',
            service TEXT DEFAULT '',
            product TEXT DEFAULT '',
            version TEXT DEFAULT '',
            cpe TEXT DEFAULT '',
            source TEXT DEFAULT '',
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            template_id TEXT DEFAULT '',
            name TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            matched_at TEXT DEFAULT '',
            description TEXT DEFAULT '',
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            change_type TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );

        
        CREATE TABLE IF NOT EXISTS tech_detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            technology TEXT NOT NULL,
            evidence TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS screenshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            path TEXT DEFAULT '',
            status TEXT DEFAULT 'created',
            error TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            severity TEXT DEFAULT '',
            title TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            source TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

CREATE INDEX IF NOT EXISTS idx_targets_value ON targets(value);
        CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_ports_scan_port ON ports(scan_id, port);
        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        """
    )
    conn.commit()

    for stmt in [
        "ALTER TABLE scan_jobs ADD COLUMN progress INTEGER DEFAULT 0",
        "ALTER TABLE scan_jobs ADD COLUMN stage TEXT DEFAULT 'queued'"
    ]:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()
