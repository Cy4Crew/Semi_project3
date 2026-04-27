from app.database import get_conn


def get_previous_scan_id(target_id: int, current_scan_id: int) -> int | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT id FROM scans WHERE target_id = ? AND id < ? AND status = 'done' ORDER BY id DESC LIMIT 1",
        (target_id, current_scan_id),
    ).fetchone()
    conn.close()
    return int(row["id"]) if row else None


def load_ports(scan_id: int) -> dict[int, dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM ports WHERE scan_id = ?", (scan_id,)).fetchall()
    conn.close()
    return {int(r["port"]): dict(r) for r in rows}


def detect_changes(target_id: int, scan_id: int) -> list[str]:
    previous_id = get_previous_scan_id(target_id, scan_id)
    if previous_id is None:
        return ["baseline_created:first_scan"]
    old = load_ports(previous_id)
    new = load_ports(scan_id)
    changes = []
    for port in sorted(set(new) - set(old)):
        changes.append(f"new_open_port:{port}")
    for port in sorted(set(old) - set(new)):
        changes.append(f"closed_port:{port}")
    for port in sorted(set(old) & set(new)):
        old_sig = (old[port].get("service"), old[port].get("product"), old[port].get("version"))
        new_sig = (new[port].get("service"), new[port].get("product"), new[port].get("version"))
        if old_sig != new_sig:
            changes.append(f"service_changed:{port}:{old_sig}->{new_sig}")
    return changes
