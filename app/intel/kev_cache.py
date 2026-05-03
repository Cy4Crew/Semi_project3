"""CISA KEV cache utilities.

The risk engine can operate without network access. If KEV download fails,
this module falls back to the last cached catalog, then to an empty catalog.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
KEV_CACHE_PATH = DATA_DIR / "kev_catalog.json"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_SECONDS = 24 * 60 * 60

_memory_cache: dict[str, Any] = {"loaded_at": 0.0, "catalog": {}}


def _parse_catalog(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for item in data.get("vulnerabilities", []) or []:
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        catalog[cve] = {
            "cve": cve,
            "vendorProject": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "vulnerabilityName": item.get("vulnerabilityName", ""),
            "dateAdded": item.get("dateAdded", ""),
            "dueDate": item.get("dueDate", ""),
            "knownRansomwareCampaignUse": item.get("knownRansomwareCampaignUse", ""),
            "requiredAction": item.get("requiredAction", ""),
        }
    return catalog


def _read_cache_file() -> dict[str, dict[str, Any]]:
    if not KEV_CACHE_PATH.exists():
        return {}
    try:
        data = json.loads(KEV_CACHE_PATH.read_text(encoding="utf-8"))
        if "vulnerabilities" in data:
            return _parse_catalog(data)
        if isinstance(data, dict):
            return {str(k).upper(): v for k, v in data.items() if str(k).upper().startswith("CVE-")}
    except Exception:
        return {}
    return {}


def refresh_kev_catalog(force: bool = False) -> dict[str, dict[str, Any]]:
    now = time.time()
    if not force and _memory_cache["catalog"] and now - float(_memory_cache["loaded_at"] or 0) < CACHE_TTL_SECONDS:
        return dict(_memory_cache["catalog"])

    if not force and KEV_CACHE_PATH.exists():
        try:
            age = now - KEV_CACHE_PATH.stat().st_mtime
            if age < CACHE_TTL_SECONDS:
                catalog = _read_cache_file()
                _memory_cache["loaded_at"] = now
                _memory_cache["catalog"] = catalog
                return dict(catalog)
        except Exception:
            pass

    try:
        with httpx.Client(timeout=12.0, follow_redirects=True) as client:
            resp = client.get(KEV_FEED_URL)
            if resp.status_code == 200:
                raw = resp.json()
                KEV_CACHE_PATH.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                catalog = _parse_catalog(raw)
                _memory_cache["loaded_at"] = now
                _memory_cache["catalog"] = catalog
                return dict(catalog)
    except Exception:
        pass

    catalog = _read_cache_file()
    _memory_cache["loaded_at"] = now
    _memory_cache["catalog"] = catalog
    return dict(catalog)


def is_kev(cve_id: str) -> bool:
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return False
    return cve in refresh_kev_catalog(force=False)


def get_kev_record(cve_id: str) -> dict[str, Any] | None:
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return None
    return refresh_kev_catalog(force=False).get(cve)
