import os
import re
import time
import urllib.parse
from functools import lru_cache
from typing import Any

import httpx

try:
    from app.intel.kev_cache import is_kev as _is_kev_cached
except Exception:  # pragma: no cover
    _is_kev_cached = None

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cve_ids(value: Any) -> list[str]:
    """Extract and normalize CVE IDs from strings, lists, dicts, or nested values."""
    if not value:
        return []
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(extract_cve_ids(item))
        return sorted(set(out))
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(extract_cve_ids(item))
        return sorted(set(out))
    return sorted(set(m.group(0).upper() for m in CVE_RE.finditer(str(value))))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(str(value).strip())
    except Exception:
        return default


async def query_nvd(keyword: str, limit: int = 5) -> list[dict]:
    """
    Query NVD by keyword.

    This is intentionally used as enrichment/candidate evidence, not as proof that
    a service is vulnerable. Prefer exact CPE matching if a teammate provides it.
    """
    keyword = (keyword or "").strip()
    if not keyword:
        return []

    api_key = os.getenv("NVD_API_KEY", "").strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(max(1, min(int(limit or 5), 20))),
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    url = NVD_API_URL + "?" + urllib.parse.urlencode(params)

    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return []
            data = resp.json()
    except Exception:
        return []

    rows: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {}) or {}
        cve_id = str(cve.get("id", "")).upper()
        if not cve_id.startswith("CVE-"):
            continue

        metrics = cve.get("metrics", {}) or {}
        severity = "unknown"
        score: float | str = ""

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                metric = metrics[key][0] or {}
                cvss = metric.get("cvssData", {}) or {}
                severity = str(metric.get("baseSeverity", cvss.get("baseSeverity", "unknown"))).lower()
                score = cvss.get("baseScore", "")
                break

        descs = cve.get("descriptions", []) or []
        title = ""
        for desc in descs:
            if desc.get("lang") == "en":
                title = desc.get("value", "")
                break
        if not title and descs:
            title = descs[0].get("value", "")

        rows.append(
            {
                "cve": cve_id,
                "severity": severity,
                "score": _safe_float(score, 0.0),
                "title": title[:240],
                "fix": "Review vendor advisory and upgrade to a patched version.",
            }
        )

    return rows


@lru_cache(maxsize=2048)
def query_epss_sync(cve_id: str) -> dict[str, float]:
    """Query FIRST EPSS for one CVE. Official endpoint is /data/v1/epss."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return {"epss": 0.0, "percentile": 0.0}

    try:
        with httpx.Client(timeout=8.0, follow_redirects=True) as client:
            resp = client.get(EPSS_API_URL, params={"cve": cve_id})
            if resp.status_code != 200:
                return {"epss": 0.0, "percentile": 0.0}
            data = resp.json()
    except Exception:
        return {"epss": 0.0, "percentile": 0.0}

    rows = data.get("data") or []
    if not rows:
        return {"epss": 0.0, "percentile": 0.0}
    row = rows[0]
    return {
        "epss": _safe_float(row.get("epss"), 0.0),
        "percentile": _safe_float(row.get("percentile"), 0.0),
    }


def query_epss_batch(cve_ids: list[str]) -> dict[str, dict[str, float]]:
    """
    Batch query FIRST EPSS.

    Args:
        cve_ids: list of CVE IDs.

    Returns:
        {"CVE-XXXX-YYYY": {"epss": float, "percentile": float}, ...}

    Failure is non-fatal: returns {}.
    """
    cves = sorted(set(cve for cve in extract_cve_ids(cve_ids)))
    if not cves:
        return {}

    # FIRST supports comma-separated CVE query. Keep batches conservative to avoid long URLs.
    result: dict[str, dict[str, float]] = {}
    chunk_size = 80
    try:
        with httpx.Client(timeout=12.0, follow_redirects=True) as client:
            for i in range(0, len(cves), chunk_size):
                chunk = cves[i : i + chunk_size]
                resp = client.get(EPSS_API_URL, params={"cve": ",".join(chunk)})
                if resp.status_code != 200:
                    continue
                data = resp.json()
                for row in data.get("data") or []:
                    cve = str(row.get("cve", "")).upper()
                    if not cve.startswith("CVE-"):
                        continue
                    result[cve] = {
                        "epss": _safe_float(row.get("epss"), 0.0),
                        "percentile": _safe_float(row.get("percentile"), 0.0),
                    }
    except Exception:
        return {}

    return result


_kev_cache: dict[str, Any] = {"loaded_at": 0.0, "cves": set()}


def get_cisa_kev_set() -> set[str]:
    """Return CISA KEV CVE IDs. Fails closed as empty set if network is unavailable."""
    now = time.time()
    if _kev_cache["cves"] and now - float(_kev_cache["loaded_at"] or 0) < 3600:
        return set(_kev_cache["cves"])

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return set(_kev_cache.get("cves") or set())
            data = resp.json()
    except Exception:
        return set(_kev_cache.get("cves") or set())

    cves = {str(v.get("cveID", "")).upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
    _kev_cache["loaded_at"] = now
    _kev_cache["cves"] = cves
    return set(cves)


def is_cisa_kev(cve_id: str) -> bool:
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return False
    if _is_kev_cached is not None:
        try:
            return bool(_is_kev_cached(cve))
        except Exception:
            pass
    return cve in get_cisa_kev_set()


def get_max_epss(cve_text: Any) -> float:
    cves = extract_cve_ids(cve_text)
    if not cves:
        return 0.0
    epss_rows = query_epss_batch(cves)
    if epss_rows:
        return max((float(row.get("epss") or 0.0) for row in epss_rows.values()), default=0.0)
    return max((float(query_epss_sync(cve).get("epss") or 0.0) for cve in cves), default=0.0)


def has_any_kev(cve_text: Any) -> bool:
    return any(is_cisa_kev(cve) for cve in extract_cve_ids(cve_text))


def enrich_findings_with_intel(findings: list[dict]) -> list[dict]:
    """Add epss_score and kev fields to nuclei findings in-place-safe form."""
    enriched: list[dict] = []
    all_cves: list[str] = []

    prepared: list[tuple[dict, list[str]]] = []
    for finding in findings or []:
        row = dict(finding)
        cves = extract_cve_ids(row.get("cve_id") or row.get("cve") or row.get("description") or row.get("name"))
        prepared.append((row, cves))
        all_cves.extend(cves)

    epss_map = query_epss_batch(all_cves) if all_cves else {}

    for row, cves in prepared:
        if cves:
            row["cve_id"] = ",".join(cves)
            row["epss_score"] = max((float(epss_map.get(cve, {}).get("epss") or 0.0) for cve in cves), default=0.0)
            row["epss_percentile"] = max((float(epss_map.get(cve, {}).get("percentile") or 0.0) for cve in cves), default=0.0)
            row["kev"] = any(is_cisa_kev(cve) for cve in cves)
        else:
            row.setdefault("cve_id", "")
            row.setdefault("epss_score", 0.0)
            row.setdefault("epss_percentile", 0.0)
            row.setdefault("kev", False)
        row.setdefault("source", "nuclei")
        row.setdefault("confidence", 1.0)
        enriched.append(row)

    return enriched
