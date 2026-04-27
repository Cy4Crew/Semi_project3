import os
import urllib.parse
import httpx


async def query_nvd(keyword: str, limit: int = 5) -> list[dict]:
    keyword = (keyword or "").strip()
    if not keyword:
        return []

    api_key = os.getenv("NVD_API_KEY", "").strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(limit),
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return []
            data = resp.json()
    except Exception:
        return []

    rows = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        severity = "unknown"
        score = ""

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                metric = metrics[key][0]
                cvss = metric.get("cvssData", {})
                severity = metric.get("baseSeverity", cvss.get("baseSeverity", "unknown"))
                score = cvss.get("baseScore", "")
                break

        descs = cve.get("descriptions", [])
        title = ""
        for desc in descs:
            if desc.get("lang") == "en":
                title = desc.get("value", "")
                break
        if not title and descs:
            title = descs[0].get("value", "")

        rows.append({
            "cve": cve.get("id", ""),
            "severity": str(severity).lower(),
            "score": score,
            "title": title[:240],
            "fix": "Review vendor advisory and upgrade to a patched version.",
        })

    return rows
