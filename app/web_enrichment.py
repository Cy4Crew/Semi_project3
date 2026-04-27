import asyncio
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx

WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000, 9000}


def build_urls(host: str, ports: list[int]) -> list[str]:
    urls = []
    for port in ports:
        if port not in WEB_PORTS:
            continue
        scheme = "https" if port in {443, 8443} else "http"
        urls.append(f"{scheme}://{host}" if port in {80, 443} else f"{scheme}://{host}:{port}")
    return urls


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160]


def detect_technologies_from_response(url: str, status_code: int, headers: dict, body: str) -> list[dict]:
    found = {}

    def add(name: str, evidence: str):
        if name and name not in found:
            found[name] = {"url": url, "technology": name, "evidence": evidence[:300]}

    add(f"HTTP {status_code}", "response status")

    title = _title(body)
    if title:
        add(f"Title: {title}", "html title")

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    via = headers.get("via", "")
    waf = headers.get("x-sucuri-id", "") or headers.get("cf-ray", "") or headers.get("x-akamai-transformed", "")

    if server:
        add(f"Server: {server}", "server header")
    if powered:
        add(f"X-Powered-By: {powered}", "x-powered-by header")
    if via:
        add(f"Proxy/Via: {via}", "via header")
    if waf:
        add("WAF/CDN Indicator", "security/CDN related header")

    low = body.lower()
    patterns = [
        ("WordPress", "wp-content"),
        ("WordPress", "wp-includes"),
        ("Drupal", "drupal"),
        ("Joomla", "joomla"),
        ("Spring Boot", "whitelabel error page"),
        ("React", "react"),
        ("Vue.js", "vue"),
        ("Angular", "ng-version"),
        ("jQuery", "jquery"),
        ("Bootstrap", "bootstrap"),
        ("Swagger/OpenAPI", "swagger"),
        ("Swagger/OpenAPI", "openapi"),
        ("Grafana", "grafana"),
        ("Kibana", "kibana"),
        ("Jenkins", "jenkins"),
        ("Apache Default Page", "apache2 ubuntu default page"),
        ("Nginx Default Page", "welcome to nginx"),
        ("PHP", ".php"),
    ]
    for name, token in patterns:
        if token in low:
            add(name, f"body token: {token}")

    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if generator:
        add(f"Generator: {generator.group(1)}", "generator meta tag")

    return list(found.values())


async def probe_technologies(host: str, ports: list[int]) -> list[dict]:
    rows = []
    urls = build_urls(host, ports)

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        for url in urls:
            try:
                resp = await client.get(url, headers={"User-Agent": "ASM-Lite/1.0"})
                rows.extend(detect_technologies_from_response(url, resp.status_code, dict(resp.headers), resp.text[:200000]))
            except Exception as exc:
                rows.append({"url": url, "technology": "Probe Failed", "evidence": str(exc)[:300]})

    return rows


def _safe_name(url: str, scan_id: int, idx: int, suffix: str) -> str:
    parsed = urlparse(url)
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", parsed.netloc + parsed.path)
    return f"scan_{scan_id}_{idx}_{safe}_{suffix}"


def _write_html_fallback(output_dir: Path, url: str, scan_id: int, idx: int, reason: str) -> dict:
    rel = _safe_name(url, scan_id, idx, "evidence.html")
    path = output_dir / rel
    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ASM-Lite Evidence Fallback</title>
</head>
<body style="font-family:Arial,sans-serif;padding:24px;line-height:1.5">
<h1>Web Evidence Fallback</h1>
<p><b>URL:</b> {url}</p>
<p><b>Status:</b> Screenshot capture was skipped or failed.</p>
<p><b>Reason:</b> {reason}</p>
<p>The endpoint was detected and technology probing was performed. This fallback page is generated to keep auditable evidence without breaking the scan.</p>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return {"url": url, "path": f"/static/screenshots/{rel}", "status": "html_fallback", "error": reason[:300]}


def capture_screenshots_sync(host: str, ports: list[int], scan_id: int, output_dir: Path) -> list[dict]:
    urls = build_urls(host, ports)
    if not urls:
        return []

    output_dir.mkdir(parents=True, exist_ok=True)

    # Safe default for Windows + Uvicorn reload. It prevents Playwright subprocess crashes.
    if os.getenv("ASM_ENABLE_SCREENSHOT", "0").strip() != "1":
        return [
            _write_html_fallback(
                output_dir,
                url,
                scan_id,
                idx,
                "screenshot disabled by default; set ASM_ENABLE_SCREENSHOT=1 to enable Playwright capture",
            )
            for idx, url in enumerate(urls, start=1)
        ]

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return [_write_html_fallback(output_dir, url, scan_id, idx, f"playwright not installed: {exc}") for idx, url in enumerate(urls, start=1)]

    rows = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1365, "height": 768})

            for idx, url in enumerate(urls, start=1):
                rel = _safe_name(url, scan_id, idx, "screenshot.png")
                path = output_dir / rel
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    page.screenshot(path=str(path), full_page=True)
                    rows.append({"url": url, "path": f"/static/screenshots/{rel}", "status": "created", "error": ""})
                except Exception as exc:
                    rows.append(_write_html_fallback(output_dir, url, scan_id, idx, str(exc)))

            browser.close()
    except Exception as exc:
        rows = [_write_html_fallback(output_dir, url, scan_id, idx, str(exc)) for idx, url in enumerate(urls, start=1)]

    return rows


def run_web_enrichment_sync(host: str, ports: list[int], scan_id: int, output_dir: Path):
    tech = asyncio.run(probe_technologies(host, ports))
    screenshots = capture_screenshots_sync(host, ports, scan_id, output_dir)
    return tech, screenshots
