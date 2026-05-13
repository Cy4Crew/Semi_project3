# ASM-Lite / Semi_project3

ASM-Lite is a web-based Attack Surface Management and vulnerability scanning platform.

The project registers targets, scans exposed TCP services, enriches scan results with Nmap, Nuclei, NVD/CVE, EPSS, CISA KEV, web fingerprinting, screenshots, and recommendation logic, then calculates a risk score and generates reports.

---

## Core Purpose

A basic port scanner only shows whether a port is open.

ASM-Lite connects the full security analysis chain:

```text
Target
-> TCP Port Scan
-> Nmap Service / Version Detection
-> Nuclei Web Vulnerability Scan
-> NVD / CVE / EPSS Enrichment
-> CISA KEV Check
-> Web Technology Detection
-> Screenshot Capture
-> Change Detection
-> Risk Score / Priority / SLA
-> Markdown / HTML Report
```

The goal is not only to find open ports, but also to explain why they matter, how urgent they are, and what action should be taken.

---

## Main Features

- Target registration by IP address, domain, or small CIDR range
- Bulk target upload from a text file
- Scan profiles: `quick`, `standard`, `extended`, `full`
- Custom port input such as `22,80,443,8000-8100`
- Asynchronous TCP port scanning
- Nmap-based service and version detection
- Nmap XML parsing
- Nuclei-based web vulnerability detection
- NVD/CVE enrichment from detected service/version data
- EPSS, EPSS percentile, and CISA KEV-based prioritization
- Playwright-based web screenshot collection
- Web technology detection and exposed service analysis
- Change detection between scans
- Risk score, risk level, P1-P4 priority, and SLA calculation
- Explainable risk reasons
- Markdown and HTML report generation
- Admin login and API key management
- Role-based API access control
- Scan request rate limiting
- SQLite persistence with WAL mode
- Docker Compose execution

---

## Project Structure

```text
Semi_project3/
├── app/
│   ├── main.py                # FastAPI app, pages, API routes
│   ├── auth.py                # API key, session, role, rate-limit logic
│   ├── database.py            # SQLite schema, migrations, safe write helpers
│   ├── scanner.py             # Target expansion, scan profiles, async TCP scan
│   ├── worker.py              # End-to-end scan job pipeline
│   ├── nmap_runner.py         # Nmap execution and XML parsing
│   ├── nuclei_runner.py       # Nuclei target building and JSONL parsing
│   ├── cve_api.py             # NVD, EPSS, KEV enrichment helpers
│   ├── risk.py                # Risk score, priority, SLA, risk reasons
│   ├── risk_policy_config.py  # Risk policy values
│   ├── ssvc.py                # Response action decision logic
│   ├── web_enrichment.py      # HTTP probing, technology detection, screenshots
│   ├── recommendations.py     # Remediation recommendation generation
│   ├── report.py              # Markdown report generation
│   ├── scheduler.py           # Scheduled scan support
│   ├── templates/             # Jinja2 HTML pages
│   └── static/                # CSS, JavaScript, screenshots
├── reports/                   # Generated report files
├── Dockerfile                 # Runtime image with Python, Nmap, Nuclei, Playwright
├── docker-compose.yml         # Docker Compose service definition
├── requirements.txt           # Python dependencies
├── README.md                  # Project overview
├── README_DOCKER.md           # Docker build and run guide
└── README_OPERATIONS.md       # Internal operation and troubleshooting guide
```

---

## Runtime Architecture

```text
Browser / API Client
        |
        v
FastAPI app.main
        |
        v
SQLite Database
        |
        v
scan_jobs Queue Record
        |
        v
worker.run_scan_job
        |
        +--> scanner.tcp_scan
        +--> nmap_runner.run_nmap
        +--> nuclei_runner.run_nuclei
        +--> cve_api enrichment
        +--> web_enrichment
        +--> recommendations
        +--> diff/change detection
        +--> risk.calculate_risk_detail
        |
        v
Report / Web UI / API Response
```

---

## Quick Start

Run with Docker Compose:

```bash
docker compose up --build
```

Open the web UI:

```text
http://localhost:8000
```

On first startup, the application creates an admin API key and writes it to:

```text
ADMIN_API_KEY.txt
```

Use that key to log in at:

```text
http://localhost:8000/admin
```

---

## Docker Runtime Components

The Docker image includes the major runtime tools:

- Python runtime
- Nmap
- Nuclei v3.8.0
- Playwright Chromium

The Compose service exposes port `8000` and persists SQLite data through a Docker volume.

---

## Main Web Pages

| Path | Purpose |
|---|---|
| `/admin` | Login page |
| `/admin/manage` | API key management |
| `/` | Main dashboard |
| `/assets` | Target asset list |
| `/scans` | Scan history |
| `/scans/{scan_id}` | Scan detail page |
| `/reports` | Report list |
| `/reports/{scan_id}` | Markdown report download |
| `/reports/{scan_id}/html` | HTML report view |
| `/ports/{port}` | Port guide and recent exposure context |

---

## Main API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/targets` | Add a target |
| `POST` | `/targets/upload` | Upload a target list file |
| `POST` | `/scan/{target_id}` | Start a scan |
| `GET` | `/api/scheduler` | Get scheduler status |
| `GET` | `/api/jobs` | Get protected job list |
| `GET` | `/api/jobs/public` | Get public job list |
| `GET` | `/api/scans/public` | Get public scan list |
| `GET` | `/api/history` | Get protected scan history |
| `GET` | `/api/keys` | List admin API keys |
| `POST` | `/api/keys` | Create an API key |
| `DELETE` | `/api/keys/{key_id}` | Revoke an API key |

Protected API routes require this header:

```text
X-API-Key: <api_key>
```

---

## Scan Profiles

| Profile | Scope | Intended Use |
|---|---:|---|
| `quick` | Major service ports | Fast validation |
| `standard` | Extended common ports | Recommended default |
| `extended` | 1-10000 | Wider discovery |
| `full` | 1-65535 | Full TCP range, slow |

Custom port input is also supported:

```text
22,80,443,8000-8100
```

---

## Scan Flow

1. The user registers a target.
2. The user starts a scan with a profile or custom port list.
3. The app creates a `scan_jobs` record.
4. `worker.run_scan_job` marks the job as running.
5. TCP scan checks the selected ports.
6. Nmap detects service names and versions on open ports.
7. Nuclei scans detected web services.
8. NVD, EPSS, and CISA KEV enrichment adds vulnerability intelligence.
9. Web enrichment collects technology evidence and screenshots.
10. Recommendations are generated.
11. Change detection compares the scan with previous results.
12. Risk scoring calculates score, level, priority, SLA, and reasons.
13. Results are saved and shown through the dashboard and reports.

---

## Risk Model Summary

The risk engine considers:

- exposed ports
- administrative ports
- database and infrastructure ports
- legacy or clear-text services
- service version fingerprints
- Nuclei findings
- CVSS score
- EPSS probability and percentile
- CISA KEV status
- target criticality
- changes from previous scans

Outputs include:

- `risk_score`: 0-100
- `risk_level`: Low, Medium, High, Critical
- `priority_level`: P1, P2, P3, P4
- `sla_hours`: recommended remediation window
- `risk_reasons`: explainable score contributions

Nmap/NVD service-version CVE matches are treated as candidate evidence, not validated exploit findings.

---

## Environment Variables

| Variable | Default | Purpose |
|---|---:|---|
| `ASM_ENABLE_SCREENSHOT` | `1` | Enable screenshot collection |
| `DATABASE_PATH` | `/data/asm_lite.db` | SQLite DB path inside the Docker container |
| `NVD_API_KEY` | empty | Optional NVD API key |
| `DISCORD_WEBHOOK_URL` | empty | Optional Discord alert webhook |
| `TELEGRAM_BOT_TOKEN` | empty | Optional Telegram bot token |
| `TELEGRAM_CHAT_ID` | empty | Optional Telegram chat ID |

---

## Additional Documentation

- [README_DOCKER.md](./README_DOCKER.md): Docker build, run, logs, volumes, and environment guide
- [README_OPERATIONS.md](./README_OPERATIONS.md): Internal pipeline, database tables, operation, and troubleshooting guide

---

## Safe Use

Only scan assets that you own or have explicit permission to test.

Port scanning and vulnerability scanning can trigger security alarms, violate service terms, or create legal issues when used against third-party systems.
