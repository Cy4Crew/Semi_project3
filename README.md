# ASM-Lite

ASM-Lite is a lightweight external attack surface assessment project built with FastAPI, Nmap, and Nuclei.

It is designed for security lab environments, authorized penetration testing practice, and asset exposure monitoring.

## Purpose

Basic port scanners only show whether a port is open.

ASM-Lite extends that idea by collecting service/version information, running template-based vulnerability checks, detecting changes between scans, calculating risk, and generating reports.

## Core Features

- Asset and target registration
- Bulk target upload
- TCP connect-based initial port scan
- Nmap service and version detection
- Nmap XML parsing
- Nuclei template-based vulnerability scan
- Change detection between scan results
- Risk score calculation
- Web dashboard
- Markdown report generation

## Architecture

```text
Target Registration
        ↓
TCP Port Scan
        ↓
Nmap Service Detection
        ↓
Nuclei Web Vulnerability Scan
        ↓
SQLite Storage
        ↓
Change Detection / Risk Scoring
        ↓
Dashboard / Markdown Report
```

## Tech Stack

- Python 3.12
- FastAPI
- Uvicorn
- Jinja2
- SQLite
- Nmap
- Nuclei

## Required Tools

Check Python:

```bat
py -0p
```

Check Nmap:

```bat
nmap --version
```

Check Nuclei:

```bat
nuclei -version
nuclei -update-templates
```

## Windows Installation

Install dependencies with Python 3.12:

```bat
cd C:\Users\drkob\Downloads\asm_lite_project
py -3.12 -m pip install --upgrade pip
py -3.12 -m pip install -r requirements.txt
```

Run the server:

```bat
py -3.12 -m uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Recommended Demo Target

```text
scanme.nmap.org
```

## Risk Scoring Policy

Risk score is calculated from the following signals:

- Asset criticality
- Exposed port risk
- Service/version exposure
- CPE exposure
- Nuclei severity
- Newly opened ports
- Service changes
- Newly detected findings

Info-level Nuclei findings do not increase the score.

Duplicate findings are counted once.

High-risk exposed services such as RDP, SMB, Redis, MongoDB, Elasticsearch, and Docker API receive higher weights.

## Risk Grade

```text
0-19   Info
20-39  Low
40-69  Medium
70-100 High
```

## Report

Each scan can generate a Markdown report containing:

- Target summary
- Open ports
- Service and version information
- Change history
- Nuclei findings
- Risk score

## Presentation Point

This project is not just a port scanner.

It works as a small ASM platform that performs asset exposure checking, service identification, vulnerability detection, change tracking, and report generation.

## Safe Usage

Use this tool only on systems you own, lab targets, CTF environments, or explicitly authorized assessment targets.


## Enterprise UI Update

The dashboard UI was redesigned for security operations.

### Added UI Improvements

- Sidebar based console layout
- KPI cards for targets, scans, ports, and findings
- Risk color labels
- Severity badges for Nuclei findings
- Improved scan detail page
- Operational flow section
- Better table readability
- Report download action area

### UI Goal

The interface is designed to look like a lightweight ASM/SOC console instead of a simple student project page.


## Scheduler, Filtering, and Job Status

This version adds operational features:

- APScheduler based daily automatic scan at 09:00 Asia/Seoul
- Scan job table with queued/running/done/failed status
- Dashboard filters by target, scan status, and risk grade
- Scan detail filters by port and Nuclei severity
- Job status API: `/api/jobs`
- Scheduler status API: `/api/scheduler`

Run:

```bat
py -3.12 -m pip install -r requirements.txt
py -3.12 -m uvicorn app.main:app --reload
```


## Web Enrichment Update

This version adds:

- HTTP technology detection
- Optional web screenshot capture
- Remediation recommendation generation
- Risk trend chart on the dashboard
- Extended Markdown report sections

### Optional Screenshot Setup

Screenshots use Playwright only if installed.

```bat
py -3.12 -m pip install playwright
py -3.12 -m playwright install chromium
```

If Playwright is not installed, scans still work and screenshot rows are marked as skipped.


## Final Polish Update

This version improves four operational areas:

- `partial_success` status is used when the core scan succeeds but optional enrichment, such as screenshots, fails.
- HTTP technology detection now records status code, title, server header, powered-by header, and common web framework fingerprints.
- Remediation recommendations are generated from exposed ports and common Nuclei finding patterns.
- Findings are easier to triage with severity summary chips and row-level severity styling.

PDF export is intentionally excluded.


## Port Detail Guide Update

Open ports in the scan result table are now clickable.

Example:

```text
22/tcp -> /ports/22
80/tcp -> /ports/80
```

Each port detail page includes:

- Service overview
- Risk factors
- Linux remediation commands
- Windows remediation steps
- Hardening recommendations
- Verification commands
- Recent assets where the same port was detected


Expanded runbook guides for many common ports.


## Final No-Export Feature Update

This version adds the requested features except CSV/JSON export:

- Real scan job progress bar and scan stage labels
- Enhanced port detail pages
- Optional Discord/Telegram alert delivery through environment variables
- Optional online CVE lookup through NVD API
- Screenshot fallback evidence page when Playwright capture is unavailable
- User-friendly partial success message
- Toggle button for info-level findings

### Alert Environment Variables

```bat
set DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
set TELEGRAM_BOT_TOKEN=...
set TELEGRAM_CHAT_ID=...
```

### Optional NVD API Key

```bat
set NVD_API_KEY=your_api_key
```

The system still works without these values.


## CVE API and Screenshot Recovery

This version explicitly includes:

- Optional NVD CVE API lookup on port detail pages
- Environment variable support for `NVD_API_KEY`
- Screenshot recovery fallback
- If Playwright or Chromium is unavailable, ASM-Lite generates an HTML evidence fallback instead of leaving the screenshot section empty

Optional setup:

```bat
set NVD_API_KEY=your_api_key
py -3.12 -m pip install playwright
py -3.12 -m playwright install chromium
```


## Windows Screenshot Fix

Screenshot capture now uses Playwright sync API instead of async subprocess-based API.

If Chromium cannot be launched on Windows, ASM-Lite creates an HTML evidence fallback file and the scan still completes.


## Final Error Fix

- `online_cves` is now always initialized in the port detail page.
- Screenshot capture is disabled by default on Windows to prevent Playwright subprocess crashes.
- HTML evidence fallback is generated automatically.
- To force real screenshots, set `ASM_ENABLE_SCREENSHOT=1` before running the server.


## Docker Run

Recommended for stable Playwright screenshot capture.

### Requirements

- Docker Desktop
- Docker Compose v2

### Start

```bat
run_docker.bat
```

or:

```bat
docker compose build
docker compose up -d
```

Open:

```text
http://127.0.0.1:8000
```

### Stop

```bat
stop_docker.bat
```

or:

```bat
docker compose down
```

### Logs

```bat
logs_docker.bat
```

or:

```bat
docker compose logs -f asm-lite
```

### Docker Features

- Python version fixed inside container
- Nmap installed inside container
- Nuclei installed inside container
- Playwright Chromium installed inside container
- Screenshots enabled by default
- SQLite data persisted in Docker volume
- Reports and screenshots mounted to local folders

### Optional Environment Variables

Create `.env` next to `docker-compose.yml` if needed:

```env
NVD_API_KEY=
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```


## Live Scheduler Refresh

Dashboard server time now refreshes every second using:

```text
GET /api/scheduler
```

No manual browser refresh is required.


## Clock Refresh Fix

Dashboard time now updates every second with:

- Browser local-time fallback
- `/api/scheduler` server-time fetch
- Cache-busting query parameter

If the API fails, the displayed clock still continues to move.
