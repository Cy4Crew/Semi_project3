# README_OPERATIONS

This document explains the internal operation, module responsibilities, data flow, and troubleshooting process for ASM-Lite / Semi_project3.

General users should read `README.md` and `README_DOCKER.md` first. This document is intended for developers and operators who need to understand the internal pipeline.

---

## End-to-End Execution Flow

```text
User
 |
 v
FastAPI Web UI / API
 |
 v
Target Registration
 |
 v
Scan Job Creation
 |
 v
worker.run_scan_job
 |
 +--> TCP Port Scan
 +--> Nmap Service Detection
 +--> Nuclei Vulnerability Scan
 +--> NVD / EPSS / KEV Enrichment
 +--> Web Enrichment / Screenshot
 +--> Recommendation Build
 +--> Change Detection
 +--> Risk Scoring
 |
 v
SQLite Persistence
 |
 v
Dashboard / Scan Detail / Report
```

---

## Module Responsibilities

### app/main.py

FastAPI entry point.

Responsibilities:

- Create the FastAPI app
- Mount static files
- Connect Jinja2 templates
- Initialize DB and auth tables at startup
- Start the scheduler
- Serve web pages
- Serve API routes

Main pages:

```text
/
 /admin
 /admin/manage
 /assets
 /scans
 /scans/{scan_id}
 /reports
 /reports/{scan_id}
 /reports/{scan_id}/html
 /ports/{port}
```

Main APIs:

```text
/api/scheduler
/api/jobs
/api/jobs/public
/api/scans/public
/api/history
/api/keys
```

---

### app/auth.py

Handles authentication, authorization, sessions, and rate limiting.

Main responsibilities:

- Issue API keys
- Store hashed API keys
- Verify API keys
- Check admin role
- Create session cookies
- Validate login sessions
- Apply scan request rate limits
- Enforce maximum target count

On first startup, the default admin API key is generated automatically.

```text
ADMIN_API_KEY.txt
```

In production-like usage, this file should be stored safely and should not be committed to a public repository.

---

### app/database.py

Handles SQLite connection and schema creation.

Main characteristics:

- SQLite database
- WAL mode enabled
- `busy_timeout` configured
- Safe SQL execution helper
- Migration-like column addition

Main tables:

| Table | Purpose |
|---|---|
| `targets` | Registered scan targets |
| `scan_jobs` | Scan job queue and progress state |
| `scans` | Scan result metadata |
| `ports` | Open ports and service data |
| `findings` | Nuclei findings and CVE candidates |
| `changes` | Changes compared to previous scans |
| `tech_detections` | Web technology detection results |
| `screenshots` | Screenshot collection results |
| `recommendations` | Remediation recommendations |
| `risk_reasons` | Explainable risk score reasons |
| `risk_issues` | Prioritized risk issues |
| `api_keys` | API key management table |

---

### app/scanner.py

Handles target expansion, port input parsing, and TCP scanning.

Supported target types:

- IP address
- Domain
- CIDR

CIDR ranges are limited to prevent overly broad scans.

Supported port input:

```text
quick
standard
extended
full
22,80,443
8000-8100
22,80,8000-8100
```

Scan profiles:

| Profile | Scope |
|---|---|
| `quick` | Major ports |
| `standard` | Extended common ports |
| `extended` | 1-10000 |
| `full` | 1-65535 |

`tcp_scan()` uses `asyncio.open_connection()` to check whether ports are reachable.

---

### app/worker.py

Core scan pipeline orchestrator.

Main stages inside `run_scan_job()`:

1. Load the job from `scan_jobs`
2. Mark the job as `running`
3. Create a `scans` record
4. Run TCP port scan
5. Run Nmap service detection
6. Store Nmap results in `ports`
7. Run Nuclei scan
8. Enrich Nuclei results with CVE/EPSS/KEV data
9. Add NVD candidate CVEs based on Nmap service/version data
10. Store findings
11. Run web technology detection and screenshot collection
12. Generate recommendations
13. Detect changes
14. Calculate risk score
15. Store `risk_reasons`
16. Send alerts when required
17. Finalize the scan as `done`, `partial_success`, or `failed`

Progress stages:

```text
10  starting
20  tcp_scan
40  nmap
65  nuclei
82  enrichment
95  finalizing
100 done / partial_success / failed
```

---

### app/nmap_runner.py

Runs Nmap and parses XML output.

Command structure:

```bash
nmap -sV -O --version-light -p <ports> -oX <output.xml> <target>
```

Collected fields:

- port
- protocol
- state
- service
- product
- version
- cpe
- source

If Nmap is not available, the pipeline falls back to TCP scan output.

---

### app/nuclei_runner.py

Runs Nuclei against detected web ports.

Web ports:

```text
80, 443, 8000, 8080, 8443, 3000, 5000, 9000
```

URL generation rules:

```text
80    -> http://host
443   -> https://host
8080  -> http://host:8080
8443  -> https://host:8443
```

Nuclei command:

```bash
nuclei -l <target_file> -jsonl -o <output_file> -silent
```

Collected fields:

- target
- template_id
- name
- severity
- matched_at
- description
- cve_id
- cvss_score
- dedupe_key

---

### app/cve_api.py

Handles vulnerability intelligence enrichment.

Main responsibilities:

- Extract CVE IDs
- Query NVD
- Query EPSS
- Check CISA KEV status
- Enrich Nuclei findings
- Support Nmap service/version-based CVE candidate enrichment

Using an NVD API key helps reduce rate-limit issues.

```env
NVD_API_KEY=<key>
```

---

### app/risk.py

Risk scoring engine.

Inputs:

- Open ports
- Vulnerability findings
- Changes
- Target criticality

Outputs:

- score
- raw_score
- level
- priority
- sla_hours
- max_cvss
- max_epss
- max_epss_percentile
- kev_count
- ssvc_action
- has_validated_vulnerability
- has_candidate_vulnerability
- reasons

Risk levels:

| Score | Level |
|---:|---|
| 0-29 | Low |
| 30-69 | Medium |
| 70-89 | High |
| 90-100 | Critical |

Priorities:

| Priority | Meaning |
|---|---|
| P1 | Immediate response |
| P2 | Fast response |
| P3 | Planned response |
| P4 | Low priority |

Nmap/NVD service-version CVEs are treated as candidate evidence. Guardrails prevent candidate-only evidence from being over-promoted to Critical/P1 without validated vulnerability or KEV evidence.

---

### app/web_enrichment.py

Collects web service enrichment data.

Main responsibilities:

- HTTP/HTTPS probing
- Web technology detection
- Screenshot capture
- Status and error recording

Result tables:

- `tech_detections`
- `screenshots`

Screenshot failure may produce `partial_success` instead of full scan failure.

---

### app/recommendations.py

Generates remediation recommendations from ports and vulnerability findings.

Stored in:

```text
recommendations
```

Recommendations are used in scan detail pages and reports.

---

### app/report.py

Generates Markdown reports from scan results.

Download endpoint:

```text
/reports/{scan_id}
```

HTML report page:

```text
/reports/{scan_id}/html
```

---

### app/scheduler.py

Handles scheduled scans.

Important note:

The current `scheduler.py` references `assets` and `asset_id`, while the main database flow uses `targets` and `target_id`.

If scheduled scans do not work, check and fix this mapping first:

```text
assets   -> targets
asset_id -> target_id
```

Manual scans follow the `/scan/{target_id}` route in `main.py` and `worker.run_scan_job()`.

---

## Detailed Data Flow

### 1. Target Registration

Targets are registered through a web form or file upload.

Stored in:

```text
targets
```

Example fields:

- id
- value
- label
- criticality
- active
- created_at

---

### 2. Scan Job Creation

Manual scan requests create a scan job.

Stored in:

```text
scan_jobs
```

Main fields:

- target_id
- job_type
- status
- progress
- stage
- message
- scan_id

---

### 3. Port Scan

`scanner.tcp_scan()` checks selected ports for reachability.

The result is passed to the Nmap stage.

---

### 4. Nmap Service Detection

Nmap detects service and version information on open ports.

Stored in:

```text
ports
```

---

### 5. Nuclei Vulnerability Detection

Nuclei runs against generated web URLs.

Stored in:

```text
findings
```

---

### 6. CVE / EPSS / KEV Enrichment

Findings are enriched with:

- CVE ID
- CVSS
- EPSS
- EPSS percentile
- KEV status
- confidence
- source

---

### 7. Web Enrichment

Technology evidence and screenshots are collected.

Stored in:

```text
tech_detections
screenshots
```

---

### 8. Recommendation Generation

Remediation recommendations are generated from services and vulnerabilities.

Stored in:

```text
recommendations
```

---

### 9. Change Detection

The current scan is compared with previous scans.

Stored in:

```text
changes
```

Examples:

- new_open_port
- service_changed
- new_finding
- baseline_created

---

### 10. Risk Score Calculation

`risk.calculate_risk_detail()` calculates the final risk score.

Stored in:

```text
scans
risk_reasons
risk_issues
```

---

## Status Values

### scan_jobs.status

| Value | Meaning |
|---|---|
| `queued` | Job created |
| `running` | Job running |
| `done` | Completed |
| `partial_success` | Some stages failed, but useful output exists |
| `failed` | Failed |

### scans.status

| Value | Meaning |
|---|---|
| `running` | Scan running |
| `done` | Completed successfully |
| `partial_success` | Partially completed |
| `failed` | Failed |

---

## Operational Commands

Check container status:

```bash
docker compose ps
```

Follow logs:

```bash
docker compose logs -f asm-lite
```

Open a container shell:

```bash
docker compose exec asm-lite bash
```

Check tools:

```bash
nmap --version
nuclei -version
python --version
```

Check database files:

```bash
ls -al /data
```

Check reports:

```bash
ls -al /app/reports
```

Check screenshots:

```bash
ls -al /app/app/static/screenshots
```

---

## Troubleshooting

### Scan is stuck in running state

Check in this order:

1. Container logs
2. `scan_jobs.message`
3. Nmap timeout
4. Nuclei timeout
5. Screenshot timeout
6. SQLite lock

Logs:

```bash
docker compose logs -f asm-lite
```

---

### Nmap results are empty

Possible causes:

- Target is unreachable
- Ports are closed
- DNS resolution failed
- Container network issue
- Nmap timeout

Direct test inside the container:

```bash
nmap -sV --version-light -p 80,443 example.com
```

---

### Nuclei results are empty

Possible causes:

- No detected web ports
- Target URL was not generated
- No template matches
- Nuclei execution failed
- Timeout

Check:

```bash
nuclei -version
```

---

### Screenshot failed

Possible causes:

- Web service is unreachable
- TLS issue
- Slow target response
- Playwright Chromium issue
- Output directory permission issue

Check:

```bash
python -m playwright --version
ls -al /app/app/static/screenshots
```

---

### SQLite database locked

SQLite write contention may occur.

The project uses WAL mode and retry helpers. If the issue repeats, check:

- Concurrent scan count
- Long-running transactions
- Docker volume performance
- Whether writes use safe helper functions

---

### Scheduled scan error

The current `scheduler.py` has a table/column naming mismatch.

Expected fix direction:

```text
assets   -> targets
asset_id -> target_id
```

Fix this before relying on scheduled scans.

---

## Operational Recommendations

- Register only authorized targets.
- Do not expose `ADMIN_API_KEY.txt`.
- Provide `NVD_API_KEY` through `.env`.
- Back up `/data/asm_lite.db` regularly.
- Use the `full` scan profile only when necessary.
- Investigate `partial_success` results instead of ignoring them.
- Do not treat Nmap/NVD candidate CVEs as confirmed vulnerabilities without validation.
