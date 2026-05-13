# README_OPERATIONS

## Purpose

This document provides a detailed, code-level explanation of how the system operates internally.

It is intended for developers who need to understand execution flow, module responsibilities, data handling, and troubleshooting.

---

## End-to-End Execution Flow (Detailed)

1. Client accesses the Web UI or API.
2. FastAPI receives the request in `main.py`.
3. Target data is stored in `targets`.
4. A scan job is created in `scan_jobs`.
5. `worker.py` orchestrates the full scan lifecycle.
6. `scanner.py` runs asynchronous TCP port checks.
7. `nmap_runner.py` executes Nmap service detection.
8. Nmap XML is parsed into structured rows.
9. `nuclei_runner.py` executes web vulnerability scanning.
10. `cve_api.py` enriches findings with CVE, EPSS, and KEV data.
11. `web_enrichment.py` collects technology evidence and screenshots.
12. `recommendations.py` builds remediation recommendations.
13. Change detection compares current and previous scans.
14. `risk.py` calculates score, level, priority, SLA, and reasons.
15. `report.py` generates Markdown and HTML report output.
16. API and Web UI return structured results.

---

## Execution Sequence (Pseudo Code)

```text
run_scan_job(job_id):
    job = load scan job and target
    scan_id = create scan record

    open_ports = tcp_scan(target, ports)

    nmap_rows = run_nmap(target, open_ports, scan_id)
    save nmap_rows to ports

    nuclei_findings = run_nuclei(target, web_ports, scan_id)
    enriched_findings = enrich_findings_with_intel(nuclei_findings)

    service_cve_candidates = enrich_service_cves_from_nmap(nmap_rows)
    merge findings

    save findings

    tech_rows, screenshot_rows = run_web_enrichment_sync(...)
    save tech detections and screenshots

    recommendations = build_recommendations(...)
    save recommendations

    changes = detect_changes(target_id, scan_id)
    save changes

    risk_detail = calculate_risk_detail(...)
    save risk score and risk reasons

    finalize scan status
```

---

## Module Deep Dive

### 1. main.py

Responsibilities:

- Entry point for FastAPI
- Defines API routes
- Handles incoming HTTP requests
- Renders Web UI pages
- Triggers scan process
- Serves reports
- Manages admin login and API keys

Important routes:

```text
GET  /
POST /targets
POST /targets/upload
POST /scan/{target_id}
GET  /scans/{scan_id}
GET  /reports/{scan_id}
GET  /reports/{scan_id}/html
GET  /admin
GET  /admin/manage
```

---

### 2. scanner.py

Responsibilities:

- Defines default and extended port lists
- Defines scan profiles
- Parses custom port input
- Expands small CIDR ranges
- Runs asynchronous TCP port checks

Supported input:

```text
quick
standard
extended
full
80,443,8080
8000-8100
22,80,8000-8100
```

---

### 3. worker.py

Core orchestrator.

Responsibilities:

- Controls execution order
- Handles data passing between modules
- Updates job progress
- Preserves partial results when possible
- Finalizes scan status

Key logic:

```text
TCP Scan -> Nmap -> Nuclei -> CVE/EPSS/KEV -> Web Enrichment -> Recommendations -> Change Detection -> Risk
```

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

### 4. nmap_runner.py

Execution command:

```bash
nmap -sV -O --version-light -p <ports> -oX <output.xml> <target>
```

Details:

- `-sV`: service version detection
- `-O`: OS detection attempt
- `--version-light`: lighter version detection
- `-p`: scan only selected open TCP ports from the TCP scan phase
- `-oX`: write XML output

Output:

- XML file under the data directory

Parsing extracts:

- open ports
- protocol
- service names
- service products
- service versions
- CPE values

---

### 5. Parsing Layer

Transforms:

```text
Nmap XML -> structured rows -> SQLite ports table
```

Structure example:

```json
{
  "port": 22,
  "protocol": "tcp",
  "state": "open",
  "service": "ssh",
  "product": "OpenSSH",
  "version": "8.2",
  "cpe": "",
  "source": "nmap"
}
```

---

### 6. nuclei_runner.py

Execution:

```bash
nuclei -l <target_file> -jsonl -o <output_file> -silent
```

Processing extracts:

- template ID
- matched URL
- severity
- CVE reference
- CVSS score
- description
- dedupe key

Nuclei is run against generated web URLs from detected web ports.

---

### 7. cve_api.py

Function:

- Calls external vulnerability intelligence sources
- Extracts CVE IDs
- Queries NVD
- Queries EPSS
- Checks CISA KEV status

Adds:

- CVE ID
- CVSS score
- severity classification
- EPSS score
- EPSS percentile
- KEV status
- source
- confidence

---

### 8. risk.py

Core algorithm.

Input:

- parsed ports
- enriched vulnerabilities
- detected changes
- target criticality

Output:

- final risk score
- risk level
- priority
- SLA hours
- scoring reasons
- SSVC-style action

Important scoring inputs:

- port exposure
- administrative service exposure
- database/infrastructure exposure
- legacy or clear-text services
- CVSS score
- EPSS probability
- EPSS percentile
- CISA KEV status
- new open ports
- new findings
- asset criticality

Risk levels:

| Score Range | Level |
|---:|---|
| 0 - 29 | Low |
| 30 - 69 | Medium |
| 70 - 89 | High |
| 90 - 100 | Critical |

Important policy:

- Nmap/NVD service-version CVE candidates are useful for prioritization.
- Candidate-only evidence is capped and cannot over-promote a target above policy limits without validated CVE or KEV evidence.

---

### 9. report.py

Responsibilities:

- Aggregate processed scan data
- Generate Markdown report files
- Provide download-ready output
- Support UI-compatible report rendering

Report endpoints:

```text
GET /reports/{scan_id}
GET /reports/{scan_id}/html
```

---

### 10. database.py

Responsibilities:

- SQLite connection management
- WAL mode setup
- Schema creation
- Index creation
- Migration-style column additions
- Retry-safe SQL execution helpers

Main tables:

| Table | Purpose |
|---|---|
| `targets` | Registered scan targets |
| `scan_jobs` | Scan job queue and progress |
| `scans` | Scan metadata and final risk summary |
| `ports` | Open ports and service detection results |
| `findings` | Nuclei findings and CVE candidates |
| `changes` | Differences from previous scans |
| `tech_detections` | Web technology evidence |
| `screenshots` | Screenshot capture results |
| `recommendations` | Remediation guidance |
| `risk_reasons` | Explainable scoring reasons |
| `risk_issues` | Priority issues and SLA tracking |
| `api_keys` | API key records |

---

### 11. web_enrichment.py

Responsibilities:

- HTTP/HTTPS probing
- Technology detection
- Screenshot capture
- Web evidence collection

Stores results in:

```text
tech_detections
screenshots
```

---

### 12. recommendations.py

Responsibilities:

- Build remediation guidance from ports and findings
- Provide UI/report-compatible recommendation rows

Stores results in:

```text
recommendations
```

---

### 13. scheduler.py

Responsibilities:

- Start APScheduler
- Register scheduled scan job
- Report scheduler status

Important current issue:

The current scheduler code references `assets` and `asset_id`, while the main database schema uses `targets` and `target_id`.

If scheduled scans are required, update:

```text
assets   -> targets
asset_id -> target_id
```

Manual scans are not affected because they use `/scan/{target_id}`.

---

## Data Flow (Detailed)

```text
targets
  |
  v
scan_jobs
  |
  v
scans
  |
  +--> ports
  +--> findings
  +--> changes
  +--> tech_detections
  +--> screenshots
  +--> recommendations
  +--> risk_reasons
  +--> risk_issues
```

Expanded flow:

```text
Nmap XML
-> Parser
-> SQLite ports
-> Merge with Nuclei findings
-> CVE / EPSS / KEV enrichment
-> Web enrichment
-> Recommendation generation
-> Change detection
-> Risk calculation
-> Final report
```

---

## Concurrency & Execution Model

- FastAPI handles HTTP routes.
- Scan jobs are tracked in `scan_jobs`.
- Worker logic executes the scan pipeline.
- TCP scanning is asynchronous.
- Nmap and Nuclei are executed through subprocess calls.
- SQLite uses WAL mode and retry helpers for selected writes.
- Scheduler support exists, but scheduled scan table names should be aligned before relying on it.

Execution types:

- manual scan through Web UI
- API-protected result retrieval
- scheduled scan after scheduler table-name fix

---

## Error Handling

Handled scenarios:

- Nmap missing
- Nmap timeout
- Nuclei missing
- Nuclei timeout
- CVE enrichment failure
- web enrichment failure
- screenshot failure
- partial output preservation
- SQLite lock retry for selected writes

A scan may become `partial_success` when core scan data exists but a later enrichment stage fails.

---

## Performance Considerations

- TCP scanning is asynchronous.
- Large port ranges increase scan time.
- `full` profile can be slow.
- Nmap service detection is heavier than raw TCP checks.
- Nuclei execution depends on target count and template behavior.
- Screenshot capture can be slow for unstable web services.
- SQLite is acceptable for local or small usage but not ideal for heavy concurrent scanning.

---

## Security Considerations

- Input validation is required for target values.
- Avoid command injection by using list-based subprocess commands.
- Limit scan scope.
- Keep API keys private.
- Do not expose `ADMIN_API_KEY.txt`.
- Do not publish reports or screenshots containing sensitive target information.
- Use the tool only against authorized assets.

---

## Scaling Strategy

Future design:

- Worker queue with Redis or RabbitMQ
- Distributed scanning nodes
- Persistent database with PostgreSQL
- Per-target scan policies
- Per-scan timeout policies
- Worker health checks
- Audit logs
- Role-based access control
- Central reporting dashboard

---

## Known Limitations

- Dependent on external tool accuracy.
- No horizontal scaling implemented.
- Scheduled scan code needs table-name alignment.
- Limited historical analytics.
- SQLite can become a bottleneck under heavy concurrency.
- Candidate CVE enrichment should not be treated as proof of exploitation.
- AI-generated summaries should be reviewed before formal reporting.

---

## Troubleshooting

### Scan stuck in running state

Check:

```bash
docker compose logs -f asm-lite
```

Then inspect:

- `scan_jobs.status`
- `scan_jobs.stage`
- `scan_jobs.message`
- Nmap timeout
- Nuclei timeout
- Screenshot timeout
- DB lock errors

---

### Nmap result is empty

Possible causes:

- Target unreachable
- Ports closed
- DNS failure
- Nmap timeout
- Container network issue

Manual check:

```bash
docker compose exec asm-lite nmap -sV --version-light -p 80,443 example.com
```

---

### Nuclei result is empty

Possible causes:

- No detected web ports
- No generated URL
- No matching templates
- Nuclei timeout
- Nuclei binary issue

Check:

```bash
docker compose exec asm-lite nuclei -version
```

---

### Screenshot capture failed

Possible causes:

- Web service unreachable
- TLS error
- Slow response
- Playwright issue
- Output path permission issue

Check:

```bash
docker compose exec asm-lite python -m playwright --version
docker compose exec asm-lite ls -al /app/app/static/screenshots
```

---

## Best Practice

- Always validate scan outputs before processing.
- Keep Nmap and Nuclei updated.
- Monitor scan performance and failures.
- Use `standard` as the default practical scan profile.
- Use `full` only when broad coverage is necessary.
- Treat `partial_success` as useful but incomplete output.
- Review candidate CVEs before reporting them as confirmed vulnerabilities.
- Back up the SQLite database if scan history matters.
