# Semi_project3

## Overview

Semi_project3, also referred to as **ASM-Lite**, is a production-grade security scanning platform designed to replicate real-world penetration testing and SOC (Security Operations Center) workflows.

This system integrates multiple security tools and enrichment layers into a unified automated pipeline:

- **FastAPI** for backend orchestration, Web UI, and API handling
- **Async TCP scanning** for fast open-port discovery
- **Nmap** for network reconnaissance and service/version detection
- **Nuclei** for web vulnerability detection
- **NVD/CVE enrichment** for vulnerability intelligence
- **EPSS** for exploitation probability scoring
- **CISA KEV** checks for known exploited vulnerabilities
- **Playwright** for optional web screenshot collection
- **SQLite** for scan result persistence
- **Markdown / HTML reports** for result output
- **Ollama** for optional local AI-assisted report summarization and risk explanation, if the local implementation is enabled

Unlike basic port scanners, this project focuses on **end-to-end automation**, from initial discovery to risk-based decision making.

---

## Required Software

Install the following software before running the project.

### Required for Docker execution

- Docker latest version  
  https://www.docker.com/products/docker-desktop/

- Docker Compose v2 or later  
  Included in Docker Desktop

- Git  
  https://git-scm.com/downloads

### Installed automatically inside the Docker container

The Docker image installs the following runtime components:

- Python runtime
- Nmap
- Nuclei v3.8.0
- Playwright Chromium
- Python dependencies from `requirements.txt`

### Required only for local non-Docker execution

If you run the project directly on the host instead of Docker, install these manually:

- Python 3.12 or compatible Python 3 version  
  https://www.python.org/downloads/

- Nmap latest version  
  https://nmap.org/download.html

- Nuclei latest version  
  https://github.com/projectdiscovery/nuclei/releases

- Playwright Chromium

```bash
python -m playwright install chromium
```

### Optional software

- Ollama  
  https://ollama.com/download

Ollama is optional. The scanner and report pipeline should still work without Ollama if AI-assisted explanation is not enabled or not available.

---

## Ollama Model Setup

This project can optionally use Ollama for local AI-assisted report summarization, vulnerability explanation, and risk interpretation.

The recommended model is:

```text
gemma3:4b
```

Download the model:

```bash
ollama pull gemma3:4b
```

Check installed models:

```bash
ollama list
```

Run the model manually:

```bash
ollama run gemma3:4b
```

If the model runs successfully, Ollama is ready to be used by the project.

Ollama should be treated as an optional assistant layer. It should not be required for core scanning, vulnerability detection, risk scoring, or report generation.

---

## Installation Check

Verify that all required tools are installed correctly.

### Host check

```bash
docker --version
docker compose version
git --version
```

Expected result:

- Docker command prints the installed Docker version.
- Docker Compose command prints Compose v2 or later.
- Git command prints the installed Git version.

### Container check

After starting the container, verify the tools inside the container:

```bash
docker compose exec asm-lite python --version
docker compose exec asm-lite nmap --version
docker compose exec asm-lite nuclei -version
docker compose exec asm-lite python -m playwright --version
```

Expected result:

- Python command prints the container Python version.
- Nmap command prints the installed Nmap version.
- Nuclei command prints the installed Nuclei version.
- Playwright command runs without import errors.

### Optional Ollama check

If Ollama is used:

```bash
ollama --version
ollama list
```

---

## Problem Statement

Traditional port scanners usually provide only basic technical information.

They commonly report:

- Open ports
- Protocol information
- Basic service names
- Service versions

However, basic scanners do not provide enough security context for real-world decision making.

They usually do not provide:

- Vulnerability context
- CVE-based enrichment
- Exploitation probability
- Known exploited vulnerability status
- Risk prioritization
- Business-impact interpretation
- Actionable remediation guidance
- Report output
- Historical comparison

Semi_project3 solves this limitation by linking the full security analysis chain:

```text
Ports -> Services -> Vulnerabilities -> CVE Data -> EPSS / KEV -> Risk Score -> Report
```

The goal is not only to find open ports, but also to explain why they matter.

---

## Full Workflow

### 1. Target Input

The user submits a scan target.

Supported target types:

- IP address
- Domain name
- Small CIDR range

Example targets:

```text
192.168.0.10
example.com
192.168.0.0/24
```

The system receives the target through the Web UI and stores it in the `targets` table.

---

### 2. Scan Job Creation

When the user starts a scan, the system creates a job in the `scan_jobs` table.

Actual scan route:

```text
POST /scan/{target_id}
```

The scan can use a predefined profile or custom port input.

Supported scan profiles:

| Profile | Scope | Purpose |
|---|---:|---|
| `quick` | Major service ports | Fast validation |
| `standard` | Extended common ports | Recommended default |
| `extended` | 1-10000 | Wider discovery |
| `full` | 1-65535 | Full TCP range, slow |

Custom port input example:

```text
22,80,443,8000-8100
```

---

### 3. TCP Port Scanning

Before running Nmap, the system performs an asynchronous TCP scan.

Purpose:

- Quickly identify reachable ports
- Reduce unnecessary Nmap service-detection work
- Support profile-based or custom-port scanning

Main implementation:

```text
app/scanner.py
```

---

### 4. Network Scanning with Nmap

Nmap is used for service and version detection on open ports.

Actual command structure:

```bash
nmap -sV -O --version-light -p <ports> -oX <output.xml> <target>
```

Purpose:

- Identify open ports
- Detect running services
- Extract service names
- Extract service products
- Extract service versions
- Extract CPE values when available
- Provide structured XML output

Output format:

- XML output is preferred because it is easier to parse reliably.

---

### 5. Parsing Layer

The parsing layer converts raw Nmap XML output into structured data.

Extracted fields include:

- Port number
- Protocol
- Port state
- Service name
- Service product
- Service version
- CPE
- Data source

Example parsed result:

```json
{
  "port": 22,
  "protocol": "tcp",
  "state": "open",
  "service": "ssh",
  "product": "OpenSSH",
  "version": "8.9",
  "cpe": "cpe:/a:openbsd:openssh:8.9",
  "source": "nmap"
}
```

The parsed output is stored in the `ports` table and reused by enrichment, risk scoring, and reporting modules.

---

### 6. Vulnerability Scanning with Nuclei

Nuclei is used to detect known vulnerabilities and misconfigurations on detected web services.

ASM-Lite builds web targets from detected web ports.

Web ports include:

```text
80, 443, 8000, 8080, 8443, 3000, 5000, 9000
```

Actual command structure:

```bash
nuclei -l <target_file> -jsonl -o <output_file> -silent
```

Purpose:

- Match known vulnerability templates
- Detect CVEs when templates expose CVE metadata
- Identify exposed panels or weak configurations
- Detect web misconfigurations

The project focuses on meaningful findings rather than excessive low-severity noise.

---

### 7. CVE Enrichment

The CVE enrichment layer adds external vulnerability intelligence to scan results.

For each detected or candidate vulnerability, the system may enrich the result with:

- CVE ID
- CVSS score
- Severity level
- EPSS probability
- EPSS percentile
- CISA KEV status
- Vulnerability description
- Reference context
- Confidence value
- Source type

Example enriched vulnerability:

```json
{
  "cve_id": "CVE-2021-41773",
  "cvss_score": 7.5,
  "epss_score": 0.12,
  "epss_percentile": 0.91,
  "kev": false,
  "severity": "high",
  "source": "nuclei",
  "confidence": 1.0
}
```

Nmap service/version-based NVD matches are treated as **candidate evidence**, not validated exploit findings.

---

### 8. Optional AI-Based Report Explanation

Ollama can be used to generate local AI-assisted explanations.

Possible uses:

- Explain why a finding is dangerous
- Summarize scan results
- Convert technical findings into plain-language risk descriptions
- Assist with remediation recommendations

Recommended local model:

```text
gemma3:4b
```

This feature should be treated as optional. The scanner must still work without Ollama if AI summarization is disabled.

---

### 9. Web Enrichment and Screenshot Capture

The system performs additional web enrichment after vulnerability scanning.

Possible outputs:

- Web technology detection
- HTTP/HTTPS evidence
- Screenshot path
- Screenshot status
- Screenshot error reason

Stored in:

```text
tech_detections
screenshots
```

Screenshot failure does not necessarily mean the whole scan failed. The scan may be marked as:

```text
partial_success
```

---

### 10. Recommendation Generation

The system generates remediation recommendations based on detected ports and vulnerability findings.

Stored in:

```text
recommendations
```

---

### 11. Change Detection

The system compares current scan results with previous results for the same target.

Detected change examples:

- New open port
- Service change
- New finding
- Baseline creation

Stored in:

```text
changes
```

---

### 12. Risk Scoring Engine

The risk scoring engine calculates a final score based on exposed services, vulnerability severity, exploit likelihood, known exploitation status, asset criticality, and changes.

Basic concept:

```text
Risk Score = Exposure Risk + Vulnerability Risk + Exploit Likelihood + KEV Impact + Change Impact + Asset Criticality
```

Main components:

### Port Weight

Some ports have higher risk because they commonly expose sensitive services.

Examples:

| Port | Service | Risk Level |
|---:|---|---|
| 22 | SSH | Medium |
| 80 | HTTP | Medium |
| 443 | HTTPS | Medium |
| 445 | SMB | High |
| 3306 | MySQL | High |
| 3389 | RDP | High |
| 6379 | Redis | High |
| 9200 | Elasticsearch | High |
| 27017 | MongoDB | High |

### Exposure Level

Publicly exposed administrative, database, infrastructure, or clear-text services receive higher scores.

### CVSS Contribution

CVSS score contributes to the final risk score.

### EPSS Contribution

EPSS helps estimate exploitation likelihood.

### CISA KEV Contribution

CISA KEV-listed vulnerabilities receive stronger prioritization because they are known to be exploited in the wild.

### Candidate Evidence Guardrail

Service/version-based NVD matches from Nmap are useful, but they are not proof of exploitation.

The project applies guardrails so candidate-only evidence does not over-promote a target to Critical/P1 without validated vulnerability or KEV evidence.

---

## Example Risk Calculation

Example case:

- Port 22 is open: `+15`
- Administrative exposure: `+15`
- CVSS score is 8.5: `+30`
- EPSS signal exists: `+10`

Final calculation:

```text
15 + 15 + 30 + 10 = 70
```

Final result:

```text
70 = High Risk
```

Example risk bands:

| Score Range | Risk Level |
|---:|---|
| 0 - 29 | Low |
| 30 - 69 | Medium |
| 70 - 89 | High |
| 90 - 100 | Critical |

Priority output:

| Priority | Meaning |
|---|---|
| P1 | Immediate response |
| P2 | Fast response |
| P3 | Planned response |
| P4 | Low priority |

---

## System Architecture

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
Scan Job Queue
  |
  v
Async TCP Scanner
  |
  v
Nmap Service Detection
  |
  v
Nmap XML Parser
  |
  v
Nuclei Web Scanner
  |
  v
CVE / EPSS / KEV Enrichment
  |
  v
Web Enrichment / Screenshots
  |
  v
Recommendation Builder
  |
  v
Change Detection
  |
  v
Risk Scoring Engine
  |
  v
Report Generator
  |
  v
Web UI / API Response
```

The architecture separates scanning, parsing, enrichment, scoring, and reporting into independent modules.

This makes the project easier to maintain and extend.

---

## Project Structure

```text
app/
 ├── main.py                 # FastAPI entry point, pages, API routes
 ├── auth.py                 # API key, session, role, rate-limit logic
 ├── database.py             # SQLite schema, migrations, safe write helpers
 ├── scanner.py              # Target expansion, scan profiles, async TCP scan
 ├── worker.py               # Background task processing and scan orchestration
 ├── nmap_runner.py          # Executes Nmap and parses XML
 ├── nuclei_runner.py        # Executes Nuclei and parses JSONL
 ├── cve_api.py              # CVE, NVD, EPSS, KEV enrichment
 ├── risk.py                 # Risk scoring logic
 ├── risk_policy_config.py   # Risk policy values
 ├── ssvc.py                 # Response action decision logic
 ├── web_enrichment.py       # Web probing, technology detection, screenshots
 ├── recommendations.py      # Remediation recommendation logic
 ├── report.py               # Report generation logic
 ├── scheduler.py            # Periodic scan scheduling support
 ├── templates/              # HTML templates for Web UI
 └── static/                 # CSS, JavaScript, screenshots
```

Additional project files:

```text
README.md                   # Main project documentation
README_DOCKER.md            # Docker execution guide
README_OPERATIONS.md        # Internal pipeline and operation guide
docker-compose.yml          # Docker Compose configuration
Dockerfile                  # Container image definition
requirements.txt            # Python dependencies
reports/                    # Generated reports
```

---

## Data Flow

The technical data flow is as follows:

1. User registers a target.
2. FastAPI creates a scan job.
3. Worker starts the scan job.
4. TCP scanner checks selected ports.
5. Nmap scans open ports and generates XML output.
6. Parser converts Nmap XML output into structured rows.
7. Parsed service data is stored in `ports`.
8. Nuclei scans detected web services.
9. Nuclei results are normalized into findings.
10. CVE, EPSS, and KEV enrichment adds vulnerability context.
11. Web enrichment collects technologies and screenshots.
12. Recommendations are generated.
13. Change detection compares the current scan with previous scans.
14. Risk engine calculates score, priority, SLA, and risk reasons.
15. Report module generates the final result.
16. User views the result through the Web UI or API.

---

## API Design

### Web UI routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/admin` | Login page |
| `GET` | `/admin/manage` | API key management |
| `GET` | `/` | Main dashboard |
| `GET` | `/assets` | Target list |
| `GET` | `/scans` | Scan history |
| `GET` | `/scans/{scan_id}` | Scan detail |
| `GET` | `/reports` | Report list |
| `GET` | `/reports/{scan_id}` | Markdown report download |
| `GET` | `/reports/{scan_id}/html` | HTML report view |
| `GET` | `/ports/{port}` | Port detail guide |

### Target and scan routes

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/targets` | Add a target |
| `POST` | `/targets/upload` | Upload target list |
| `POST` | `/scan/{target_id}` | Start scan for a registered target |

### API routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/scheduler` | Scheduler status |
| `GET` | `/api/jobs` | Protected job list |
| `GET` | `/api/jobs/public` | Public job list |
| `GET` | `/api/scans/public` | Public scan list |
| `GET` | `/api/history` | Protected scan history |
| `GET` | `/api/keys` | Admin API key list |
| `POST` | `/api/keys` | Create API key |
| `DELETE` | `/api/keys/{key_id}` | Revoke API key |

Protected API routes require:

```text
X-API-Key: <api_key>
```

---

## Key Design Decisions

### TCP Scan Before Nmap

The system first checks selected ports with an asynchronous TCP scanner. Nmap then runs against confirmed open ports.

### XML to Structured Data Conversion

Nmap XML output is converted into structured rows because structured data is easier to store, display, score, and report.

### Modular Scanner Runners

Nmap and Nuclei are separated into independent runner modules.

Benefits:

- Easier debugging
- Easier replacement of tools
- Cleaner pipeline structure
- Better maintainability

### Risk Scoring Abstraction

Risk calculation is handled in a separate module.

This allows the project to adjust risk rules without modifying scanner logic.

### Async Worker Support

Scanning can take time, so the project supports job-based execution.

Benefits:

- API remains responsive
- Multiple scans can be tracked
- Long-running scans have progress and status
- Partial results can still be retained

### Candidate CVE Policy

Nmap service/version-based NVD matches are useful for prioritization, but they are not confirmed vulnerabilities.

The risk engine stores them as candidate evidence with lower confidence.

### Optional Local AI Assistance

Ollama is optional and should not be required for the core scanning workflow.

The project should still produce reports even when AI-based summarization is disabled.

---

## Limitations

Current limitations:

- Results depend on Nmap, Nuclei, and target response accuracy.
- False positives may occur in template-based vulnerability scanning.
- Nmap service/version-based CVE matching is candidate evidence, not proof of exploitation.
- Distributed scanning is not implemented yet.
- SQLite is suitable for local or small-scale use, but PostgreSQL would be better for larger deployments.
- Real-time alerting depends on Discord or Telegram webhook configuration.
- CVE enrichment depends on external data availability and API limits.
- AI-generated explanations should be reviewed before use in formal reports.
- Scheduled scan code should be reviewed because `scheduler.py` references `assets/asset_id` while the main schema uses `targets/target_id`.

---

## Future Improvements

Planned improvements:

- Fix and harden scheduled scan support
- Distributed scanning cluster
- Worker queue using Redis or RabbitMQ
- PostgreSQL support
- Real-time alerts through Telegram or Discord
- Threat intelligence integration
- Dashboard analytics
- Historical scan comparison
- Asset inventory grouping
- Authentication and role-based access control hardening
- Export reports as PDF
- Improved remediation recommendations
- AI-assisted executive summaries through Ollama
- Formal test suite for scanner, parser, risk engine, and API routes

---

## Documentation

Additional documentation:

- Execution Guide: [README_DOCKER.md](./README_DOCKER.md)
- Internal Pipeline: [README_OPERATIONS.md](./README_OPERATIONS.md)

`README.md` provides the main project overview.

`README_DOCKER.md` explains how to build and run the project.

`README_OPERATIONS.md` explains the internal scanning pipeline, modules, environment variables, logging, and troubleshooting.

---

## Best Practice

Only scan systems that you own or have explicit permission to test.

Unauthorized scanning may violate laws, contracts, or service policies.

Do not expose `ADMIN_API_KEY.txt`, scan reports, or screenshots publicly if they contain sensitive target information.
