# Semi_project3

## Overview

Semi_project3 is a production-grade security scanning platform designed to replicate real-world penetration testing and SOC (Security Operations Center) workflows.

This system integrates multiple security tools into a unified automated pipeline:

- **Nmap** for network reconnaissance and service discovery
- **Nuclei** for vulnerability detection
- **FastAPI** for backend orchestration and API handling
- **Ollama** for optional local AI-assisted report summarization and risk explanation

Unlike basic port scanners, this project focuses on **end-to-end automation**, from initial discovery to risk-based decision making.

---

## Required Software

Install the following software before running the project.

- Docker latest version  
  https://www.docker.com/products/docker-desktop/

- Docker Compose v2 or later  
  Included in Docker Desktop

- Python 3.12  
  https://www.python.org/downloads/release/python-3120/

- Nmap latest version  
  https://nmap.org/download.html

- Nuclei latest version  
  https://github.com/projectdiscovery/nuclei/releases

- Ollama  
  https://ollama.com/download

---

## Ollama Model Setup

This project can optionally use Ollama for local AI-assisted report summarization, vulnerability explanation, and risk interpretation.

The recommended model is `gemma3:4b`.

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

---

## Installation Check

Verify that all required tools are installed correctly.

```bash
docker --version
docker compose version
python --version
nmap --version
nuclei -version
ollama --version
```

Expected result:

- Docker command prints the installed Docker version.
- Docker Compose command prints Compose v2 or later.
- Python command prints Python 3.12 or a compatible version.
- Nmap command prints the installed Nmap version.
- Nuclei command prints the installed Nuclei version.
- Ollama command prints the installed Ollama version.

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
- Risk prioritization
- Business-impact interpretation
- Actionable remediation guidance

Semi_project3 solves this limitation by linking the full security analysis chain:

```text
Ports -> Services -> Vulnerabilities -> CVE Data -> Risk Score -> Report
```

The goal is not only to find open ports, but also to explain why they matter.

---

## Full Workflow

### 1. Target Input

The user submits a scan target.

Supported target types:

- IP address
- Domain name

Example targets:

```text
192.168.0.10
example.com
```

The system receives the target through the API or Web UI and starts a scan job.

---

### 2. Network Scanning with Nmap

Nmap is used for network reconnaissance and service detection.

Example command:

```bash
nmap -sS -sV -T4 -Pn <target>
```

Purpose:

- Identify open ports
- Detect running services
- Extract service names
- Extract service versions
- Provide structured scan output

Main options:

- `-sS`: TCP SYN scan
- `-sV`: Service and version detection
- `-T4`: Faster timing profile
- `-Pn`: Treat host as online and skip host discovery

Output format:

- XML output is preferred because it is easier to parse reliably.

---

### 3. Parsing Layer

The parsing layer converts raw Nmap XML output into structured JSON data.

Extracted fields include:

- Host
- Port number
- Protocol
- Service name
- Service product
- Service version
- Port state

Example parsed result:

```json
{
  "host": "192.168.0.10",
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "version": "OpenSSH 8.9"
    }
  ]
}
```

The parser creates a normalized data structure that can be reused by later modules.

---

### 4. Vulnerability Scanning with Nuclei

Nuclei is used to detect known vulnerabilities and misconfigurations using templates.

Example command:

```bash
nuclei -u <target> -t /templates -severity medium,high,critical
```

Purpose:

- Match known vulnerability templates
- Detect CVEs
- Identify exposed panels or weak configurations
- Detect security misconfigurations

Severity levels used by default:

- Medium
- High
- Critical

The project focuses on meaningful findings rather than excessive low-severity noise.

---

### 5. CVE Enrichment

The CVE enrichment layer adds external vulnerability intelligence to scan results.

For each detected vulnerability, the system may enrich the result with:

- CVE ID
- CVSS score
- Severity level
- Vulnerability description
- Reference links
- Recommended remediation summary

Example enriched vulnerability:

```json
{
  "cve_id": "CVE-2021-41773",
  "cvss": 7.5,
  "severity": "High",
  "description": "Path traversal vulnerability in Apache HTTP Server.",
  "affected_service": "Apache HTTP Server"
}
```

This step converts raw scanner output into security intelligence that can support risk-based decisions.

---

### 6. Optional AI-Based Report Explanation

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

### 7. Risk Scoring Engine

The risk scoring engine calculates a final score based on exposed services and vulnerability severity.

Basic formula:

```text
Risk Score = Port Weight + Exposure Level + CVSS Contribution
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

### Exposure Level

Publicly exposed services receive a higher score than internal-only services.

Example:

- Public service: higher risk
- Internal service: lower risk

### CVSS Contribution

CVSS score directly contributes to the final risk score.

Higher CVSS scores increase the final risk level.

---

## Example Risk Calculation

Example case:

- Port 22 is open: `+15`
- CVSS score is 8.5: `+50`
- Public exposure: `+10`

Final calculation:

```text
15 + 50 + 10 = 75
```

Final result:

```text
75 = High Risk
```

Example risk bands:

| Score Range | Risk Level |
|---:|---|
| 0 - 19 | Low |
| 20 - 39 | Medium |
| 40 - 69 | High |
| 70 - 100 | Critical |

---

## System Architecture

```text
User
  |
  v
FastAPI Backend
  |
  v
Nmap Scanner
  |
  v
Nmap XML Parser
  |
  v
Nuclei Scanner
  |
  v
CVE Enrichment
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
 ├── main.py              # FastAPI entry point
 ├── scanner.py           # Controls the full scan workflow
 ├── nmap_runner.py       # Executes Nmap commands
 ├── nuclei_runner.py     # Executes Nuclei commands
 ├── risk.py              # Risk scoring logic
 ├── report.py            # Report generation logic
 ├── scheduler.py         # Periodic scan scheduling
 ├── worker.py            # Background task processing
 ├── cve_api.py           # CVE data fetching and enrichment
 ├── web_enrichment.py    # Additional intelligence enrichment
 ├── templates/           # HTML templates for Web UI
 └── static/              # CSS and JavaScript files
```

Suggested additional files:

```text
README.md                 # Main project documentation
README_DOCKER.md          # Docker execution guide
README_OPERATIONS.md      # Internal pipeline and operation guide
docker-compose.yml        # Docker Compose configuration
requirements.txt          # Python dependencies
.env.example              # Example environment variables
```

---

## Data Flow

The technical data flow is as follows:

1. User submits a target.
2. FastAPI creates a scan job.
3. Nmap scans the target and generates XML output.
4. Parser converts XML output into structured JSON.
5. Nuclei scans the target for vulnerabilities.
6. Nuclei results are merged with service data.
7. CVE enrichment adds vulnerability context.
8. Risk engine calculates the final score.
9. Report module generates the final result.
10. User views the result through the API or Web UI.

---

## API Design

### POST /scan

Starts a new scan job.

Request example:

```json
{
  "target": "example.com"
}
```

Response example:

```json
{
  "scan_id": "scan_001",
  "status": "queued"
}
```

---

### GET /report/{id}

Returns the final scan report.

Response includes:

- Target
- Open ports
- Services
- Vulnerabilities
- CVE enrichment data
- Risk score
- Risk level
- Recommended actions

Response example:

```json
{
  "scan_id": "scan_001",
  "target": "example.com",
  "risk_score": 75,
  "risk_level": "High",
  "ports": [],
  "vulnerabilities": []
}
```

---

## Key Design Decisions

### XML to JSON Conversion

Nmap XML output is converted into JSON because JSON is easier to process in APIs, Web UIs, and reporting modules.

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

Scanning can take time, so the project supports background task execution.

Benefits:

- API remains responsive
- Multiple scans can be queued
- Long-running scans do not block the server

### Optional Local AI Assistance

Ollama is optional and should not be required for the core scanning workflow.

The project should still produce reports even when AI-based summarization is disabled.

---

## Limitations

Current limitations:

- Results depend on Nmap and Nuclei accuracy.
- False positives may occur in template-based vulnerability scanning.
- Distributed scanning is not implemented yet.
- Real-time alerting is limited or not implemented.
- CVE enrichment depends on external data availability.
- AI-generated explanations should be reviewed before use in formal reports.

---

## Future Improvements

Planned improvements:

- Distributed scanning cluster
- Real-time alerts through Telegram or Discord
- Threat intelligence integration
- Dashboard analytics
- Historical scan comparison
- Asset inventory management
- Authentication and role-based access control
- Export reports as PDF or Markdown
- Improved remediation recommendations
- AI-assisted executive summaries through Ollama

---

## Documentation

Additional documentation:

- Execution Guide: [README_DOCKER.md](./README_DOCKER.md)
- Internal Pipeline: [README_OPERATIONS.md](./README_OPERATIONS.md)

`README.md` should provide the main project overview.

`README_DOCKER.md` should explain how to build and run the project.

`README_OPERATIONS.md` should explain the internal scanning pipeline, modules, environment variables, logging, and troubleshooting.

---

## Best Practice

Only scan systems that you own or have explicit permission to test.

Unauthorized scanning may violate laws, contracts, or service policies.
