# Semi_project3

## Overview

Semi_project3 is a production-grade security scanning platform designed to replicate real-world penetration testing and SOC (Security Operations Center) workflows.

This system integrates multiple security tools into a unified pipeline:

* nmap for network reconnaissance
* Nuclei for vulnerability detection
* FastAPI for backend orchestration and API handling

Unlike basic scanners, this project focuses on **end-to-end automation**, from initial discovery to risk-based decision making.

---

## Required Software

- Docker (latest)  
  https://www.docker.com/products/docker-desktop/

- Docker Compose v2+  
  (included in Docker Desktop)

- Python 3.12  
  https://www.python.org/downloads/release/python-3120/

- nmap (latest)  
  https://nmap.org/download.html

- Nuclei (latest)  
  https://github.com/projectdiscovery/nuclei/releases

---

## Installation Check

Verify installation:

```bash
docker --version
docker compose version
python --version
nmap --version
nuclei -version
```

---

## Problem Statement

Traditional port scanners only provide:

* Open ports
* Basic service info

They do NOT provide:

* Vulnerability context
* Risk prioritization
* Actionable intelligence

This project solves that by:

* Linking ports → services → vulnerabilities → risk score

---

## Full Workflow (Detailed)

### 1. Target Input

User submits:

* IP address
* Domain

---

### 2. Network Scanning (Nmap)

Command used:

```
nmap -sS -sV -T4 -Pn <target>
```

**Purpose**

* Identify open ports
* Detect running services
* Extract service versions

**Output**

* XML format

---

### 3. Parsing Layer

* Converts XML → structured JSON
* Extracts:

  * port
  * protocol
  * service name
  * version

---

### 4. Vulnerability Scanning (Nuclei)

Command:

```
nuclei -u <target> -t /templates -severity medium,high,critical
```

**What it does**

* Matches known vulnerability templates
* Identifies CVEs

---

### 5. Data Enrichment (CVE)

* External API calls
* Adds:

  * CVE ID
  * CVSS score
  * severity level
  * description

---

### 6. Risk Scoring Engine

Risk Score =
(Port Weight) + (Exposure Level) + (CVSS Score)

#### Components

**Port Weight**

* 22 (SSH): medium risk
* 445 (SMB): high risk
* 3389 (RDP): high risk

**Exposure**

* Public service → higher score

**CVSS**

* Directly contributes major portion

---

### Example Calculation

* Port 22 open → +15
* CVSS 8.5 → +50
* Public exposure → +10

Final Score = 75 → High Risk

---

## System Architecture

User
↓
Nmap Scanner
↓
Parser
↓
Nuclei Scanner
↓
CVE Enrichment
↓
Risk Engine
↓
Report Generator
↓
Web UI

---

## Project Structure (Detailed)

```
app/
 ├── main.py              # FastAPI entry point
 ├── scanner.py           # Controls scan flow
 ├── nmap_runner.py       # Executes Nmap
 ├── nuclei_runner.py     # Executes Nuclei
 ├── risk.py              # Risk scoring logic
 ├── report.py            # Report generator
 ├── scheduler.py         # Periodic scanning
 ├── worker.py            # Background tasks
 ├── cve_api.py           # CVE data fetching
 ├── web_enrichment.py    # Additional intelligence
 ├── templates/           # HTML UI
 └── static/              # CSS/JS
```

---

## Data Flow (Technical)

1. Nmap generates XML
2. Parser converts to JSON
3. Nuclei results merged
4. CVE API enriches vulnerabilities
5. Risk engine computes score
6. Report module outputs final result

---

## API Design

### POST /scan

* Starts scan
* Input: target
* Output: scan_id

### GET /report/{id}

* Returns:

  * ports
  * services
  * vulnerabilities
  * risk score

---

## Key Design Decisions

* XML → JSON conversion for flexibility
* Modular runners (nmap / nuclei separated)
* Risk scoring abstraction
* Async worker support for scalability

---

## Limitations

* Dependent on Nmap/Nuclei accuracy
* No distributed scanning yet
* Limited real-time alerting

---

## Future Improvements

* Distributed scanning cluster
* Real-time alerts (Telegram / Discord)
* Threat intelligence integration
* Dashboard analytics
* Historical scan comparison

---

## Documentation

* Execution Guide → [README_DOCKER.md](./README_DOCKER.md)
* Internal Pipeline → [README_OPERATIONS.md](./README_OPERATIONS.md)

---

## Best Practice

Only scan systems you own or have explicit permission to test.
