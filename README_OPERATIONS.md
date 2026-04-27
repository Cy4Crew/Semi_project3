# README_OPERATIONS

## Purpose

This document provides a detailed, code-level explanation of how the
system operates internally.\
It is intended for developers who need to understand execution flow,
module responsibilities, and data handling.

------------------------------------------------------------------------

## End-to-End Execution Flow (Detailed)

1.  Client sends request to API (/scan)
2.  FastAPI receives request in main.py
3.  scanner.py orchestrates full scan lifecycle
4.  nmap_runner executes network scan
5.  XML output is parsed into structured JSON
6.  nuclei_runner executes vulnerability scan
7.  CVE enrichment layer enhances vulnerability data
8.  risk.py calculates final risk score
9.  report.py aggregates and formats results
10. API returns structured response

------------------------------------------------------------------------

## Execution Sequence (Pseudo Code)

scan(target): ports = run_nmap(target) parsed_ports = parse_nmap(ports)

    vulnerabilities = run_nuclei(target)
    enriched_vulns = enrich_cve(vulnerabilities)

    score = calculate_risk(parsed_ports, enriched_vulns)

    return generate_report(parsed_ports, enriched_vulns, score)

------------------------------------------------------------------------

## Module Deep Dive

### 1. main.py

-   Entry point for FastAPI
-   Defines API routes
-   Handles incoming HTTP requests
-   Triggers scan process

------------------------------------------------------------------------

### 2. scanner.py (Core Orchestrator)

Responsibilities: - Controls execution order - Handles data passing
between modules - Ensures pipeline integrity

Key logic: - Sequential execution (Nmap → Nuclei → Risk) - Data
merging - Error handling

------------------------------------------------------------------------

### 3. nmap_runner.py

Execution command:

nmap -sS -sV -T4 -Pn `<target>`{=html} -oX output.xml

Details: - -sS: SYN scan (fast and stealthy) - -sV: service version
detection - -T4: performance tuning - -Pn: skip host discovery

Output: - XML file

Parsing: - Extract open ports - Extract service names - Extract versions

------------------------------------------------------------------------

### 4. Parsing Layer

Transforms: XML → JSON

Structure example:

{ "port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH
8.2" }

------------------------------------------------------------------------

### 5. nuclei_runner.py

Execution:

nuclei -u `<target>`{=html} -severity medium,high,critical -json

Processing: - Reads JSON output - Extracts: - template ID - matched
URL - severity - CVE reference

------------------------------------------------------------------------

### 6. cve_api.py (Enrichment Layer)

Function: - Calls external CVE database

Adds: - CVE ID - CVSS score - severity classification - description

------------------------------------------------------------------------

### 7. risk.py (Core Algorithm)

Input: - parsed ports - enriched vulnerabilities

Logic:

score = 0

# Port weight

if port == 22: score += 15 elif port == 445: score += 25

# Vulnerability weight

score += int(cvss \* 5)

# Exposure

if public_service: score += 10

return min(score, 100)

------------------------------------------------------------------------

### 8. report.py

Responsibilities: - Aggregate all processed data - Format into
structured JSON - Provide UI-compatible output

Example output:

{ "ports": \[...\], "services": \[...\], "vulnerabilities": \[...\],
"risk_score": 72 }

------------------------------------------------------------------------

## Data Flow (Detailed)

Nmap XML\
→ Parser (XML → JSON)\
→ Merge with Nuclei findings\
→ CVE enrichment\
→ Risk calculation\
→ Final report

------------------------------------------------------------------------

## Concurrency & Execution Model

-   FastAPI uses async endpoints
-   worker.py handles background execution
-   scheduler.py supports periodic scans

Execution types: - synchronous scan (default) - background task
execution (future scaling)

------------------------------------------------------------------------

## Error Handling

Handled scenarios: - Nmap failure → retry or partial output - Nuclei
failure → skip vulnerability stage - API failure → fallback without
enrichment

Timeout handling: - configurable via environment variables

------------------------------------------------------------------------

## Performance Considerations

-   Nmap is IO-bound → benefits from parallel execution
-   Nuclei template loading affects performance
-   Parsing optimized using streaming

------------------------------------------------------------------------

## Security Considerations

-   Input validation required for target
-   Avoid command injection (sanitize subprocess input)
-   Limit scan scope

------------------------------------------------------------------------

## Scaling Strategy

Future design: - Worker queue (Redis / RabbitMQ) - Distributed scanning
nodes - Persistent database (PostgreSQL)

------------------------------------------------------------------------

## Known Limitations

-   Dependent on external tools accuracy
-   No horizontal scaling implemented
-   Limited historical tracking

------------------------------------------------------------------------

## Best Practice

-   Always validate scan outputs before processing
-   Keep Nmap and Nuclei updated
-   Monitor scan performance and failures
