Semi_project3 README_OPERATIONS
===============================

1. Purpose of This Document
---------------------------

This document is the detailed operations guide for Semi_project3.

README.txt explains the project briefly.
README_DOCKER.txt explains Docker execution.
README_OPERATIONS.txt explains how the project works internally, how to interpret results, how to operate it, and how to present it.

This should be the most detailed document.


2. Operational Goal
-------------------

Semi_project3 is designed around this workflow:

    Discover -> Analyze -> Prioritize -> Remediate -> Verify

Meaning:

Discover:
    Find open ports.

Analyze:
    Identify service, product, version, and findings.

Prioritize:
    Calculate risk score and severity.

Remediate:
    Provide port-specific guidance.

Verify:
    Re-scan after remediation.


3. High-Level Architecture
--------------------------

Main components:

    Web UI
        User-facing dashboard.

    FastAPI Server
        Handles HTTP routes, templates, and scan requests.

    SQLite Database
        Stores targets, scan jobs, scans, ports, findings, screenshots, recommendations, and changes.

    Scanner Worker
        Executes scan logic.

    Nmap Integration
        Performs service detection.

    Nuclei Integration
        Performs template-based checks.

    Web Enrichment
        Performs HTTP probing, technology detection, and screenshot/evidence generation.

    Recommendation Engine
        Converts findings and open ports into remediation advice.

    Port Guide Engine
        Provides detailed explanation for each port.

    Report Generator
        Generates Markdown reports.


4. Data Flow
------------

The normal data flow is:

    User enters target
        ->
    Target saved to database
        ->
    Scan job created
        ->
    Port scan starts
        ->
    Nmap service detection runs
        ->
    Nuclei scan runs
        ->
    HTTP probe and evidence capture run
        ->
    Recommendations are generated
        ->
    Risk score is calculated
        ->
    Scan result is saved
        ->
    Dashboard displays final result


5. Target Input Handling
------------------------

The target must be a host.

Correct:

    scanme.nmap.org
    127.0.0.1
    host.docker.internal

Incorrect:

    http://scanme.nmap.org
    scanme.nmap.org:80
    127.0.0.1:8000

Reason:

The scanner resolves hostnames and passes them to tools such as Nmap and Nuclei.
A host:port string can cause name resolution failure.

Recommended validation improvement:

    Strip http://
    Strip https://
    Reject values containing /
    Reject values containing : unless IPv6 support is intentionally added


6. Scan Job Lifecycle
---------------------

A scan job may go through these states:

    queued
    running
    done
    partial_success
    failed

Meaning:

queued:
    Job was created but not started.

running:
    Worker is processing the job.

done:
    Scan completed normally.

partial_success:
    Core scan completed, but optional evidence or enrichment failed.

failed:
    Core scan failed.

In stable versions, screenshot failure should not make the whole scan fail.


7. Progress Stages
------------------

Expected progress stages:

    starting
    tcp_scan
    nmap
    nuclei
    enrichment
    finalizing
    done

Example:

    10% starting
    20% tcp_scan
    40% nmap
    65% nuclei
    82% enrichment
    95% finalizing
    100% done

The exact values do not need to represent real time. They are progress indicators.


8. Nmap Role
------------

Nmap is responsible for:

- Detecting open ports
- Identifying service names
- Identifying product names
- Identifying service versions
- Producing CPE values when possible

Example output:

    22/tcp open ssh OpenSSH 6.6.1p1
    80/tcp open http Apache httpd 2.4.7

Operational meaning:

    SSH open:
        Remote administration exposed.

    HTTP open:
        Web service exposed.

    Version visible:
        Useful for vulnerability mapping.


9. Nuclei Role
--------------

Nuclei is responsible for template-based detection.

It can find:

- Missing security headers
- Exposed panels
- Weak service configurations
- Known CVE patterns
- Technology fingerprints
- Informational records

Nuclei severities:

    info
    low
    medium
    high
    critical

Operational guidance:

    info:
        Useful context, not always dangerous.

    low:
        Minor issue or weak configuration.

    medium:
        Needs remediation planning.

    high:
        Should be prioritized.

    critical:
        Immediate action.


10. Technology Detection
------------------------

HTTP probing collects web-related information.

Possible detections:

- HTTP status code
- HTML title
- Server header
- X-Powered-By header
- WordPress
- Drupal
- Joomla
- Spring Boot
- React
- Vue
- Angular
- Swagger/OpenAPI
- Jenkins
- Grafana
- Kibana
- Apache default page
- Nginx default page

Example:

    URL:
        http://scanme.nmap.org

    Technology:
        Server: Apache/2.4.7 (Ubuntu)

    Evidence:
        server header


11. Evidence Handling
---------------------

Evidence can be:

    PNG screenshot
    HTML fallback evidence

PNG screenshot:
    Browser rendered the target page and saved an image.

HTML fallback:
    Screenshot was skipped or failed, but a fallback evidence file was created.

Fallback is important because:

- It prevents scan failure
- It keeps auditability
- It shows the endpoint was processed
- It works even when Playwright fails

In Docker, PNG screenshots are more reliable.
In Windows local execution, fallback mode is safer.


12. Risk Score Logic
--------------------

The risk score is a simplified exposure score.

Suggested interpretation:

    0 - 19
        Very low / informational

    20 - 39
        Low

    40 - 69
        Medium

    70 - 89
        High

    90 - 100
        Critical

Factors that increase score:

- Open SSH
- Open RDP
- Open SMB
- Open database ports
- Open Redis
- Open Docker API
- Nuclei medium/high/critical findings
- Known CVE detection
- Multiple open services
- Weak cryptographic configuration
- Missing security headers

Factors that lower practical concern:

- Test server
- Only informational findings
- Expected public web service
- No exploitable finding


13. Risk Interpretation Examples
--------------------------------

Example 1:

    Ports:
        80, 443

    Findings:
        info only

    Expected risk:
        Low

Reason:
    Common public web service with no strong finding.

Example 2:

    Ports:
        22, 80, 443

    Findings:
        SSH weak algorithm

    Expected risk:
        Medium

Reason:
    Management port is exposed and weak SSH configuration exists.

Example 3:

    Ports:
        445, 3389

    Findings:
        medium/high

    Expected risk:
        High

Reason:
    Windows management/file-sharing exposure.

Example 4:

    Ports:
        2375

    Findings:
        Docker API exposed

    Expected risk:
        Critical

Reason:
    Unauthenticated Docker API can lead to full compromise.


14. Port-Specific Operational Guide
-----------------------------------

Important ports:

21 FTP:
    Risk:
        Cleartext authentication and file exposure.

    Action:
        Replace with SFTP or FTPS.
        Block public access.

22 SSH:
    Risk:
        Brute-force and remote administration exposure.

    Action:
        Use VPN or IP allowlist.
        Disable password login.
        Disable root login.

23 Telnet:
    Risk:
        Cleartext remote administration.

    Action:
        Disable immediately.
        Replace with SSH.

25 SMTP:
    Risk:
        Open relay or mail abuse.

    Action:
        Verify relay policy.
        Restrict mail submission.

53 DNS:
    Risk:
        Zone transfer and amplification.

    Action:
        Disable recursion for external users.
        Restrict zone transfer.

80 HTTP:
    Risk:
        Cleartext web traffic.

    Action:
        Redirect to HTTPS.
        Add security headers.

443 HTTPS:
    Risk:
        Weak TLS or vulnerable web app.

    Action:
        Review TLS config.
        Patch application.

445 SMB:
    Risk:
        File sharing exposure and remote exploitation.

    Action:
        Block from public networks.

3389 RDP:
    Risk:
        Brute-force and remote desktop compromise.

    Action:
        Use VPN.
        Enable NLA.
        Apply MFA.

3306 MySQL:
    Risk:
        Database exposure.

    Action:
        Bind to private interface.
        Block public access.

5432 PostgreSQL:
    Risk:
        Database exposure.

    Action:
        Restrict network access.
        Enforce authentication.

6379 Redis:
    Risk:
        Unauthenticated data access.

    Action:
        Bind to localhost/private network.
        Enable protected mode.

9200 Elasticsearch:
    Risk:
        Data leakage.

    Action:
        Enable authentication.
        Restrict access.

2375 Docker API:
    Risk:
        Critical host compromise risk.

    Action:
        Disable public API.
        Use TLS on 2376 if remote API is required.


15. Recommendation Engine
-------------------------

The recommendation engine should produce guidance from:

- Open port type
- Service name
- Product name
- Nuclei template ID
- Finding severity
- Known CVE pattern

Example:

    Port 22 open
        Recommendation:
        Restrict SSH by VPN or allowlist.

    http-missing-security-headers
        Recommendation:
        Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options.

    CVE-2023-48795
        Recommendation:
        Upgrade OpenSSH and disable affected algorithms.


16. Port Detail Page Operations
-------------------------------

The port detail page is one of the most important features.

It should answer:

- What is this port?
- Why is it open?
- Is it dangerous?
- When is it acceptable?
- How do I close or harden it?
- How do I verify the fix?

Good page sections:

- Overview
- Risk Factors
- Linux Fix
- Windows Fix
- Hardening
- Verification
- Recent Assets
- Related CVEs


17. Scheduler Operations
------------------------

The scheduler is useful for repeated monitoring.

Important concept:

    Scheduled scans only run while the application is running.

If the application is stopped:

    No scheduled scan runs.

Docker recommendation:

    Use restart: unless-stopped

Operational use:

    Daily scan at fixed time
    Detect new open ports
    Compare changes
    Track risk trend


18. Change Detection
--------------------

Change detection should identify:

- New open port
- Closed port
- New finding
- Removed finding
- Service version change
- Risk score change

Example:

    baseline_created
        First scan for this target.

    new_port
        A port appeared that was not open before.

    removed_port
        A previously open port disappeared.

Operational value:

    Change detection helps catch accidental exposure.


19. Database Operations
-----------------------

SQLite is used for local simplicity.

Recommended SQLite settings:

- WAL mode
- busy_timeout
- short transactions
- close connections quickly

Why:

    Scans can write several result types.
    Without WAL and timeout, database is locked errors can occur.

For larger use:

    PostgreSQL is recommended.


20. Important Tables Concept
----------------------------

Possible tables:

targets:
    Registered scan targets.

scan_jobs:
    Scan job status, progress, stage, message.

scans:
    Completed scan metadata.

ports:
    Open ports and services.

findings:
    Nuclei findings.

screenshots:
    PNG or HTML evidence.

recommendations:
    Suggested remediation.

changes:
    Difference from previous scan.


21. Log Interpretation
----------------------

Normal logs:

    GET / HTTP/1.1 200 OK
    POST /targets 303 See Other
    POST /scan/1 303 See Other
    GET /scans/1 200 OK

Meaning:

    Web UI loaded.
    Target added.
    Scan started.
    Result page opened.

Problem logs:

    404 Not Found
        Page or scan ID does not exist.

    500 Internal Server Error
        Application exception.

    database is locked
        SQLite contention.

    Name or service not known
        Invalid target format or DNS failure.


22. Operating Rules
-------------------

Recommended:

- Use Docker for demos
- Scan only authorized targets
- Do not include ports in target input
- Avoid repeated rapid scan clicks
- Check logs when something fails
- Use port detail pages for explanation
- Use Markdown reports for submission evidence


23. Demo Script
---------------

Suggested presentation script:

1. "This is Semi_project3, a service port scanner."
2. "The user enters a target host."
3. "The system scans open ports using Nmap."
4. "It identifies service name, product, version, and CPE."
5. "Nuclei checks add security findings."
6. "The system calculates a risk score."
7. "Each open port links to a remediation guide."
8. "Evidence is stored as screenshot or HTML fallback."
9. "The final result can be downloaded as a report."


24. Evaluation Points
---------------------

Strong points for grading:

- Nmap is actually integrated
- Nuclei is actually integrated
- Results are displayed clearly
- Port results are interpreted
- Remediation guidance exists
- Docker makes the demo reproducible
- Screenshot/evidence exists
- Risk score helps prioritize
- Project goes beyond a basic CLI scanner


25. Future Improvements
-----------------------

Possible future work:

- PostgreSQL migration
- User login
- Role-based access
- CSV/JSON export
- Email alerts
- Slack/Discord alerts
- Asset grouping
- Subdomain discovery
- TLS analysis
- DNS security checks
- CVE API caching
- Scan policy profiles
- Multi-target batch scanning
- Historical charts


26. Final Operational Summary
-----------------------------

Semi_project3 should be presented as:

    "A service port scanner that identifies exposed services and provides practical security guidance."

The project is aligned with the assignment topic because the core remains service port scanning.

The added features improve practical value:

- Risk score
- Findings
- Evidence
- Remediation
- Dashboard
- Docker deployment
