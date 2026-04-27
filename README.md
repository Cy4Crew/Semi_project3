Semi_project3 README
====================

## Documents

- [README](README.md)
- [Docker](README_DOCKER.md)
- [Operations](README_OPERATIONS.md)

1. Project Overview
-------------------

Semi_project3 is a service port scanner implementation project.

The main purpose of this project is to scan a target host, detect open ports, identify the services running on those ports, and help the user understand the security meaning of the results.

The project uses:

- Nmap for port scanning and service detection
- Nuclei for template-based security checks
- FastAPI for the web dashboard
- SQLite for local scan result storage
- Playwright / Chromium for screenshot evidence
- Docker for stable execution

This project can be introduced as:

    "A service port scanner that expands open-port results into service analysis, risk scoring, evidence collection, and remediation guidance."


2. Why This Project Fits the Assignment
---------------------------------------

The assignment topic is a service port scanner.

A basic service port scanner should provide:

1. Target input
2. Open port detection
3. Service identification
4. Result output

Semi_project3 provides all of these.

In addition, it includes:

- Service version detection
- Risk scoring
- Nuclei finding integration
- Port-specific remediation guide
- Screenshot evidence
- Markdown report
- Dashboard view
- Docker execution support

Therefore, this project satisfies the service port scanner requirement and adds practical security operation features.


3. Main Features
----------------

Semi_project3 includes the following features.

Target Management:

- Add scan target
- View registered assets
- Run manual scan
- Track scan history

Port Scanning:

- Detect open TCP ports
- Identify service name
- Identify product name
- Identify service version
- Display CPE if available

Security Analysis:

- Run Nuclei templates
- Collect security findings
- Group findings by severity
- Generate recommendations
- Calculate risk score

Evidence:

- Web screenshot capture
- HTML fallback evidence when screenshot capture is unavailable
- Evidence link on scan result page

Remediation:

- Port detail page
- Linux hardening guide
- Windows hardening guide
- Verification commands
- Recommended response by service type

Dashboard:

- Scan result summary
- Open port table
- Technology detection table
- Finding table
- Severity summary
- Live server clock
- Report download


4. Execution Methods
--------------------

There are two execution methods.

Method 1: Docker execution

Recommended for:

- Presentation
- Stable screenshot capture
- Environment consistency
- Avoiding Windows Playwright issues

Run:

    run_docker.bat

Open:

    http://127.0.0.1:8000


Method 2: Windows local execution

Recommended for:

- Simple local testing
- Fast code debugging
- Environments where Docker is unavailable

Run:

    run.bat

Open:

    http://127.0.0.1:8000


5. Target Input Rules
---------------------

Semi_project3 expects a host or IP address.

Correct examples:

    scanme.nmap.org
    testphp.vulnweb.com
    demo.testfire.net
    127.0.0.1
    host.docker.internal
    192.168.0.10

Incorrect examples:

    http://scanme.nmap.org
    https://example.com
    127.0.0.1:8000
    scanme.nmap.org:80
    example.com/login

Do not include:

- URL scheme such as http:// or https://
- Port number such as :8000
- Path such as /admin or /login

Reason:

The scanner handles the target as a host. If a URL or host:port value is entered, name resolution may fail.

Common error:

    failed: [Errno -2] Name or service not known

Fix:

    Use 127.0.0.1 instead of 127.0.0.1:8000.


6. Recommended Test Targets
---------------------------

Use only authorized systems.

Safe public test targets:

    scanme.nmap.org
    testphp.vulnweb.com
    demo.testfire.net
    neverssl.com
    badssl.com

Local vulnerable labs:

    DVWA
    OWASP Juice Shop
    Metasploitable2
    Metasploitable3

Recommended presentation targets:

    scanme.nmap.org
        Good for Nmap and service port scanning demonstration.

    testphp.vulnweb.com
        Good for web finding demonstration.

    Local DVWA or Juice Shop
        Good for controlled vulnerable web application demonstration.


7. How to Read the Result
-------------------------

Example result:

    22/tcp open ssh OpenSSH 6.6.1
    80/tcp open http Apache httpd 2.4.7

Interpretation:

    22/tcp
        TCP port 22 is open.
        SSH service is running.
        Remote administration may be possible.

    80/tcp
        TCP port 80 is open.
        HTTP web service is running.
        Apache web server was detected.

Fields:

    Port
        Network port number.

    Service
        Service name detected by Nmap.

    Product
        Software product name.

    Version
        Detected version.

    CPE
        Common Platform Enumeration string used for vulnerability mapping.

    Source
        Tool or module that produced the data.


8. Risk Score
-------------

The risk score summarizes the exposure level.

Example range:

    0 - 19      Very Low
    20 - 39     Low
    40 - 69     Medium
    70 - 89     High
    90 - 100    Critical

Risk score can increase when:

- More ports are open
- Management ports are exposed
- Database ports are exposed
- Nuclei findings exist
- Medium or high severity findings exist
- Known CVE-related findings are detected
- Weak security configuration is found

Risk score can stay low when:

- Only common web ports are open
- Findings are informational
- The host is an intentionally exposed test server
- No strong vulnerability is detected


9. Port Detail Page
-------------------

Each detected port is clickable.

Example:

    22/tcp -> /ports/22
    80/tcp -> /ports/80

The port detail page provides:

- Service description
- Risk explanation
- Linux remediation commands
- Windows remediation steps
- Hardening checklist
- Verification commands
- Recent assets where the port was found
- Related CVE information if available

This feature is important because it turns the scanner into an actionable tool.


10. Reports
-----------

Semi_project3 supports Markdown report download.

The report can include:

- Target
- Scan status
- Risk score
- Open ports
- Services
- Findings
- Recommendations
- Changes
- Evidence references

PDF output is not required in this version.


11. Common Problems
-------------------

Problem:

    Target scan fails with name resolution error.

Cause:

    Target format is wrong.

Fix:

    Enter host only.

Problem:

    Screenshot is not generated.

Cause:

    Playwright or Chromium capture failed.

Fix:

    Use Docker or rely on HTML fallback evidence.

Problem:

    Nmap not recognized.

Cause:

    Nmap is not installed or PATH is missing.

Fix:

    Use Docker or install Nmap on Windows.

Problem:

    Nuclei not recognized.

Cause:

    Nuclei is not installed or PATH is missing.

Fix:

    Use Docker or install Nuclei on Windows.


12. Legal Notice
----------------

Only scan systems you own or have explicit permission to test.

Do not scan random public systems.

Recommended safe environments:

- Localhost
- Docker labs
- Official test targets
- Training systems
- Assigned lab infrastructure
