PORT_RECOMMENDATIONS = {
    21: ("FTP Service Exposure", "Disable FTP if unnecessary. Prefer SFTP/FTPS and block public access."),
    22: ("SSH Service Exposure", "Restrict SSH by IP allowlist or VPN. Disable password login if possible and use key-based authentication."),
    23: ("Telnet Exposure", "Disable Telnet immediately and replace it with SSH."),
    80: ("HTTP Service Exposure", "Redirect HTTP to HTTPS and apply secure headers."),
    443: ("HTTPS Service Exposure", "Check TLS configuration, certificate validity, and secure response headers."),
    445: ("SMB Exposure", "Block SMB from the internet and restrict access through VPN or internal networks."),
    3389: ("RDP Exposure", "Restrict RDP by VPN, IP allowlist, MFA, and account lockout policy."),
    5900: ("VNC Exposure", "Restrict VNC access and require strong authentication over VPN."),
    6379: ("Redis Exposure", "Do not expose Redis publicly. Bind to localhost/private network and require authentication."),
    9200: ("Elasticsearch Exposure", "Restrict Elasticsearch access and enable authentication/TLS."),
    2375: ("Docker API Exposure", "Disable unauthenticated Docker API or expose only over TLS with strict access control."),
    27017: ("MongoDB Exposure", "Restrict MongoDB to private networks and enforce authentication."),
}

SEVERITY_RECOMMENDATIONS = {
    "critical": "Prioritize immediate remediation. Validate exposure, patch the affected component, and restrict access.",
    "high": "Plan urgent remediation. Confirm exploitability and apply patches or configuration hardening.",
    "medium": "Schedule remediation. Reduce exposure and apply vendor-recommended mitigations.",
    "low": "Track and fix during regular maintenance.",
    "info": "Use as supporting evidence. No direct risk score increase unless combined with exposure.",
}

TEMPLATE_RECOMMENDATIONS = [
    ("http-missing-security-headers", "Missing HTTP Security Headers", "Add appropriate security headers such as HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."),
    ("ssh-weak", "SSH Weak Algorithm", "Disable weak SSH algorithms. Prefer modern KEX, MAC, and ciphers such as curve25519, chacha20-poly1305, and AES-GCM."),
    ("ssh-cbc", "SSH CBC Ciphers Enabled", "Disable CBC mode ciphers and prefer CTR/GCM or chacha20-poly1305 based ciphers."),
    ("ssh-diffie-hellman-logjam", "SSH Diffie-Hellman Weak Modulus", "Disable weak Diffie-Hellman groups and use stronger key exchange algorithms."),
    ("ssh-password-auth", "SSH Password Authentication", "Disable password-based SSH login where possible and enforce key-based authentication."),
    ("CVE-2023-48795", "OpenSSH Terrapin Attack", "Upgrade OpenSSH and related SSH implementations to patched versions. Disable affected weak algorithm combinations."),
    ("apache-mod-negotiation-listing", "Apache Content Negotiation Listing", "Disable MultiViews/content negotiation where unnecessary and review exposed files."),
    ("options-method", "HTTP OPTIONS Method", "Restrict unnecessary HTTP methods and validate allowed method configuration."),
]


def _row_get(row, key, default=None):
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default


def build_recommendations(services, findings):
    rows = []
    seen = set()

    for service in services:
        port = int(_row_get(service, "port", 0) or 0)
        if port in PORT_RECOMMENDATIONS:
            title, rec = PORT_RECOMMENDATIONS[port]
            key = f"port:{port}"
            if key not in seen:
                seen.add(key)
                severity = "high" if port in {23, 2375, 3389, 445} else "medium"
                rows.append({"severity": severity, "title": title, "recommendation": rec, "source": f"port:{port}"})

    for finding in findings:
        sev = str(_row_get(finding, "severity", "info")).lower()
        template = str(_row_get(finding, "template_id", ""))
        name = str(_row_get(finding, "name", ""))

        matched = False
        for token, title, rec in TEMPLATE_RECOMMENDATIONS:
            if token.lower() in template.lower() or token.lower() in name.lower():
                key = f"template:{token}"
                if key not in seen:
                    seen.add(key)
                    rows.append({"severity": sev, "title": title, "recommendation": rec, "source": template or token})
                matched = True
                break

        if not matched and sev in {"critical", "high", "medium"}:
            key = f"finding:{template}:{sev}"
            if key not in seen:
                seen.add(key)
                rows.append({
                    "severity": sev,
                    "title": name or template or "Nuclei Finding",
                    "recommendation": SEVERITY_RECOMMENDATIONS.get(sev, SEVERITY_RECOMMENDATIONS["medium"]),
                    "source": template,
                })

    if not rows:
        rows.append({
            "severity": "info",
            "title": "No Immediate Remediation Item",
            "recommendation": "No high-priority issue was detected. Continue scheduled monitoring.",
            "source": "system",
        })

    return rows
