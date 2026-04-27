PORT_GUIDES = {
    21: {
        "service": "FTP",
        "title": "FTP Service Exposure",
        "summary": "FTP is used for file transfer, but plain FTP does not encrypt credentials or data.",
        "risk_level": "Medium",
        "risks": [
            "Credentials may be exposed over cleartext FTP.",
            "Anonymous access may expose files.",
            "Old FTP daemons often contain known vulnerabilities."
        ],
        "linux_fix": [
            "sudo ufw deny 21",
            "sudo firewall-cmd --permanent --remove-service=ftp",
            "sudo firewall-cmd --reload",
            "Replace FTP with SFTP or FTPS where file transfer is required."
        ],
        "windows_fix": [
            "Open Windows Defender Firewall with Advanced Security.",
            "Create an inbound block rule for TCP 21.",
            "If IIS FTP is used, disable public FTP binding or restrict allowed IP ranges."
        ],
        "hardening": [
            "Disable anonymous login.",
            "Use SFTP/FTPS instead of FTP.",
            "Restrict access by VPN or IP allowlist.",
            "Monitor upload directories for webshell or malware upload attempts."
        ],
        "verify": [
            "nmap -p 21 <target>",
            "Confirm that TCP 21 is filtered or closed from external networks."
        ]
    },
    22: {
        "service": "SSH",
        "title": "SSH Service Exposure",
        "summary": "SSH is used for remote administration. It is safe when hardened, but risky when exposed broadly.",
        "risk_level": "Medium",
        "risks": [
            "Brute-force login attempts.",
            "Password-based authentication abuse.",
            "Weak cipher, MAC, or key exchange algorithms.",
            "Root login exposure."
        ],
        "linux_fix": [
            "sudo ufw deny 22",
            "sudo firewall-cmd --permanent --remove-service=ssh",
            "sudo firewall-cmd --reload",
            "sudo systemctl restart sshd"
        ],
        "windows_fix": [
            "Open Windows Defender Firewall with Advanced Security.",
            "Create an inbound block rule for TCP 22.",
            "If OpenSSH Server is installed, restrict access by IP allowlist."
        ],
        "hardening": [
            "Set PasswordAuthentication no in /etc/ssh/sshd_config.",
            "Set PermitRootLogin no.",
            "Use AllowUsers or AllowGroups.",
            "Use key-based authentication.",
            "Restrict SSH to VPN or management IP ranges.",
            "Enable fail2ban or equivalent login protection."
        ],
        "verify": [
            "nmap -p 22 <target>",
            "ssh -o PreferredAuthentications=password <user>@<target>",
            "Check /var/log/auth.log or journalctl -u ssh."
        ]
    },
    23: {
        "service": "Telnet",
        "title": "Telnet Exposure",
        "summary": "Telnet is an insecure remote administration protocol that transmits data in cleartext.",
        "risk_level": "High",
        "risks": [
            "Credentials are transmitted in cleartext.",
            "Session traffic can be intercepted.",
            "Telnet exposure is commonly targeted by automated attacks."
        ],
        "linux_fix": [
            "sudo systemctl disable --now telnet.socket",
            "sudo ufw deny 23",
            "sudo firewall-cmd --permanent --remove-port=23/tcp",
            "sudo firewall-cmd --reload"
        ],
        "windows_fix": [
            "Disable Telnet Server feature.",
            "Block TCP 23 inbound in Windows Defender Firewall."
        ],
        "hardening": [
            "Replace Telnet with SSH.",
            "Restrict management interfaces to internal networks.",
            "Review devices such as routers, switches, and legacy appliances."
        ],
        "verify": [
            "nmap -p 23 <target>",
            "telnet <target> 23 should fail from external networks."
        ]
    },
    80: {
        "service": "HTTP",
        "title": "HTTP Service Exposure",
        "summary": "HTTP provides unencrypted web access. It is common, but should be redirected to HTTPS when sensitive data exists.",
        "risk_level": "Low",
        "risks": [
            "Cleartext traffic can expose cookies, tokens, and credentials.",
            "Missing security headers may increase browser-side attack surface.",
            "Default pages or old web servers reveal stack information."
        ],
        "linux_fix": [
            "sudo ufw deny 80",
            "Configure Apache/Nginx to redirect HTTP to HTTPS.",
            "Apache: Redirect permanent / https://example.com/",
            "Nginx: return 301 https://$host$request_uri;"
        ],
        "windows_fix": [
            "Block TCP 80 inbound if HTTP is unnecessary.",
            "In IIS, configure HTTPS binding and HTTP to HTTPS redirect."
        ],
        "hardening": [
            "Use HTTPS on TCP 443.",
            "Apply HSTS after HTTPS is validated.",
            "Add CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
            "Remove default pages and directory listing.",
            "Keep Apache/Nginx/IIS updated."
        ],
        "verify": [
            "curl -I http://<target>",
            "Confirm 301/302 redirect to HTTPS or TCP 80 blocked if unnecessary."
        ]
    },
    443: {
        "service": "HTTPS",
        "title": "HTTPS Service Exposure",
        "summary": "HTTPS is the standard secure web service port. It should remain open only for intended public web services.",
        "risk_level": "Low",
        "risks": [
            "Weak TLS versions or ciphers.",
            "Expired or mismatched certificates.",
            "Vulnerable web application behind TLS."
        ],
        "linux_fix": [
            "Keep 443 open only if the web service is intended to be public.",
            "sudo ufw allow 443",
            "Use certbot or enterprise certificate management for valid TLS certificates."
        ],
        "windows_fix": [
            "Allow TCP 443 only for intended public IIS/site services.",
            "Review IIS TLS certificate binding.",
            "Disable legacy TLS through Windows registry or group policy."
        ],
        "hardening": [
            "Disable TLS 1.0/1.1.",
            "Use modern cipher suites.",
            "Enable HSTS.",
            "Renew certificates before expiration.",
            "Patch the web application and server."
        ],
        "verify": [
            "nmap --script ssl-enum-ciphers -p 443 <target>",
            "curl -Iv https://<target>"
        ]
    },
    445: {
        "service": "SMB",
        "title": "SMB Exposure",
        "summary": "SMB is used for Windows file sharing and should not be exposed to the public internet.",
        "risk_level": "High",
        "risks": [
            "Remote exploitation of SMB vulnerabilities.",
            "Credential relay and brute-force attacks.",
            "Information disclosure through shares."
        ],
        "linux_fix": [
            "sudo ufw deny 445",
            "sudo firewall-cmd --permanent --remove-service=samba",
            "sudo firewall-cmd --reload"
        ],
        "windows_fix": [
            "Block TCP 445 inbound on public profiles.",
            "Disable SMB exposure to external networks.",
            "Restrict file sharing to private/VPN networks."
        ],
        "hardening": [
            "Disable SMBv1.",
            "Require SMB signing where appropriate.",
            "Restrict shares by least privilege.",
            "Monitor authentication failures and share access."
        ],
        "verify": [
            "nmap -p 445 <target>",
            "net view \\\\<target> should not work externally."
        ]
    },
    3389: {
        "service": "RDP",
        "title": "RDP Exposure",
        "summary": "RDP is used for Windows remote desktop administration and is high risk when directly exposed.",
        "risk_level": "High",
        "risks": [
            "Brute-force attacks.",
            "Credential stuffing.",
            "Exploitation of RDP vulnerabilities.",
            "Lateral movement after compromise."
        ],
        "linux_fix": [
            "If xrdp is used, block TCP 3389 externally.",
            "sudo ufw deny 3389"
        ],
        "windows_fix": [
            "Block TCP 3389 inbound from the internet.",
            "Allow RDP only through VPN or specific management IPs.",
            "Enable Network Level Authentication.",
            "Enforce account lockout policy and MFA where possible."
        ],
        "hardening": [
            "Use VPN or zero-trust access.",
            "Restrict source IPs.",
            "Enable NLA.",
            "Monitor Event ID 4625 and RDP logon events.",
            "Use strong passwords and MFA."
        ],
        "verify": [
            "nmap -p 3389 <target>",
            "Test from external network that RDP is filtered or closed."
        ]
    },
    6379: {
        "service": "Redis",
        "title": "Redis Exposure",
        "summary": "Redis should not be publicly exposed. Public Redis can lead to data leakage or server compromise.",
        "risk_level": "High",
        "risks": [
            "Unauthenticated data access.",
            "Remote command abuse through unsafe configuration.",
            "Persistence abuse and potential server compromise."
        ],
        "linux_fix": [
            "sudo ufw deny 6379",
            "Set bind 127.0.0.1 or private IP in redis.conf.",
            "Set protected-mode yes.",
            "Set requirepass or ACL authentication."
        ],
        "windows_fix": [
            "Block TCP 6379 inbound.",
            "Bind Redis to localhost/private network only.",
            "Require authentication."
        ],
        "hardening": [
            "Never expose Redis directly to the internet.",
            "Use private networks.",
            "Enable authentication and ACLs.",
            "Disable dangerous commands if needed."
        ],
        "verify": [
            "nmap -p 6379 <target>",
            "redis-cli -h <target> ping should fail externally."
        ]
    },
    9200: {
        "service": "Elasticsearch",
        "title": "Elasticsearch Exposure",
        "summary": "Elasticsearch contains indexed data and should be authenticated and restricted.",
        "risk_level": "High",
        "risks": [
            "Data leakage.",
            "Unauthorized search/index modification.",
            "Cluster metadata exposure."
        ],
        "linux_fix": [
            "sudo ufw deny 9200",
            "Bind Elasticsearch to private interfaces.",
            "Enable authentication and TLS."
        ],
        "windows_fix": [
            "Block TCP 9200 inbound.",
            "Restrict Elasticsearch to private network interfaces."
        ],
        "hardening": [
            "Enable xpack security.",
            "Use TLS.",
            "Restrict access through reverse proxy or VPN.",
            "Review exposed indices."
        ],
        "verify": [
            "curl http://<target>:9200 should not expose cluster information externally."
        ]
    },
    2375: {
        "service": "Docker API",
        "title": "Docker API Exposure",
        "summary": "Docker API on TCP 2375 without TLS is critical. It may allow full container and host compromise.",
        "risk_level": "Critical",
        "risks": [
            "Unauthenticated Docker control.",
            "Container creation with privileged mounts.",
            "Potential host compromise."
        ],
        "linux_fix": [
            "Remove tcp://0.0.0.0:2375 from Docker daemon configuration.",
            "Use unix:///var/run/docker.sock locally.",
            "If remote API is required, use TLS on 2376.",
            "sudo systemctl restart docker"
        ],
        "windows_fix": [
            "Disable Docker API exposure on TCP 2375.",
            "Restrict Docker Desktop/daemon remote access.",
            "Use TLS-secured remote Docker only if required."
        ],
        "hardening": [
            "Never expose Docker API without TLS.",
            "Restrict by firewall and VPN.",
            "Monitor Docker daemon logs.",
            "Audit containers and mounted host paths."
        ],
        "verify": [
            "curl http://<target>:2375/version should fail externally.",
            "nmap -p 2375 <target>"
        ]
    },
    27017: {
        "service": "MongoDB",
        "title": "MongoDB Exposure",
        "summary": "MongoDB should be private and authenticated. Public exposure can leak application data.",
        "risk_level": "High",
        "risks": [
            "Unauthorized database access.",
            "Data exfiltration.",
            "Ransom or destructive database attacks."
        ],
        "linux_fix": [
            "sudo ufw deny 27017",
            "Set bindIp to 127.0.0.1/private IP in mongod.conf.",
            "Enable authorization."
        ],
        "windows_fix": [
            "Block TCP 27017 inbound.",
            "Bind MongoDB to localhost/private interface.",
            "Enable authentication."
        ],
        "hardening": [
            "Use private network only.",
            "Enable authentication and role-based access.",
            "Enable TLS where needed.",
            "Monitor audit logs."
        ],
        "verify": [
            "nmap -p 27017 <target>",
            "mongosh mongodb://<target>:27017 should fail externally."
        ]
    }
}


def get_port_guide(port: int) -> dict:
    return PORT_GUIDES.get(int(port), {
        "service": "Unknown",
        "title": f"Port {port} Exposure",
        "summary": "This port is open. Confirm whether the exposed service is required.",
        "risk_level": "Review",
        "risks": [
            "Unexpected external exposure.",
            "Unknown service behavior.",
            "Potential vulnerable or misconfigured application."
        ],
        "linux_fix": [
            f"sudo ufw deny {port}",
            f"sudo firewall-cmd --permanent --remove-port={port}/tcp",
            "sudo firewall-cmd --reload"
        ],
        "windows_fix": [
            f"Create an inbound block rule for TCP {port} in Windows Defender Firewall.",
            "If the service is required, restrict source IP ranges."
        ],
        "hardening": [
            "Verify business necessity.",
            "Restrict by firewall or security group.",
            "Patch the service.",
            "Enable authentication and logging.",
            "Monitor connection attempts."
        ],
        "verify": [
            f"nmap -p {port} <target>",
            "Confirm the port is filtered/closed externally after remediation."
        ]
    })


# Auto-extended common ports
PORT_GUIDES.update({
25: {
        "service":"SMTP","title":"SMTP Exposure","summary":"SMTP service detected on port 25. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 25","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 25 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 25 <target>","Confirm service is filtered or access-controlled externally"]
    },
53: {
        "service":"DNS","title":"DNS Exposure","summary":"DNS service detected on port 53. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 53","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 53 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 53 <target>","Confirm service is filtered or access-controlled externally"]
    },
110: {
        "service":"POP3","title":"POP3 Exposure","summary":"POP3 service detected on port 110. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 110","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 110 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 110 <target>","Confirm service is filtered or access-controlled externally"]
    },
143: {
        "service":"IMAP","title":"IMAP Exposure","summary":"IMAP service detected on port 143. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 143","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 143 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 143 <target>","Confirm service is filtered or access-controlled externally"]
    },
161: {
        "service":"SNMP","title":"SNMP Exposure","summary":"SNMP service detected on port 161. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 161","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 161 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 161 <target>","Confirm service is filtered or access-controlled externally"]
    },
389: {
        "service":"LDAP","title":"LDAP Exposure","summary":"LDAP service detected on port 389. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 389","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 389 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 389 <target>","Confirm service is filtered or access-controlled externally"]
    },
636: {
        "service":"LDAPS","title":"LDAPS Exposure","summary":"LDAPS service detected on port 636. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 636","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 636 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 636 <target>","Confirm service is filtered or access-controlled externally"]
    },
465: {
        "service":"SMTPS","title":"SMTPS Exposure","summary":"SMTPS service detected on port 465. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 465","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 465 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 465 <target>","Confirm service is filtered or access-controlled externally"]
    },
587: {
        "service":"SMTP Submission","title":"SMTP Submission Exposure","summary":"SMTP Submission service detected on port 587. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 587","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 587 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 587 <target>","Confirm service is filtered or access-controlled externally"]
    },
993: {
        "service":"IMAPS","title":"IMAPS Exposure","summary":"IMAPS service detected on port 993. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 993","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 993 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 993 <target>","Confirm service is filtered or access-controlled externally"]
    },
995: {
        "service":"POP3S","title":"POP3S Exposure","summary":"POP3S service detected on port 995. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 995","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 995 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 995 <target>","Confirm service is filtered or access-controlled externally"]
    },
1433: {
        "service":"MSSQL","title":"MSSQL Exposure","summary":"MSSQL service detected on port 1433. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 1433","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 1433 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 1433 <target>","Confirm service is filtered or access-controlled externally"]
    },
1521: {
        "service":"Oracle","title":"Oracle Exposure","summary":"Oracle service detected on port 1521. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 1521","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 1521 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 1521 <target>","Confirm service is filtered or access-controlled externally"]
    },
3306: {
        "service":"MySQL","title":"MySQL Exposure","summary":"MySQL service detected on port 3306. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 3306","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 3306 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 3306 <target>","Confirm service is filtered or access-controlled externally"]
    },
5432: {
        "service":"PostgreSQL","title":"PostgreSQL Exposure","summary":"PostgreSQL service detected on port 5432. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 5432","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 5432 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 5432 <target>","Confirm service is filtered or access-controlled externally"]
    },
5900: {
        "service":"VNC","title":"VNC Exposure","summary":"VNC service detected on port 5900. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 5900","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 5900 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 5900 <target>","Confirm service is filtered or access-controlled externally"]
    },
8080: {
        "service":"HTTP Alt","title":"HTTP Alt Exposure","summary":"HTTP Alt service detected on port 8080. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 8080","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 8080 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 8080 <target>","Confirm service is filtered or access-controlled externally"]
    },
8443: {
        "service":"HTTPS Alt","title":"HTTPS Alt Exposure","summary":"HTTPS Alt service detected on port 8443. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 8443","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 8443 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 8443 <target>","Confirm service is filtered or access-controlled externally"]
    },
11211: {
        "service":"Memcached","title":"Memcached Exposure","summary":"Memcached service detected on port 11211. Verify whether public exposure is intended.","risk_level":"Medium",
        "risks":["Unauthorized access","Old software vulnerabilities","Misconfiguration exposure"],
        "linux_fix":["sudo ufw deny 11211","Restrict service bind address","Restart service after config changes"],
        "windows_fix":["Block TCP 11211 inbound in Windows Defender Firewall","Restrict source IP ranges"],
        "hardening":["Enable authentication","Use TLS if supported","Patch regularly","Allowlist management IPs"],
        "verify":["nmap -p 11211 <target>","Confirm service is filtered or access-controlled externally"]
    },
})
