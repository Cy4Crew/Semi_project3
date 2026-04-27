
def map_cves(product: str, version: str):
    text = f"{product} {version}".lower()
    rows = []
    if "openssh" in text:
        rows.append({"cve":"CVE-2023-48795","severity":"medium","title":"Terrapin prefix truncation attack","fix":"Upgrade OpenSSH / SSH stack"})
    if "apache" in text:
        rows.append({"cve":"CVE-2021-41773","severity":"high","title":"Apache path traversal (older versions)","fix":"Upgrade Apache HTTP Server"})
    if "nginx" in text:
        rows.append({"cve":"CVE-2021-23017","severity":"medium","title":"Nginx resolver vulnerability","fix":"Upgrade Nginx"})
    if "redis" in text:
        rows.append({"cve":"CVE-2022-0543","severity":"high","title":"Redis Lua sandbox escape (package dependent)","fix":"Patch package / upgrade"})
    if "mysql" in text:
        rows.append({"cve":"CVE-2016-6662","severity":"high","title":"MySQL config injection class issue","fix":"Upgrade MySQL"})
    return rows

def exposure_decision(port:int):
    p=int(port)
    if p in {3306,5432,27017,6379,445,2375,9200}:
        return {"level":"Critical","message":"Database or infrastructure service publicly exposed. Immediate remediation recommended."}
    if p in {22,23,3389,5900}:
        return {"level":"High","message":"Administrative remote access exposed. Restrict by VPN or allowlist."}
    if p in {80,443,8080,8443}:
        return {"level":"Normal","message":"Common web service exposure. Validate patching and TLS configuration."}
    return {"level":"Review","message":"Unknown exposure. Validate business necessity and restrict access if unnecessary."}
