"""
Risk Scoring module smoke tests.

Run from project root:
    python test_risk_scoring.py

This does not require nmap/nuclei. It validates the role #4 scoring engine with
controlled evidence so CVSS/EPSS/KEV behavior can be checked without relying on
an external vulnerable target.
"""
from app.risk import calculate_risk_detail


def show(name: str, ports, findings, changes=None, criticality=3):
    print("=" * 80)
    print(name)
    print("=" * 80)
    result = calculate_risk_detail(ports, findings, changes or [], criticality)
    print(f"score={result['score']} level={result['level']} priority={result['priority']} sla_hours={result['sla_hours']}")
    print(f"max_cvss={result['max_cvss']} max_epss={result['max_epss']} kev_count={result['kev_count']}")
    print("Reasons:")
    for reason in result.get("reasons", [])[:8]:
        print(f"  - [{reason['severity']}] +{reason['score']} {reason['message']}")
    print()
    return result


if __name__ == "__main__":
    case1 = show(
        "CASE 1 - SSH + HTTP only should be Medium/P3-ish",
        ports=[
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "6.6.1"},
            {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.7"},
        ],
        findings=[],
        changes=[],
        criticality=3,
    )

    case2 = show(
        "CASE 2 - New SMB exposure should be High/P2-ish",
        ports=[{"port": 445, "service": "microsoft-ds", "product": "SMB", "version": ""}],
        findings=[],
        changes=[{"type": "new_open_port", "detail": "445"}],
        criticality=3,
    )

    case3 = show(
        "CASE 3 - Validated critical CVE with high EPSS should be Critical/P1",
        ports=[{"port": 80, "service": "http", "product": "Apache", "version": "2.4.49"}],
        findings=[
            {
                "source": "nuclei",
                "template_id": "test-critical-cve",
                "name": "Test Critical CVE",
                "severity": "critical",
                "cve_id": "CVE-2021-41773",
                "cvss_score": 9.8,
                "epss_score": 0.85,
                "kev": False,
                "confidence": 1.0,
            }
        ],
        changes=[{"type": "new_finding", "detail": "CVE-2021-41773"}],
        criticality=4,
    )

    case4 = show(
        "CASE 4 - KEV vulnerability should be Critical/P1",
        ports=[{"port": 443, "service": "https", "product": "Test Web", "version": ""}],
        findings=[
            {
                "source": "nuclei",
                "template_id": "test-kev-cve",
                "name": "Known Exploited Vulnerability Test",
                "severity": "high",
                "cve_id": "CVE-2023-0001",
                "cvss_score": 8.1,
                "epss_score": 0.42,
                "kev": True,
                "confidence": 1.0,
            }
        ],
        changes=[],
        criticality=5,
    )

    case5 = show(
        "CASE 5 - Nmap/NVD candidate is weighted by confidence",
        ports=[{"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.7"}],
        findings=[
            {
                "source": "nmap_nvd",
                "template_id": "nmap-nvd-service-cve",
                "name": "Service/version CVE candidate",
                "severity": "high",
                "cve_id": "CVE-TEST-0001",
                "cvss_score": 9.8,
                "epss_score": 0.80,
                "kev": False,
                "confidence": 0.65,
            }
        ],
        changes=[],
        criticality=3,
    )

    assert case1["level"] == "Medium"
    assert case1["priority"] == "P3"

    assert case2["level"] == "High"
    assert case2["priority"] == "P2"

    assert case3["level"] == "Critical"
    assert case3["priority"] == "P1"
    assert case3["max_cvss"] >= 9.0
    assert case3["max_epss"] >= 0.70

    assert case4["level"] == "Critical"
    assert case4["priority"] == "P1"
    assert case4["kev_count"] == 1

    # Nmap/NVD evidence is useful but unvalidated; it must not become Critical/P1 alone.
    assert case5["score"] < 90
    assert case5["level"] != "Critical"
    assert case5["priority"] != "P1"
    assert any(r["category"] == "policy" for r in case5.get("reasons", []))

    print("ALL RISK SCORING POLICY TESTS PASSED")
