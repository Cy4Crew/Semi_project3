import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def run_nmap(target: str, ports: list[int], scan_id: int) -> list[dict]:
    if not ports:
        return []
    output = DATA_DIR / f"nmap_scan_{scan_id}.xml"
    port_arg = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-sV", "-O", "--version-light", "-p", port_arg, "-oX", str(output), target]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    except FileNotFoundError:
        return [
            {
                "port": p,
                "protocol": "tcp",
                "state": "open",
                "service": "unknown",
                "product": "",
                "version": "",
                "cpe": "",
                "source": "tcp-fallback-nmap-missing",
            }
            for p in ports
        ]
    except subprocess.TimeoutExpired:
        return []
    if not output.exists():
        return []
    return parse_nmap_xml(output)


def parse_nmap_xml(path: Path) -> list[dict]:
    tree = ET.parse(path)
    root = tree.getroot()
    rows = []
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            cpe = ""
            if service_el is not None:
                cpe_el = service_el.find("cpe")
                cpe = cpe_el.text if cpe_el is not None and cpe_el.text else ""
            rows.append(
                {
                    "port": int(port_el.attrib.get("portid", 0)),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state": "open",
                    "service": service_el.attrib.get("name", "") if service_el is not None else "",
                    "product": service_el.attrib.get("product", "") if service_el is not None else "",
                    "version": service_el.attrib.get("version", "") if service_el is not None else "",
                    "cpe": cpe,
                    "source": "nmap",
                }
            )
    return rows
