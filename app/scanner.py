import asyncio
import ipaddress
import socket
from typing import Iterable

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1723, 2049, 2375, 2376, 3306,
    3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 9300, 11211, 27017
]


def expand_target(value: str) -> list[str]:
    value = value.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses > 256:
            raise ValueError("CIDR range is too large. Limit is 256 addresses.")
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [value]


async def scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except Exception:
            return None


async def tcp_scan(host: str, ports: Iterable[int] = DEFAULT_PORTS, timeout: float = 1.0, concurrency: int = 200) -> list[int]:
    socket.getaddrinfo(host, None)
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_port(host, port, timeout, sem) for port in ports]
    results = await asyncio.gather(*tasks)
    return sorted([p for p in results if p is not None])
