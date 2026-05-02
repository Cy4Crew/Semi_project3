import asyncio
import ipaddress
import socket
from typing import Iterable

# ── 표준 포트 (기존 유지) ──────────────────────────────────────────────────
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1723, 2049, 2375, 2376, 3306,
    3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 9300, 11211, 27017,
]

# ── 비표준/확장 포트 ──────────────────────────────────────────────────────
EXTENDED_PORTS = sorted(set(DEFAULT_PORTS + [
    # 개발·프록시·API 게이트웨이
    3000, 3001, 4000, 4200, 4243, 4444, 4848,
    5000, 5001, 5601, 5672, 5984,
    6000, 6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669,
    7000, 7001, 7070, 7077, 7443, 7474, 7480,
    8008, 8009, 8081, 8082, 8083, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    8161, 8181, 8280, 8443, 8444, 8500, 8545, 8888, 8983,
    9000, 9001, 9002, 9003, 9042, 9090, 9091, 9092, 9093, 9100,
    9200, 9300, 9418, 9999,
    # 데이터베이스 / 캐시 비표준
    1234, 1521, 1527, 2181, 2375, 2376, 2379, 2380,
    4369, 5044, 5984, 6379, 6380, 6381, 6382,
    7199, 7474, 7687,
    15672, 25672, 27017, 27018, 27019, 28017,
    # 관리·모니터링
    2222, 2376, 4040, 4567, 8161, 9090, 10000, 10050,
    15672, 16686, 19999, 55672,
    # IoT / 임베디드 / VPN
    1194, 1701, 1883, 4500, 5555, 6443, 8883, 9443,
]))

# ── 스캔 프로파일 정의 ────────────────────────────────────────────────────
SCAN_PROFILES: dict[str, list[int]] = {
    "quick":    DEFAULT_PORTS,                           # 35개 주요 포트
    "standard": EXTENDED_PORTS,                         # ~130개 확장 포트
    "extended": list(range(1, 10001)),                  # 1–10000 전체
    "full":     list(range(1, 65536)),                  # 1–65535 전체 (느림)
}

PROFILE_DESCRIPTIONS: dict[str, str] = {
    "quick":    "35개 주요 포트 (빠름, ~5초)",
    "standard": "~130개 확장 포트 — 비표준 포트 포함 (권장)",
    "extended": "1–10,000 전체 포트 (느림, ~1분)",
    "full":     "1–65,535 전체 포트 (매우 느림, ~5분+)",
}


def parse_port_input(raw: str) -> list[int]:
    """
    사용자 입력 문자열을 포트 목록으로 변환.

    지원 형식:
      - 프로파일 이름: "quick" | "standard" | "extended" | "full"
      - 개별 포트:    "80,443,8080"
      - 범위:         "8000-9000"
      - 혼합:         "22,80,8000-8100,443"
    """
    raw = raw.strip().lower()

    # 프로파일 이름
    if raw in SCAN_PROFILES:
        return SCAN_PROFILES[raw]

    # 빈 값 → 기본(quick)
    if not raw:
        return DEFAULT_PORTS

    ports: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
                if lo > hi:
                    lo, hi = hi, lo
                if hi - lo > 65534:
                    raise ValueError(f"범위가 너무 큽니다: {token}")
                ports.update(range(lo, hi + 1))
            except ValueError as exc:
                raise ValueError(f"잘못된 포트 범위: '{token}' → {exc}") from exc
        else:
            try:
                p = int(token)
                if not (1 <= p <= 65535):
                    raise ValueError(f"포트는 1–65535 사이여야 합니다: {p}")
                ports.add(p)
            except ValueError as exc:
                raise ValueError(f"잘못된 포트 값: '{token}' → {exc}") from exc

    return sorted(ports)


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
