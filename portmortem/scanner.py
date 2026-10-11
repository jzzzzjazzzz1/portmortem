"""
TCP connect scan engine.

Uses plain TCP connect() rather than raw SYN scanning, on purpose: a SYN scan
needs raw sockets (root/admin + libpcap on Windows), which most people running
this from a laptop don't have set up. A connect scan works anywhere Python
runs, at the cost of being slightly louder/slower - an acceptable trade for a
portfolio/learning tool. This module only answers "is this port open", never
anything about what's running there - that's probe.py's job, kept separate so
a slow/stuck banner grab on one port can't block the sweep that finds the rest.
"""

from __future__ import annotations

import concurrent.futures
import socket
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_WORKERS = 200

# Common ports worth checking by default - covers the services most worth
# auditing (web, remote access, mail, db, file sharing) without the time cost
# of a full 1-65535 sweep. --ports can override this.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 179, 389, 443,
    445, 465, 514, 515, 587, 631, 636, 873, 993, 995, 1025, 1080, 1433, 1521,
    1723, 2049, 2082, 2083, 2095, 2096, 2181, 2375, 2376, 27017, 27018, 3000,
    3128, 3306, 3389, 3690, 4000, 4040, 4369, 4848, 5000, 5432, 5601, 5672,
    5900, 5984, 6000, 6379, 6443, 7001, 7077, 7199, 7474, 7687, 8000, 8008,
    8009, 8020, 8080, 8081, 8088, 8181, 8200, 8443, 8500, 8545, 8888, 8983,
    9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 11211, 15672,
    20000, 27015, 28015, 50000, 50070,
]


@dataclass
class ScanResult:
    host: str
    resolved_ip: str | None = None
    open_ports: list[int] = field(default_factory=list)
    scanned_count: int = 0
    resolve_error: str | None = None


def resolve_host(host: str) -> tuple[str | None, str | None]:
    """Resolve a hostname to an IP once, up front, so every port check
    reuses the same address instead of re-resolving per port.
    """
    try:
        ip = socket.gethostbyname(host)
        return ip, None
    except socket.gaierror as exc:
        return None, f"DNS resolution failed: {exc}"


def _check_port(ip: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()


def parse_port_spec(spec: str) -> list[int]:
    """Parse a port spec like '22,80,443' or '1-1000' or 'top' into a sorted
    list of unique ports.
    """
    spec = spec.strip().lower()
    if spec in ("top", "default", ""):
        return sorted(set(TOP_PORTS))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def scan_host(
    host: str,
    ports: list[int] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress_callback=None,
) -> ScanResult:
    ports = ports or TOP_PORTS
    result = ScanResult(host=host)

    ip, error = resolve_host(host)
    if error:
        result.resolve_error = error
        return result
    result.resolved_ip = ip

    open_ports: list[int] = []
    completed = 0
    total = len(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_port = {pool.submit(_check_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            completed += 1
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
            if progress_callback:
                progress_callback(completed, total)

    result.open_ports = sorted(open_ports)
    result.scanned_count = total
    return result
