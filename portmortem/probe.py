"""
Service and version fingerprinting for ports found open by scanner.py.

Strategy per port, cheapest first:
  1. Passive banner grab - many services (SSH, FTP, SMTP, POP3, IMAP) announce
     themselves the instant a TCP connection opens, before you send anything.
  2. Protocol-appropriate active probe - for ports that stay silent (HTTP,
     HTTPS, and anything else), send the smallest valid request for that
     protocol and read the reply (an HTTP GET, or a TLS handshake to read the
     certificate).
  3. Fallback to the IANA well-known port name if nothing answered.

Every probe here is read-only: connect, read/send one request, read the
reply, close. Nothing here attempts a login, writes data, or exploits
anything - that distinction matters both for the law and for the CV pitch.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field

BANNER_TIMEOUT = 2.5
HTTP_TIMEOUT = 3.0
TLS_TIMEOUT = 3.0
MAX_BANNER_BYTES = 512

# Ports that typically speak first (send a banner before you do) - worth a
# short passive read before trying anything active.
BANNER_FIRST_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 3306}

WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP-Submission",
    631: "IPP", 636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle-DB", 1723: "PPTP", 2049: "NFS",
    2181: "ZooKeeper", 2375: "Docker-API", 2376: "Docker-API-TLS",
    27017: "MongoDB", 3000: "Dev-HTTP", 3128: "HTTP-Proxy", 3306: "MySQL",
    3389: "RDP", 4369: "EPMD", 5000: "Dev-HTTP", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "Kubernetes-API", 7001: "WebLogic", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "HTTP-Alt", 9042: "Cassandra",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt", 27018: "MongoDB",
}

# (service display name, regex to pull a version string out of a banner/header)
VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenSSH", re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)", re.IGNORECASE)),
    ("vsFTPd", re.compile(r"vsFTPd\s+([\d.]+)", re.IGNORECASE)),
    ("ProFTPD", re.compile(r"ProFTPD\s+([\d.]+)", re.IGNORECASE)),
    ("Pure-FTPd", re.compile(r"Pure-?FTPd", re.IGNORECASE)),
    ("Apache httpd", re.compile(r"Apache(?:/([\d.]+))?", re.IGNORECASE)),
    ("Nginx", re.compile(r"nginx(?:/([\d.]+))?", re.IGNORECASE)),
    ("Microsoft IIS", re.compile(r"Microsoft-IIS(?:/([\d.]+))?", re.IGNORECASE)),
    ("MySQL", re.compile(r"(\d+\.\d+\.\d+)-MariaDB|mysql_native_password", re.IGNORECASE)),
    ("Postfix", re.compile(r"Postfix", re.IGNORECASE)),
    ("Exim", re.compile(r"Exim\s+([\d.]+)", re.IGNORECASE)),
    ("Redis", re.compile(r"-ERR|redis_version:([\d.]+)", re.IGNORECASE)),
]


@dataclass
class ServiceInfo:
    port: int
    protocol_guess: str = "unknown"
    product: str | None = None
    version: str | None = None
    banner: str = ""
    tls: dict | None = None  # {subject, issuer, not_after, protocol_version}
    http_headers: dict[str, str] = field(default_factory=dict)
    http_body: str = ""


def _grab_banner(ip: str, port: int) -> str:
    try:
        with socket.create_connection((ip, port), timeout=BANNER_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            data = sock.recv(MAX_BANNER_BYTES)
            return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError, ConnectionResetError):
        return ""


def _http_probe(ip: str, port: int, use_tls: bool, host_header: str) -> tuple[dict[str, str], str, str]:
    """Send a minimal HTTP/1.1 GET and return (headers, status_line, body_sample)."""
    try:
        raw_sock = socket.create_connection((ip, port), timeout=HTTP_TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host_header)
        else:
            sock = raw_sock

        sock.settimeout(HTTP_TIMEOUT)
        request = f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: NetScope/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        try:
            while len(response) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

        text = response.decode("utf-8", errors="replace")
        header_part, _, body_part = text.partition("\r\n\r\n")
        lines = header_part.split("\r\n")
        status_line = lines[0] if lines else ""
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return headers, status_line, body_part[:4096]
    except (socket.timeout, OSError, ssl.SSLError):
        return {}, "", ""


def _tls_probe(ip: str, port: int, host_header: str) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=TLS_TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host_header) as tls_sock:
                cert = tls_sock.getpeercert()
                return {
                    "protocol_version": tls_sock.version(),
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None,
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "not_after": cert.get("notAfter") if cert else None,
                }
    except (socket.timeout, OSError, ssl.SSLError):
        return None


def _match_version(text: str) -> tuple[str | None, str | None]:
    for name, pattern in VERSION_PATTERNS:
        m = pattern.search(text)
        if m:
            version = m.group(1) if m.groups() and m.group(1) else None
            return name, version
    return None, None


def identify_service(ip: str, port: int, hostname_for_tls: str) -> ServiceInfo:
    info = ServiceInfo(port=port)
    info.protocol_guess = WELL_KNOWN_PORTS.get(port, "unknown")

    combined_text = ""

    # Step 1: passive banner for services that speak first.
    if port in BANNER_FIRST_PORTS:
        banner = _grab_banner(ip, port)
        info.banner = banner
        combined_text += banner

    # Step 2: HTTP/HTTPS active probe for web ports (including non-standard
    # ones we still want to check, since 8080/8443/etc are common web ports).
    likely_https = port in (443, 8443, 2376, 6443) or port % 1000 == 443
    likely_http = not likely_https and (
        port in (80, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000) or info.protocol_guess.startswith("HTTP")
    )

    if likely_https:
        tls_info = _tls_probe(ip, port, hostname_for_tls)
        info.tls = tls_info
        headers, status, body = _http_probe(ip, port, use_tls=True, host_header=hostname_for_tls)
        if headers:
            info.http_headers = headers
            info.http_body = body
            info.protocol_guess = "HTTPS"
            combined_text += " " + status + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
    elif likely_http:
        headers, status, body = _http_probe(ip, port, use_tls=False, host_header=hostname_for_tls)
        if headers:
            info.http_headers = headers
            info.http_body = body
            info.protocol_guess = "HTTP"
            combined_text += " " + status + " " + " ".join(f"{k}:{v}" for k, v in headers.items())

    # Step 3: for anything still unidentified and not already tried, attempt
    # a generic passive banner grab as a last resort (covers Redis, Memcached-
    # style services that print something on connect even outside our
    # banner-first list).
    if not combined_text and port not in BANNER_FIRST_PORTS:
        banner = _grab_banner(ip, port)
        if banner:
            info.banner = banner
            combined_text += banner

    product, version = _match_version(combined_text)
    if product:
        info.product = product
        info.version = version

    # Prefer the Server header as the product name for HTTP(S) when our
    # signature table didn't already set one.
    server_header = info.http_headers.get("server")
    if server_header and not info.product:
        info.product = server_header

    return info


def identify_all(ip: str, hostname_for_tls: str, ports: list[int], max_workers: int = 30) -> list[ServiceInfo]:
    import concurrent.futures

    results: list[ServiceInfo] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(identify_service, ip, p, hostname_for_tls): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                results.append(ServiceInfo(port=futures[future]))
    results.sort(key=lambda r: r.port)
    return results
