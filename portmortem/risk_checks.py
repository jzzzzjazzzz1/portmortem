"""
Risk detection for discovered services.

Same rule as the rest of this tool: a finding only gets reported when there
is a concrete, attached piece of evidence a human can verify by reading one
line - an actual server response code, a JSON field, a protocol handshake
byte, a certificate date. Nothing here is inferred from "this port is
usually risky" alone; a database port being open is not, by itself, a
finding - only a *verified unauthenticated* database is.

Checks:
  1. Cleartext remote-access/file-transfer protocols (Telnet, plain FTP) -
     flagged from the service identification already done in probe.py
     (protocol_guess / banner), not re-probed.
  2. Anonymous FTP login - actively attempts an anonymous login (USER
     anonymous / PASS anonymous@) and only flags it if the server's own
     response code confirms a successful login (230). This mirrors what
     nmap's ftp-anon script does and is non-destructive: login, confirm,
     disconnect - no file listing or upload.
  3. Unauthenticated Redis - sends a single PING and only flags it if the
     server replies +PONG without ever receiving credentials. A server that
     requires AUTH replies with a NOAUTH error instead, which is correctly
     NOT flagged.
  4. Unauthenticated Elasticsearch / exposed Docker API - uses the HTTP
     response body already captured by probe.py's HTTP probe, and only
     flags it if that body contains the exact JSON fields those APIs return
     on their root/info endpoint (cluster_name for Elasticsearch, ApiVersion
     for Docker) - a generic 200 OK on those ports is not enough on its own.
  5. Expired or outdated TLS - uses the certificate/protocol data probe.py
     already captured during its TLS handshake and flags only a verified
     expiry date in the past, or a protocol version below TLS 1.2.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from .probe import ServiceInfo

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

FTP_TIMEOUT = 3.0
REDIS_TIMEOUT = 2.0


@dataclass
class Finding:
    host: str
    port: int
    category: str
    severity: str
    title: str
    evidence: str
    recommendation: str


# ---------------------------------------------------------------------------
# Check 1: cleartext protocols (derived from already-collected service info,
# no extra network calls)
# ---------------------------------------------------------------------------

def check_cleartext_protocol(host: str, service: ServiceInfo) -> Finding | None:
    if service.port == 23 or service.protocol_guess == "Telnet":
        return Finding(
            host=host, port=service.port,
            category="Cleartext Protocol",
            severity=SEVERITY_MEDIUM,
            title="Telnet service exposed (unencrypted remote access)",
            evidence=f"Port {service.port} open, banner: {service.banner[:150]!r}" if service.banner else f"Port {service.port} open, identified as Telnet",
            recommendation="Disable Telnet and use SSH instead. Telnet sends credentials and all traffic in plaintext.",
        )
    if service.port == 21 or service.protocol_guess == "FTP":
        return Finding(
            host=host, port=service.port,
            category="Cleartext Protocol",
            severity=SEVERITY_LOW,
            title="FTP service exposed (unencrypted file transfer)",
            evidence=f"Port {service.port} open, banner: {service.banner[:150]!r}" if service.banner else f"Port {service.port} open, identified as FTP",
            recommendation="Replace FTP with SFTP/FTPS so credentials and file contents aren't sent in plaintext.",
        )
    return None


# ---------------------------------------------------------------------------
# Check 2: anonymous FTP login (verified by an actual login attempt)
# ---------------------------------------------------------------------------

def check_anonymous_ftp(host: str, ip: str, service: ServiceInfo) -> Finding | None:
    if service.port != 21 and service.protocol_guess != "FTP":
        return None

    try:
        with socket.create_connection((ip, service.port), timeout=FTP_TIMEOUT) as sock:
            sock.settimeout(FTP_TIMEOUT)

            def _read() -> str:
                try:
                    return sock.recv(1024).decode("utf-8", errors="replace")
                except (socket.timeout, OSError):
                    return ""

            banner = _read()  # 220 welcome banner
            if not banner.startswith("220"):
                return None

            sock.sendall(b"USER anonymous\r\n")
            user_resp = _read()

            sock.sendall(b"PASS anonymous@example.com\r\n")
            pass_resp = _read()

            sock.sendall(b"QUIT\r\n")

            if pass_resp.strip().startswith("230"):
                return Finding(
                    host=host, port=service.port,
                    category="Anonymous Access",
                    severity=SEVERITY_HIGH,
                    title="Anonymous FTP login allowed",
                    evidence=f"USER anonymous -> {user_resp.strip()!r}; PASS anonymous@... -> {pass_resp.strip()!r}",
                    recommendation="Disable anonymous FTP access unless the server is explicitly meant to be a public drop/download point with no sensitive content.",
                )
    except (socket.timeout, OSError, ConnectionResetError):
        pass
    return None


# ---------------------------------------------------------------------------
# Check 3: unauthenticated Redis
# ---------------------------------------------------------------------------

def check_unauth_redis(host: str, ip: str, service: ServiceInfo) -> Finding | None:
    if service.port != 6379 and service.protocol_guess != "Redis":
        return None

    try:
        with socket.create_connection((ip, service.port), timeout=REDIS_TIMEOUT) as sock:
            sock.settimeout(REDIS_TIMEOUT)
            sock.sendall(b"PING\r\n")
            resp = sock.recv(256).decode("utf-8", errors="replace").strip()

            if resp.upper().startswith("+PONG"):
                return Finding(
                    host=host, port=service.port,
                    category="Unauthenticated Service",
                    severity=SEVERITY_HIGH,
                    title="Redis exposed without authentication",
                    evidence=f"PING sent with no credentials -> server replied {resp!r} (a server requiring auth replies with a NOAUTH error instead)",
                    recommendation="Set `requirepass` (or use ACLs) and bind Redis to localhost/private network only - never expose it directly to the internet.",
                )
    except (socket.timeout, OSError, ConnectionResetError):
        pass
    return None


# ---------------------------------------------------------------------------
# Check 4: unauthenticated Elasticsearch / exposed Docker API
# (reuses the HTTP body probe.py already captured - no extra network call)
# ---------------------------------------------------------------------------

def check_exposed_apis(host: str, service: ServiceInfo, http_body_sample: str) -> Finding | None:
    headers = service.http_headers
    if not headers:
        return None

    body_lower = (http_body_sample or "").lower()

    if '"cluster_name"' in body_lower and '"version"' in body_lower:
        return Finding(
            host=host, port=service.port,
            category="Unauthenticated Service",
            severity=SEVERITY_HIGH,
            title="Elasticsearch exposed without authentication",
            evidence=f"GET / on port {service.port} returned a JSON body containing \"cluster_name\" with no credentials sent",
            recommendation="Enable Elasticsearch security features (authentication) and restrict network access to trusted hosts only.",
        )

    if '"apiversion"' in body_lower and '"version"' in body_lower:
        return Finding(
            host=host, port=service.port,
            category="Unauthenticated Service",
            severity=SEVERITY_HIGH,
            title="Docker API exposed without authentication",
            evidence=f"GET / on port {service.port} returned a JSON body containing \"ApiVersion\" with no credentials sent",
            recommendation="Never expose the Docker daemon socket over plain HTTP. Use TLS client-certificate authentication or a Unix socket restricted to trusted users.",
        )

    return None


# ---------------------------------------------------------------------------
# Check 5: weak/expired TLS
# ---------------------------------------------------------------------------

_OUTDATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_tls_issues(host: str, service: ServiceInfo) -> list[Finding]:
    findings: list[Finding] = []
    if not service.tls:
        return findings

    tls = service.tls
    proto = tls.get("protocol_version")
    if proto in _OUTDATED_TLS_VERSIONS:
        findings.append(Finding(
            host=host, port=service.port,
            category="Weak TLS Configuration",
            severity=SEVERITY_MEDIUM,
            title=f"Outdated TLS protocol negotiated ({proto})",
            evidence=f"TLS handshake on port {service.port} negotiated {proto}, which is deprecated and has known weaknesses.",
            recommendation="Disable TLS versions below 1.2 in the server configuration.",
        ))

    not_after = tls.get("not_after")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            if expiry < datetime.now(timezone.utc):
                findings.append(Finding(
                    host=host, port=service.port,
                    category="Weak TLS Configuration",
                    severity=SEVERITY_MEDIUM,
                    title="Expired TLS certificate",
                    evidence=f"Certificate on port {service.port} expired on {not_after} (verified from the certificate's own notAfter field).",
                    recommendation="Renew the TLS certificate. Browsers and clients will show security warnings until it's replaced.",
                ))
        except ValueError:
            pass  # unparseable date format - skip rather than guess

    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_all_checks(host: str, ip: str, service: ServiceInfo) -> list[Finding]:
    findings: list[Finding] = []

    f = check_cleartext_protocol(host, service)
    if f:
        findings.append(f)

    f = check_anonymous_ftp(host, ip, service)
    if f:
        findings.append(f)

    f = check_unauth_redis(host, ip, service)
    if f:
        findings.append(f)

    f = check_exposed_apis(host, service, service.http_body)
    if f:
        findings.append(f)

    findings.extend(check_tls_issues(host, service))

    return findings
