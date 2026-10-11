"""
Formal HTML report for Portmortem.

Presentation only: takes the data collected by scanner.py / probe.py /
risk_checks.py and renders a pentest-style deliverable (cover, contents,
executive summary, scope and methodology, numbered findings, remediation
roadmap, appendices). The file is self-contained: no external fonts, scripts
or images, so it renders offline and prints cleanly to PDF.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone

from .probe import ServiceInfo
from .risk_checks import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

TOOL_NAME = "Portmortem"
TOOL_VERSION = "1.0"

SEVERITY_ORDER = [SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
SEVERITY_LABEL = {SEVERITY_HIGH: "High", SEVERITY_MEDIUM: "Medium", SEVERITY_LOW: "Low", SEVERITY_INFO: "Informational"}
SEVERITY_MEANING = {
    SEVERITY_HIGH: "Unauthenticated access to a service or its data was demonstrated, or sensitive traffic is exposed. Fix immediately.",
    SEVERITY_MEDIUM: "Weakness that helps an attacker or exposes data under some conditions. Fix in the next maintenance cycle.",
    SEVERITY_LOW: "Limited impact on its own; a hardening or defence-in-depth improvement.",
    SEVERITY_INFO: "No direct risk; recorded for completeness.",
}
REMEDIATION_WINDOW = {
    SEVERITY_HIGH: "Immediate (within 7 days)",
    SEVERITY_MEDIUM: "Short term (within 30 days)",
    SEVERITY_LOW: "Planned (within 90 days)",
    SEVERITY_INFO: "Optional",
}

_CSS = """
:root{--ink:#1b2430;--muted:#5b6675;--rule:#cfd6df;--navy:#14304f;--paper:#fff;--tint:#f3f5f8;
--high:#8b1a1a;--medium:#b4531a;--low:#2f6b8a;--info:#5b6675}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:#e9edf2;color:var(--ink);font:15px/1.6 "Segoe UI",Calibri,Arial,sans-serif}
.page{max-width:900px;margin:28px auto;background:var(--paper);padding:56px 64px;border:1px solid var(--rule)}
h1,h2,h3{font-family:Cambria,Georgia,"Times New Roman",serif;color:var(--navy);line-height:1.25}
h2{font-size:22px;margin:42px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--navy)}
h3{font-size:17px;margin:24px 0 8px}
p{margin:0 0 12px}
a{color:var(--navy)}
table{width:100%;border-collapse:collapse;margin:12px 0 18px;font-size:14px}
th,td{border:1px solid var(--rule);padding:7px 10px;text-align:left;vertical-align:top}
th{background:var(--tint);font-weight:600}
td.k{background:var(--tint);width:28%;font-weight:600}
.scroll{overflow-x:auto}
.cover{min-height:780px;display:flex;flex-direction:column;justify-content:space-between}
.cover h1{font-size:40px;margin:90px 0 8px}
.cover .sub{font-size:19px;color:var(--muted);margin:0 0 40px}
.cover .bar{height:5px;width:96px;background:var(--navy);margin-bottom:28px}
.sev{display:inline-block;font-weight:700;font-size:13px;padding:1px 9px;border:1.5px solid currentColor;border-radius:3px;white-space:nowrap}
.s-High{color:var(--high)}.s-Medium{color:var(--medium)}.s-Low{color:var(--low)}.s-Info{color:var(--info)}
.finding{border:1px solid var(--rule);border-left:5px solid var(--info);padding:6px 20px 14px;margin:22px 0;break-inside:avoid}
.b-High{border-left-color:var(--high)}.b-Medium{border-left-color:var(--medium)}.b-Low{border-left-color:var(--low)}.b-Info{border-left-color:var(--info)}
.finding h3{margin-top:14px;color:var(--ink)}
pre{background:#10161f;color:#e5ebf3;padding:12px 14px;border-radius:3px;overflow-x:auto;
font:13px/1.5 Consolas,"Courier New",monospace;white-space:pre-wrap;word-break:break-word;margin:6px 0 12px}
.callout{background:var(--tint);border-left:4px solid var(--navy);padding:12px 16px;margin:14px 0}
.small{font-size:13px;color:var(--muted)}
.bars td{border:0;padding:3px 10px 3px 0;font-size:14px}
.bars .track{background:var(--tint);height:14px;width:100%;border-radius:2px}
.bars .fill{height:14px;border-radius:2px}
.f-High{background:var(--high)}.f-Medium{background:var(--medium)}.f-Low{background:var(--low)}.f-Info{background:var(--info)}
ol.toc{padding-left:20px;margin:0}ol.toc li{margin-bottom:3px}
ol.steps li{margin-bottom:6px}
@media(max-width:700px){.page{padding:28px 20px;margin:0}.cover h1{font-size:30px;margin-top:40px}}
@media print{body{background:#fff}.page{border:0;margin:0;max-width:none;padding:0}
.cover{page-break-after:always}h2{page-break-after:avoid}.finding,tr{page-break-inside:avoid}a{color:inherit;text-decoration:none}}
"""


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _badge(sev: str) -> str:
    return f'<span class="sev s-{_esc(sev)}">{_esc(SEVERITY_LABEL.get(sev, sev))}</span>'


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%d %B %Y, %H:%M UTC") if dt else "n/a"


def _cwe(f: Finding) -> str:
    t = f.title.lower()
    if any(k in t for k in ("redis", "elasticsearch", "docker")):
        return "CWE-306: Missing Authentication for Critical Function"
    if "anonymous" in t:
        return "CWE-284: Improper Access Control"
    if "telnet" in t or "ftp service" in t:
        return "CWE-319: Cleartext Transmission of Sensitive Information"
    if "outdated tls" in t:
        return "CWE-326: Inadequate Encryption Strength"
    if "expired" in t:
        return "CWE-298: Improper Validation of Certificate Expiration"
    return "Not mapped"


def _identified_by(s: ServiceInfo) -> str:
    if s.tls and s.http_headers:
        return "TLS handshake + HTTP response"
    if s.http_headers:
        return "HTTP response"
    if s.product and s.banner:
        return "Service banner"
    if s.banner:
        return "Service banner (unrecognised)"
    if s.tls:
        return "TLS handshake"
    return "Port number only (unverified)"


def _numbered(findings: list[Finding]) -> list[tuple[str, Finding]]:
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 9, f.port, f.title))
    return [(f"PM-{i:03d}", f) for i, f in enumerate(ordered, 1)]


def build_html_report(
    host: str,
    resolved_ip: str | None,
    ports_scanned: int,
    services: list[ServiceInfo],
    findings: list[Finding],
    *,
    client: str = "",
    assessor: str = "",
    started: datetime | None = None,
    finished: datetime | None = None,
    port_spec: str = "",
    threads: int | None = None,
    timeout: float | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    started = started or now
    finished = finished or now
    duration = max(1, int((finished - started).total_seconds()))
    counts = Counter(f.severity for f in findings)
    overall = next((s for s in SEVERITY_ORDER if counts.get(s)), None)
    numbered = _numbered(findings)
    verified = sum(1 for s in services if _identified_by(s) != "Port number only (unverified)")
    tls_services = [s for s in services if s.tls]
    target = f"{host} ({resolved_ip})" if resolved_ip and resolved_ip != host else host

    o: list[str] = []
    o.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    o.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    o.append(f"<title>Network Service Assessment Report - {_esc(host)}</title><style>{_CSS}</style></head><body>")

    # ---- Cover ----
    o.append("<div class='page'><section class='cover'><div>")
    o.append("<h1>Network Service<br>Assessment Report</h1><div class='bar'></div>")
    o.append("<p class='sub'>TCP port and service exposure review</p>")
    o.append("<table>")
    o.append(f"<tr><td class='k'>Prepared for</td><td>{_esc(client or 'Not specified')}</td></tr>")
    o.append(f"<tr><td class='k'>Prepared by</td><td>{_esc(assessor or 'Not specified')}</td></tr>")
    o.append(f"<tr><td class='k'>Target</td><td>{_esc(target)}</td></tr>")
    o.append(f"<tr><td class='k'>Assessment date</td><td>{_esc(_fmt(started))}</td></tr>")
    rating = _badge(overall) if overall else "No findings confirmed"
    o.append(f"<tr><td class='k'>Highest severity</td><td>{rating}</td></tr></table></div>")
    o.append("<p class='small'>Confidential. This document contains security-sensitive information and is "
             "intended only for the named recipient.</p></section>")

    # ---- Document control + contents ----
    o.append("<h2>Document control</h2><table>")
    o.append("<tr><td class='k'>Report version</td><td>1.0</td></tr>")
    o.append(f"<tr><td class='k'>Tool</td><td>{TOOL_NAME} {TOOL_VERSION}</td></tr>")
    o.append(f"<tr><td class='k'>Scan started</td><td>{_esc(_fmt(started))}</td></tr>")
    o.append(f"<tr><td class='k'>Scan finished</td><td>{_esc(_fmt(finished))} (about {duration} s)</td></tr>")
    o.append("<tr><td class='k'>Classification</td><td>Confidential</td></tr></table>")
    o.append("<h3>Contents</h3><ol class='toc'>")
    for anchor, label in [("summary", "Executive summary"), ("method", "Scope and methodology"),
                          ("overview", "Summary of findings"), ("details", "Detailed findings"),
                          ("roadmap", "Remediation roadmap"), ("app-a", "Appendix A. Open port inventory"),
                          ("app-b", "Appendix B. TLS inventory"), ("app-c", "Appendix C. Limitations")]:
        o.append(f"<li><a href='#{anchor}'>{label}</a></li>")
    o.append("</ol>")

    # ---- 1 Executive summary ----
    o.append("<h2 id='summary'>1. Executive summary</h2>")
    o.append(f"<p>An automated TCP network service assessment was performed against <strong>{_esc(target)}</strong>. "
             f"{ports_scanned} TCP port(s) were probed. {len(services)} open port(s) were found, and "
             f"{verified} of them were identified from the service's own response rather than from the port number.</p>")
    if findings:
        o.append(f"<p>{len(findings)} finding(s) were confirmed by direct, read-only interaction with the services. "
                 f"The highest severity observed is {_badge(overall)}. Every finding includes the evidence captured, "
                 "so it can be reproduced and verified independently.</p>")
    else:
        o.append("<p>No exposure was confirmed by the checks in this assessment. This does not prove the target is "
                 "secure; Appendix C describes the limits of the method.</p>")
    peak = max([counts.get(s, 0) for s in SEVERITY_ORDER] + [1])
    o.append("<table class='bars'>")
    for s in SEVERITY_ORDER:
        n = counts.get(s, 0)
        o.append(f"<tr><td style='width:130px'>{_badge(s)}</td><td style='width:40px'>{n}</td>"
                 f"<td><div class='track'><div class='fill f-{s}' style='width:{n / peak * 100:.0f}%'></div></div></td></tr>")
    o.append("</table>")
    top = [(fid, f) for fid, f in numbered if f.severity == SEVERITY_HIGH]
    if top:
        items = "; ".join(f"<a href='#{fid}'>{fid}</a> {_esc(f.title)} (port {f.port})" for fid, f in top)
        o.append(f"<div class='callout'><strong>Priority actions.</strong> Address these first: {items}.</div>")

    # ---- 2 Scope and methodology ----
    o.append("<h2 id='method'>2. Scope and methodology</h2><h3>2.1 Scope</h3><table>")
    o.append(f"<tr><td class='k'>Target</td><td>{_esc(host)}</td></tr>")
    o.append(f"<tr><td class='k'>Resolved address</td><td>{_esc(resolved_ip or 'n/a')}</td></tr>")
    o.append(f"<tr><td class='k'>Ports probed</td><td>{ports_scanned}" + (f" ({_esc(port_spec)})" if port_spec else "") + "</td></tr>")
    o.append("<tr><td class='k'>Protocol</td><td>TCP, IPv4</td></tr>")
    if threads and timeout:
        o.append(f"<tr><td class='k'>Concurrency / timeout</td><td>{threads} threads / {timeout:.1f} s</td></tr>")
    o.append("</table><h3>2.2 Method</h3><ol class='steps'>")
    o.append("<li><strong>Port discovery.</strong> A TCP connect scan identified ports that accept connections.</li>")
    o.append("<li><strong>Service identification.</strong> Open ports were fingerprinted from their banner, an HTTP "
             "response or a TLS handshake. Ports where no response was obtained are marked as unverified in Appendix A.</li>")
    o.append("<li><strong>Verification.</strong> For services with a known unsafe configuration, a read-only check "
             "was sent (for example an anonymous FTP login or an unauthenticated command). A finding is recorded "
             "only when the server's reply proves it.</li>")
    o.append("<li><strong>Reporting.</strong> Findings are ranked by severity and carry the captured evidence.</li></ol>")
    o.append("<h3>2.3 Severity ratings</h3><table><tr><th>Rating</th><th>Meaning</th></tr>")
    for s in SEVERITY_ORDER:
        o.append(f"<tr><td>{_badge(s)}</td><td>{_esc(SEVERITY_MEANING[s])}</td></tr>")
    o.append("</table>")

    # ---- 3 Summary of findings ----
    o.append("<h2 id='overview'>3. Summary of findings</h2>")
    if numbered:
        o.append("<div class='scroll'><table><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Affected</th></tr>")
        for fid, f in numbered:
            o.append(f"<tr><td><a href='#{fid}'>{fid}</a></td><td>{_badge(f.severity)}</td><td>{_esc(f.title)}</td>"
                     f"<td>{_esc(f.host)}:{f.port}</td></tr>")
        o.append("</table></div>")
    else:
        o.append("<p>No findings.</p>")

    # ---- 4 Detailed findings ----
    o.append("<h2 id='details'>4. Detailed findings</h2>")
    if not numbered:
        o.append("<p>No findings to detail.</p>")
    for fid, f in numbered:
        o.append(f"<div class='finding b-{_esc(f.severity)}' id='{fid}'><h3>{fid} &ndash; {_esc(f.title)}</h3><table>")
        o.append(f"<tr><td class='k'>Severity</td><td>{_badge(f.severity)}</td></tr>")
        o.append(f"<tr><td class='k'>Affected</td><td>{_esc(f.host)}:{f.port}</td></tr>")
        o.append(f"<tr><td class='k'>Category</td><td>{_esc(f.category)}</td></tr>")
        o.append(f"<tr><td class='k'>Weakness</td><td>{_esc(_cwe(f))}</td></tr></table>")
        o.append(f"<p><strong>Evidence</strong></p><pre>{_esc(f.evidence)}</pre>")
        o.append(f"<p><strong>Recommendation</strong></p><p>{_esc(f.recommendation)}</p></div>")

    # ---- 5 Remediation roadmap ----
    o.append("<h2 id='roadmap'>5. Remediation roadmap</h2>")
    if numbered:
        o.append("<p>Suggested remediation windows by severity. Adjust to the client's own risk policy.</p>")
        o.append("<table><tr><th>Window</th><th>Findings</th></tr>")
        for s in SEVERITY_ORDER:
            ids = [fid for fid, f in numbered if f.severity == s]
            if ids:
                o.append(f"<tr><td>{_esc(REMEDIATION_WINDOW[s])}</td><td>" +
                         ", ".join(f"<a href='#{i}'>{i}</a>" for i in ids) + "</td></tr>")
        o.append("</table>")
    else:
        o.append("<p>No remediation actions arise from this assessment.</p>")

    # ---- Appendix A ----
    o.append("<h2 id='app-a'>Appendix A. Open port inventory</h2>")
    if services:
        o.append("<div class='scroll'><table><tr><th>Port</th><th>Service</th><th>Product / version</th>"
                 "<th>Identified by</th><th>Banner</th></tr>")
        for s in sorted(services, key=lambda x: x.port):
            prod = " ".join(p for p in (s.product, s.version) if p) or "-"
            o.append(f"<tr><td>{s.port}/tcp</td><td>{_esc(s.protocol_guess)}</td><td>{_esc(prod)}</td>"
                     f"<td>{_esc(_identified_by(s))}</td><td>{_esc(s.banner[:80]) if s.banner else '-'}</td></tr>")
        o.append("</table></div>")
    else:
        o.append("<p>No open ports were found in the scanned range.</p>")

    # ---- Appendix B ----
    o.append("<h2 id='app-b'>Appendix B. TLS inventory</h2>")
    if tls_services:
        o.append("<div class='scroll'><table><tr><th>Port</th><th>Protocol</th><th>Cipher</th>"
                 "<th>Certificate subject</th><th>Expires</th></tr>")
        for s in sorted(tls_services, key=lambda x: x.port):
            t = s.tls or {}
            cn = (t.get("subject") or {}).get("commonName") or "-"
            o.append(f"<tr><td>{s.port}/tcp</td><td>{_esc(t.get('protocol_version') or '-')}</td>"
                     f"<td>{_esc(t.get('cipher') or '-')}</td><td>{_esc(cn)}</td><td>{_esc(t.get('not_after') or '-')}</td></tr>")
        o.append("</table></div>")
    else:
        o.append("<p>No TLS services were negotiated.</p>")

    # ---- Appendix C ----
    o.append("<h2 id='app-c'>Appendix C. Limitations</h2><ul>")
    o.append("<li>This is a point-in-time view of the ports listed in the scope. Other ports, UDP services and IPv6 were not assessed.</li>")
    o.append("<li>Firewalls and intrusion prevention systems can hide or alter results; a closed or filtered port is not proof that nothing is listening.</li>")
    o.append("<li>Findings are raised from observed behaviour, not from version numbers, so known-vulnerable software versions are not reported unless the behaviour was confirmed.</li>")
    o.append("<li>Checks are read-only. Write access, password strength and application-level flaws were not tested.</li>")
    o.append("<li>The assessment was carried out only against systems the assessor is authorised to test.</li></ul>")
    o.append("</div></body></html>")
    return "".join(o)