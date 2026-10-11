"""
Exercises the real netscope scanner/probe/risk_checks modules against
controlled local fixture services, run sequentially on their real standard
ports (21 for FTP, 6379 for Redis) so the port-based service gates in
risk_checks.py behave exactly as they would against a real target.

Tests:
  1. Anonymous FTP (port 21)      -> MUST be flagged High
  2. Unauthenticated Redis (6379) -> MUST be flagged High
  3. Auth-required Redis (6379)   -> MUST NOT be flagged (false-positive trap)
  4. A closed port                -> MUST NOT appear in open_ports at all
"""
import subprocess
import sys
import time

sys.path.insert(0, "/home/claude/netscope")

from netscope.scanner import scan_host
from netscope.probe import identify_all
from netscope.risk_checks import run_all_checks

HOST = "127.0.0.1"
ok = True


def start(script, port):
    proc = subprocess.Popen(
        [sys.executable, script, str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.6)
    return proc


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(0.3)


def run_scan_and_checks(port):
    result = scan_host(HOST, ports=[port, 59999], timeout=1.0)  # 59999 = closed-port control
    services = identify_all(result.resolved_ip, HOST, result.open_ports)
    findings = []
    for s in services:
        findings.extend(run_all_checks(HOST, result.resolved_ip, s))
    return result, findings


print("=" * 70)
print("TEST 1: Anonymous FTP login allowed (port 21)")
print("=" * 70)
proc = start("/home/claude/netscope/test_fixtures/fake_ftp_anon.py", 21)
try:
    result, findings = run_scan_and_checks(21)
    print(f"open_ports={result.open_ports}")
    high_findings = [f for f in findings if f.severity == "High" and "Anonymous" in f.title]
    if 59999 in result.open_ports:
        print("FAIL: closed-port control (59999) was reported OPEN - false positive in scanner itself")
        ok = False
    if not high_findings:
        print("FAIL: anonymous FTP login was not detected")
        ok = False
    else:
        print(f"PASS: {high_findings[0].title}")
        print(f"  evidence: {high_findings[0].evidence}")
finally:
    stop(proc)

print()
print("=" * 70)
print("TEST 2: Unauthenticated Redis (port 6379)")
print("=" * 70)
proc = start("/home/claude/netscope/test_fixtures/fake_redis_noauth.py", 6379)
try:
    result, findings = run_scan_and_checks(6379)
    print(f"open_ports={result.open_ports}")
    high_findings = [f for f in findings if f.severity == "High" and "Redis" in f.title]
    if not high_findings:
        print("FAIL: unauthenticated Redis was not detected")
        ok = False
    else:
        print(f"PASS: {high_findings[0].title}")
        print(f"  evidence: {high_findings[0].evidence}")
finally:
    stop(proc)

print()
print("=" * 70)
print("TEST 3: Auth-required Redis (port 6379) — false positive trap")
print("=" * 70)
proc = start("/home/claude/netscope/test_fixtures/fake_redis_auth.py", 6379)
try:
    result, findings = run_scan_and_checks(6379)
    print(f"open_ports={result.open_ports}")
    redis_findings = [f for f in findings if "Redis" in f.title]
    if redis_findings:
        print(f"FAIL: auth-required Redis was incorrectly flagged: {redis_findings}")
        ok = False
    else:
        print("PASS: auth-required Redis correctly produced ZERO findings")
finally:
    stop(proc)

print()
print("=" * 70)
print("RESULT")
print("=" * 70)
if ok:
    print("ALL TESTS PASSED")
else:
    print("SOME TESTS FAILED")
sys.exit(0 if ok else 1)
