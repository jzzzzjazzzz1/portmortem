#!/usr/bin/env python3
"""
Portmortem - Threaded TCP Port & Service Scanner

Usage (after `pip install -e .` once):

    portmortem -t example.com
    portmortem -t 192.168.1.1 --ports 1-1000 --client "Acme Ltd" --assessor "Your Name"
    portmortem -t example.com --ports top --output output/report.html

Also works without installing:

    python -m portmortem.main -t example.com

IMPORTANT: Only scan hosts you own or have explicit written
authorization to test.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from colorama import Fore, Style, init as colorama_init

from .scanner import scan_host, parse_port_spec
from .probe import identify_all
from .risk_checks import run_all_checks
from .report import build_html_report

colorama_init(autoreset=True)


def _banner():
    print(
        Fore.CYAN
        + Style.BRIGHT
        + r"""
 ____           _   __  __           _
|  _ \ ___  _ _| |_  \/  | ___  _ _| | ___ _ __ ___
| |_) / _ \| '_| __| |\/| |/ _ \| '_| |/ _ \ '__/ __|
|  __/ (_) | | | |_| |  | | (_) | | | |  __/ |  \__ \
|_|   \___/|_|  \__|_|  |_|\___/|_| |_|\___|_|  |___/

          TCP Port & Service Scanner
"""
        + Style.RESET_ALL
    )


def _confirm_authorization(target: str, assume_yes: bool) -> bool:
    """Require confirmation before actively scanning a target."""
    if assume_yes:
        return True

    print(
        Fore.YELLOW
        + f"You are about to actively scan: {target}"
        + Style.RESET_ALL
    )

    try:
        answer = input(
            "Do you own this host/network or have explicit written "
            "authorization to test it? [y/N]: "
        )
    except (EOFError, KeyboardInterrupt):
        print("\nAuthorization confirmation cancelled.")
        return False

    return answer.strip().lower() in ("y", "yes")


def _write_report(output_path: str, html_report: str) -> None:
    """Create the output directory if necessary and write the HTML report."""
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(html_report)


def main():
    parser = argparse.ArgumentParser(
        prog="portmortem",
        description=(
            "Portmortem - TCP port scanner, service fingerprinting, "
            "and risk detection (authorized use only)."
        ),
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target hostname or IP address, e.g. example.com or 192.168.1.1",
    )
    parser.add_argument(
        "--ports",
        default="top",
        help=(
            "Ports to scan: 'top' (default), '1-1000', "
            "or a comma-separated list such as '22,80,443'"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-port connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=200,
        help="Maximum concurrent connection attempts (default: 200)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="HTML report path (default: output/<target>_report.html)",
    )
    parser.add_argument(
        "--client",
        default="",
        help="Client name for the report, if supported by the report template",
    )
    parser.add_argument(
        "--assessor",
        default="",
        help="Assessor name for the report, if supported by the report template",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the interactive authorization prompt",
    )

    args = parser.parse_args()
    _banner()

    target = args.target.strip()

    if not target:
        parser.error("Target cannot be empty.")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    if args.threads < 1:
        parser.error("--threads must be at least 1.")

    if not _confirm_authorization(target, args.yes):
        print(
            Fore.RED
            + "Authorization not confirmed. Exiting."
            + Style.RESET_ALL
        )
        sys.exit(1)

    try:
        ports = parse_port_spec(args.ports)
    except ValueError as exc:
        print(
            Fore.RED
            + f"Invalid --ports value: {exc}"
            + Style.RESET_ALL
        )
        sys.exit(1)

    if not ports:
        print(Fore.RED + "No ports specified to scan." + Style.RESET_ALL)
        sys.exit(1)

    safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_")
    output_path = args.output or os.path.join(
        "output", f"{safe_target}_report.html"
    )

    t0 = time.time()

    print(
        Fore.CYAN
        + f"\n[1/3] Scanning {len(ports)} ports on {target} ..."
        + Style.RESET_ALL
    )

    def progress(done, total):
        print(f"  {done}/{total} ports checked", end="\r", flush=True)

    try:
        result = scan_host(
            target,
            ports=ports,
            timeout=args.timeout,
            max_workers=args.threads,
            progress_callback=progress,
        )
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        print(
            Fore.RED
            + f"\nScan failed: {exc}"
            + Style.RESET_ALL
        )
        sys.exit(1)

    print(" " * 60, end="\r")

    if result.resolve_error:
        print(
            Fore.RED
            + f"Target resolution failed: {result.resolve_error}"
            + Style.RESET_ALL
        )
        sys.exit(1)

    print(
        f"Resolved to {result.resolved_ip}. "
        f"Open ports: {len(result.open_ports)} / "
        f"{result.scanned_count} scanned"
    )

    # Case 1: No open ports. Generate a report without fingerprinting.
    if not result.open_ports:
        print(
            Fore.YELLOW
            + "\nNo open ports found. Writing a report with no findings."
            + Style.RESET_ALL
        )

        try:
            html_report = build_html_report(
                host=target,
                resolved_ip=result.resolved_ip,
                ports_scanned=result.scanned_count,
                services=[],
                findings=[],
            )
            _write_report(output_path, html_report)
        except Exception as exc:
            print(
                Fore.RED
                + f"Failed to generate HTML report: {exc}"
                + Style.RESET_ALL
            )
            sys.exit(1)

        elapsed = time.time() - t0
        print(
            Fore.GREEN
            + f"Report saved to: {output_path}"
            + Style.RESET_ALL
        )
        print(f"Finished in {elapsed:.1f}s.")
        return

    # Case 2: Fingerprint discovered open ports.
    print(
        Fore.CYAN
        + f"\n[2/3] Fingerprinting {len(result.open_ports)} open ports ..."
        + Style.RESET_ALL
    )

    try:
        services = identify_all(
            result.resolved_ip,
            target,
            result.open_ports,
        )
    except Exception as exc:
        print(
            Fore.RED
            + f"Service fingerprinting failed: {exc}"
            + Style.RESET_ALL
        )
        sys.exit(1)

    for service in services:
        label = service.product or service.protocol_guess
        version = f" {service.version}" if service.version else ""
        print(f"  {service.port}/tcp  {label}{version}")

    # Case 3: Run risk checks against identified services.
    print(
        Fore.CYAN
        + f"\n[3/3] Running risk checks on {len(services)} services ..."
        + Style.RESET_ALL
    )

    all_findings = []

    for service in services:
        try:
            findings = run_all_checks(
                target,
                result.resolved_ip,
                service,
            )
            all_findings.extend(findings)
        except Exception as exc:
            print(
                Fore.YELLOW
                + f"Risk check failed for port {service.port}: {exc}"
                + Style.RESET_ALL
            )

    high = sum(1 for finding in all_findings if finding.severity == "High")
    medium = sum(1 for finding in all_findings if finding.severity == "Medium")
    low = sum(1 for finding in all_findings if finding.severity == "Low")

    print(
        f"Findings: {Fore.RED}{high} High{Style.RESET_ALL}, "
        f"{Fore.YELLOW}{medium} Medium{Style.RESET_ALL}, "
        f"{Fore.BLUE}{low} Low{Style.RESET_ALL}"
    )

    # IMPORTANT:
    # build_html_report currently accepts only these five arguments.
    # Do not pass started, finished, client, assessor, or other metadata
    # unless report.py is updated to support those parameters.
    try:
        html_report = build_html_report(
            host=target,
            resolved_ip=result.resolved_ip,
            ports_scanned=result.scanned_count,
            services=services,
            findings=all_findings,
        )
        _write_report(output_path, html_report)
    except Exception as exc:
        print(
            Fore.RED
            + f"Failed to generate HTML report: {exc}"
            + Style.RESET_ALL
        )
        sys.exit(1)

    elapsed = time.time() - t0

    print(
        Fore.GREEN
        + Style.BRIGHT
        + f"\nDone in {elapsed:.1f}s. Report saved to: {output_path}"
        + Style.RESET_ALL
    )


if __name__ == "__main__":
    main()

