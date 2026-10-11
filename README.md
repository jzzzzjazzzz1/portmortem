# Portmortem

**Threaded TCP port scanner with service fingerprinting and evidence-based risk detection.**

Portmortem maps a host's open network surface: which ports are open, what services are running, and whether those services exhibit specific, verifiable security misconfigurations. It aims to reduce false positives by requiring evidence from service responses before reporting supported security findings.

## Features

### 1. Multi-threaded TCP Port Scanning

* Performs TCP connect scans using concurrent connection attempts.
* Includes a built-in list of approximately 95 common ports.
* Supports custom port ranges and comma-separated port lists.
* Allows configuration of connection timeouts and thread counts.

### 2. Service Fingerprinting

Portmortem attempts to identify services running on discovered open ports using techniques such as:

* Banner grabbing for services that expose identifying information.
* HTTP/HTTPS probing and response-header inspection.
* TLS inspection for certificate and protocol information, where supported.
* Service and version identification when sufficient evidence is available.

### 3. Evidence-Based Risk Detection

Portmortem includes targeted checks for selected service misconfigurations, depending on the implemented checks and the responses received.

Examples of intended checks include:

* Cleartext protocols, such as Telnet and unencrypted FTP.
* Anonymous FTP access, confirmed through the server's authentication response.
* Unauthenticated Redis access, confirmed through a valid `PING` response.
* Exposed Elasticsearch or Docker APIs, verified using expected response data.
* Outdated TLS protocols or expired certificates.

**An open port is not automatically a vulnerability.** A service being reachable does not, by itself, prove that authentication is disabled or that a security misconfiguration exists.

Detection results depend on the implemented checks and the evidence collected during the scan. A lack of findings does not guarantee that the target is secure.

### 4. HTML Reporting

Portmortem generates an HTML report containing information such as:

* Target hostname or IP address.
* Resolved IP address.
* Number of ports scanned.
* Identified open ports and services.
* Security findings and severity information.
* Supporting evidence included by the report implementation.

Reports are saved locally and can be opened in a web browser.

## Installation

### Requirements

* Python 3.9 or newer.
* `pip`.
* The dependencies listed in `requirements.txt` or `pyproject.toml`.

Clone the repository and enter the project directory:

```bash
git clone https://github.com/jzzzzjazzzz1/portmortem.git
cd portmortem
```

Install the project in editable mode:

```bash
py -m pip install -e .
```

This registers the `portmortem` command using the project's configured console-script entry point.

> If you already have the project downloaded, open PowerShell in the project root and run the installation command there.

## Usage

Portmortem supports two ways to run the scanner.

### Method 1: Run the installed command

After installing the project, use:

```powershell
portmortem -t 127.0.0.1 --ports top
```

Scan a larger port range on an authorized target:

```powershell
portmortem -t 127.0.0.1 --ports 1-1000
```

### Method 2: Run the Python module directly

From the project root, you can also run:

```powershell
py -m portmortem.main -t 127.0.0.1 --ports top
```

Or scan a custom range:

```powershell
py -m portmortem.main -t 127.0.0.1 --ports 1-1000
```

Both methods use the same scanner implementation.

**Use only `127.0.0.1` for local testing, or replace it with a host you own or have explicit authorization to assess.**

## Command-Line Options

| Option           | Description                                                                    |
| ---------------- | ------------------------------------------------------------------------------ |
| `-t`, `--target` | Target hostname or IP address. Required.                                       |
| `--ports`        | Ports to scan: `top`, a range such as `1-1000`, or a list such as `22,80,443`. |
| `--timeout`      | Connection timeout per port, in seconds. Default: `1.0`.                       |
| `--threads`      | Maximum concurrent connection attempts. Default: `200`.                        |
| `--output`       | Output path for the HTML report.                                               |
| `--client`       | Client name accepted by the CLI.                                               |
| `--assessor`     | Assessor name accepted by the CLI.                                             |
| `-y`, `--yes`    | Skip the interactive authorization confirmation.                               |

### Examples

Scan the default list of common ports:

```powershell
portmortem -t 127.0.0.1 --ports top
```

Scan ports 1–1000:

```powershell
portmortem -t 127.0.0.1 --ports 1-1000
```

Scan selected ports:

```powershell
portmortem -t 127.0.0.1 --ports 22,80,443
```

Specify a custom report location:

```powershell
portmortem -t 127.0.0.1 --ports top --output output\local_report.html
```

Customize the connection timeout and concurrency:

```powershell
portmortem -t 127.0.0.1 --ports 1-1000 --timeout 2 --threads 100
```

Run the same scan without relying on the installed command:

```powershell
py -m portmortem.main -t 127.0.0.1 --ports top
```

## Example Output

A successful scan of the local Windows host may look like this:

```text
[1/3] Scanning 95 ports on 127.0.0.1 ...
Resolved to 127.0.0.1. Open ports: 2 / 95 scanned

[2/3] Fingerprinting 2 open ports ...
  135/tcp  MSRPC
  445/tcp  SMB

[3/3] Running risk checks on 2 services ...
Findings: 0 High, 0 Medium, 0 Low

Done in 3.6s. Report saved to: output\127_0_0_1_report.html
```

The results above are an example from a local scan, not expected results for every target.

## Generated Reports

By default, reports are written to the `output/` directory.

For example:

```text
output/
└── 127_0_0_1_report.html
```

Open the report in your default browser from PowerShell:

```powershell
Invoke-Item .\output\127_0_0_1_report.html
```

You can specify a different output path with `--output`.

## Project Architecture

The project is organized into separate modules, each responsible for a specific stage of the scanning workflow.

```text
portmortem/
├── portmortem/
│   ├── __init__.py
│   ├── main.py
│   ├── scanner.py
│   ├── probe.py
│   ├── risk_checks.py
│   └── report.py
├── test_fixtures/
├── output/
├── pyproject.toml
├── requirements.txt
├── README.md
└── LICENSE
```

| Module           | Responsibility                                                     |
| ---------------- | ------------------------------------------------------------------ |
| `main.py`        | CLI arguments, authorization confirmation, and scan orchestration. |
| `scanner.py`     | TCP connection scanning and port-specification parsing.            |
| `probe.py`       | Service fingerprinting and protocol probing.                       |
| `risk_checks.py` | Targeted security checks against identified services.              |
| `report.py`      | HTML report generation.                                            |
| `test_fixtures/` | Controlled test services and test scripts, where implemented.      |
| `output/`        | Generated HTML reports.                                            |

The workflow connects port scanning, service identification, risk checks, and report generation into a single command-line tool.

## Testing

The `test_fixtures/` directory can be used to validate the scanner against controlled services, provided the corresponding test scripts and fixtures are present.

If `test_fixtures/run_test.py` exists in your checkout, run:

```powershell
py test_fixtures/run_test.py
```

Use controlled local test services to verify expected detection behavior, including negative cases where authentication is required. Confirm the actual test results before treating a check as validated.

## Limitations

* **TCP connect scanning:** Uses TCP connections rather than raw SYN packets.
* **Limited default coverage:** The `top` option scans approximately 95 common ports, not every TCP port.
* **Fingerprinting limitations:** Services may hide banners or return insufficient information for reliable identification.
* **Targeted detection:** The risk checks cover specific conditions and do not constitute a comprehensive vulnerability assessment.
* **Potential false negatives:** A service may be vulnerable even when the scanner does not report a finding.
* **No exploitation framework:** The tool is intended for scanning, fingerprinting, and targeted detection rather than exploitation.

## Legal and Ethical Use

**Only scan hosts and networks you own or have explicit authorization to test.**

Examples include your own lab, intentionally vulnerable virtual machines, or infrastructure explicitly included in an authorized assessment scope.

Portmortem asks for authorization confirmation before scanning unless the `-y` option is supplied. Skipping the prompt does not grant permission to test a target.

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for details.
