# Defensive Vulnerability Scanner

A network vulnerability scanner designed for home networks, built with Python and scapy. This tool helps identify open ports, detect running services, and check for known vulnerabilities (CVEs) on systems you own.

## Legal Disclaimer

**IMPORTANT: This tool is intended for authorized security testing and educational purposes ONLY.**

- Use this scanner **only** on networks you own or have **explicit written permission** to test
- Unauthorized network scanning may violate computer crime laws (e.g., CFAA in the US, Computer Misuse Act in the UK)
- Always obtain proper authorization before scanning any network
- The developers assume no liability for misuse of this tool

This tool follows responsible disclosure principles and is designed to help network administrators secure their own systems.

## Features

- **Port Scanning**: TCP SYN (stealth) scanning for open port detection
- **Service Detection**: Identify services running on open ports with banner grabbing
- **CVE Checking**: Compare detected services against a database of known vulnerabilities
- **Prioritized Reports**: Generate reports sorted by severity (Critical -> Low)
- **Multiple Output Formats**: JSON, HTML, and plain text reports
- **Network Range Support**: Scan individual hosts or entire subnets (CIDR notation)

### CVE Database

The scanner includes a curated database of high-impact CVEs, including:

| CVE | Name | Severity | Affected Service |
|-----|------|----------|------------------|
| CVE-2024-6387 | regreSSHion | Critical | OpenSSH |
| CVE-2021-44228 | Log4Shell | Critical | HTTP/Java |
| CVE-2019-0708 | BlueKeep | Critical | RDP |
| CVE-2017-0144 | EternalBlue | Critical | SMB |
| CVE-2020-0796 | SMBGhost | Critical | SMB |
| CVE-2021-41773 | Apache Path Traversal | Critical | HTTP |

## Installation

### Prerequisites

- Python 3.10 or higher
- Linux/macOS (Windows support is experimental - requires Npcap for raw sockets)
- Root/sudo privileges for raw socket operations

### Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/vuln-scanner.git
cd vuln-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package with development dependencies
pip install -e ".[dev]"
```

### Using pip

```bash
pip install vuln-scanner
```

## Quick Start

```bash
# Scan a single host
vuln-scan 192.168.1.1

# Scan your home network
vuln-scan 192.168.1.0/24

# Quick scan (common ports only)
vuln-scan 192.168.1.0/24 --quick

# Generate HTML report only
vuln-scan 192.168.1.0/24 --format html --output ./my_reports
```

## Usage

### Command Line Options

```
usage: vuln-scan [-h] [-p PORTS] [--quick] [-t TIMEOUT] [--threads THREADS]
                 [-o OUTPUT] [-f {json,html,txt,all}] [--no-cve]
                 [--list-ports] [-v] [--version]
                 target

Defensive Network Vulnerability Scanner for Home Networks

positional arguments:
  target                Target IP address or network (CIDR notation)

options:
  -h, --help            show this help message and exit
  -p, --ports PORTS     Port range or list (e.g., '22,80,443' or '1-1000')
  --quick               Quick scan - only check common ports
  -t, --timeout TIMEOUT Scan timeout in seconds (default: 2.0)
  --threads THREADS     Number of concurrent threads (default: 50)
  -o, --output OUTPUT   Output directory for reports (default: reports)
  -f, --format {json,html,txt,all}
                        Report format (default: all)
  --no-cve              Skip CVE vulnerability checking
  --list-ports          List default ports and exit
  -v, --verbose         Enable verbose output
  --version             show program's version number and exit
```

### Examples

```bash
# Scan specific ports
vuln-scan 192.168.1.1 -p 22,80,443,3306,5432

# Scan a port range
vuln-scan 192.168.1.1 -p 1-1000

# Verbose quick scan
vuln-scan 192.168.1.0/24 --quick -v

# Skip CVE checking (faster scan)
vuln-scan 192.168.1.1 --no-cve

# Custom timeout and threads
vuln-scan 10.0.0.0/24 -t 5.0 --threads 100
```

### Using as a Library

```python
from vuln_scanner import PortScanner, ServiceDetector, CVEChecker, ReportGenerator
from vuln_scanner.scanner import ScanConfig
from vuln_scanner.models import ScanResult

# Configure the scanner
config = ScanConfig(
    timeout=2.0,
    threads=50,
)

# Initialize components
scanner = PortScanner(config)
detector = ServiceDetector()
cve_checker = CVEChecker()
reporter = ReportGenerator("reports")

# Scan a host
host = scanner.scan_host("192.168.1.1")

# Detect services
detector.analyze_host(host)

# Check for vulnerabilities
vulnerabilities = cve_checker.check_host(host)
host.vulnerabilities.extend(vulnerabilities)

# Create scan result
result = ScanResult(hosts=[host])

# Generate reports
reporter.generate(result, formats=["html", "json"])
```

### Adding Custom CVEs

```python
from vuln_scanner import CVEChecker

checker = CVEChecker()

# Add a custom vulnerability
checker.add_cve({
    "id": "CVE-2024-XXXXX",
    "description": "Custom vulnerability description",
    "severity": "high",
    "cvss_score": 8.5,
    "affected_service": "custom-service",
    "affected_versions": ["1.0", "2.0"],
    "patch_versions": ["3.0"],
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"],
    "remediation": "Upgrade to version 3.0 or later"
})

# Or load from a JSON file
checker = CVEChecker(custom_db_path=Path("custom_cves.json"))
```

## Report Formats

### JSON Report

Structured data for programmatic processing:

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00",
    "scanner_version": "1.0.0",
    "target_network": "192.168.1.0/24"
  },
  "summary": {
    "total_hosts": 10,
    "live_hosts": 8,
    "total_vulnerabilities": 5,
    "risk_level": "HIGH"
  },
  "vulnerabilities": [...]
}
```

### HTML Report

Professional, styled report with:

- Executive summary dashboard
- Severity-colored vulnerability cards
- Host inventory with open ports
- Remediation recommendations

### Text Report

Plain text format for scripting and quick review:

```
================================================================================
VULNERABILITY SCAN REPORT
================================================================================

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Hosts Scanned: 10
Live Hosts: 8
Total Vulnerabilities: 5

Severity Breakdown:
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 2
```

## Architecture

```
vuln_scanner/
+-- __init__.py          # Package exports
+-- cli.py               # Command-line interface
+-- models.py            # Data models (Host, Port, CVE, etc.)
+-- scanner.py           # Port scanning and service detection
+-- cve_checker.py       # CVE database and vulnerability checking
+-- reporter.py          # Report generation (JSON, HTML, TXT)

tests/
+-- test_models.py       # Model unit tests
+-- test_scanner.py      # Scanner unit tests
+-- test_cve_checker.py  # CVE checker tests
+-- test_reporter.py     # Reporter tests
+-- test_cli.py          # CLI integration tests
```

## Security Considerations

### For Users

1. **Authorization**: Always ensure you have permission to scan
2. **Scope**: Clearly define the scope of your scanning activities
3. **Documentation**: Keep records of your authorization
4. **Discretion**: Handle scan results securely; they contain sensitive information

### For Developers

1. **Input Validation**: The scanner validates IP addresses and port ranges
2. **Rate Limiting**: Configurable timeouts prevent network flooding
3. **Safe Defaults**: Conservative default settings minimize impact

## Responsible Disclosure

If you discover a new vulnerability:

1. **Do not** publicly disclose immediately
2. Contact the vendor/developer through their security contact
3. Provide reasonable time for a fix (typically 90 days)
4. Consider using coordinated disclosure platforms:
   - [HackerOne](https://hackerone.com)
   - [Bugcrowd](https://bugcrowd.com)
   - [CVE Program](https://cve.mitre.org)

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vuln_scanner

# Run specific test file
pytest tests/test_cve_checker.py -v

# Run with verbose output
pytest -v --tb=short
```

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run linting
ruff check vuln_scanner tests

# Run type checking
mypy vuln_scanner

# Format code
ruff format vuln_scanner tests
```

### Adding New Features

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your feature
4. Implement the feature
5. Ensure all tests pass (`pytest`)
6. Commit with clear messages
7. Push and create a Pull Request

## Limitations

- Requires root/sudo for raw socket operations (Linux/macOS)
- On Windows, requires Npcap for packet capture functionality
- CVE database is curated; consider integrating with NVD API for comprehensive coverage
- Banner grabbing may not work on all services
- Some firewalls may block scan packets

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the main repository.

Areas for contribution:
- Additional CVE entries
- New scan techniques
- Performance improvements
- Documentation improvements
- Bug fixes

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Scapy](https://scapy.net/) - Powerful packet manipulation library
- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting

## Changelog

### v1.0.0 (2024-01-15)

- Initial release
- TCP SYN scanning
- Service detection with banner grabbing
- CVE checking against curated database
- Multi-format report generation
- CLI interface with progress indicators

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
