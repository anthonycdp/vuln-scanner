"""
Command Line Interface for Vulnerability Scanner

Provides an easy-to-use CLI for scanning networks and generating reports.
"""

import argparse
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

# Configure UTF-8 encoding for Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from vuln_scanner import CVEChecker, PortScanner, ReportGenerator, ServiceDetector
from vuln_scanner.models import ScanResult
from vuln_scanner.scanner import ScanConfig

# Constants
LEGAL_NOTICE_DELAY_SECONDS = 3
EXIT_CODE_SUCCESS = 0
EXIT_CODE_HIGH_VULN = 1
EXIT_CODE_CRITICAL_VULN = 2
EXIT_CODE_PERMISSION_DENIED = 126
EXIT_CODE_INTERRUPTED = 130

console = Console()


def print_banner() -> None:
    """Print application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                     VULNERABILITY SCANNER                      ║
║              Defensive Network Security Tool                   ║
╠═══════════════════════════════════════════════════════════════╣
║  ⚠️  For authorized use only - scan networks you own          ║
║  🔒 Help secure your home network with CVE checks             ║
╚═══════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold blue")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="vuln-scan",
        description="Defensive Network Vulnerability Scanner for Home Networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single host
  vuln-scan 192.168.1.100

  # Scan a network range
  vuln-scan 192.168.1.0/24

  # Quick scan with common ports only
  vuln-scan 192.168.1.0/24 --quick

  # Generate HTML report only
  vuln-scan 192.168.1.0/24 --format html

  # Specify output directory
  vuln-scan 192.168.1.0/24 --output ./my_reports

⚠️  LEGAL NOTICE: Only use this tool on networks you own or have
    explicit written permission to test. Unauthorized scanning may
    violate computer crime laws.
        """,
    )

    parser.add_argument(
        "target",
        help="Target IP address or network (CIDR notation, e.g., 192.168.1.0/24)",
    )

    parser.add_argument(
        "-p",
        "--ports",
        help="Port range or list (e.g., '22,80,443' or '1-1000')",
        default=None,
    )

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan - only check common ports",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Scan timeout in seconds (default: 2.0)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="reports",
        help="Output directory for reports (default: reports)",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "html", "txt", "all"],
        default="all",
        help="Report format (default: all)",
    )

    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip CVE vulnerability checking",
    )

    parser.add_argument(
        "--list-ports",
        action="store_true",
        help="List default ports and exit",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    return parser.parse_args()


def parse_ports(port_string: str | None, quick: bool) -> list[int]:
    """Parse port specification into list of port numbers."""
    config = ScanConfig()

    if quick:
        return config.common_ports or []

    if not port_string:
        return config.common_ports or []

    ports: list[int] = []

    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            # Range
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            # Single port
            ports.append(int(part))

    return sorted(set(ports))


def run_scan(args: argparse.Namespace) -> ScanResult:
    """Execute the vulnerability scan."""
    config = ScanConfig(
        timeout=args.timeout,
        threads=args.threads,
    )

    ports = parse_ports(args.ports, args.quick)
    scanner = PortScanner(config)
    detector = ServiceDetector()
    cve_checker = CVEChecker() if not args.no_cve else None

    scan_result = ScanResult(
        scan_type="quick" if args.quick else "comprehensive",
        target_network=args.target if "/" in args.target else None,
    )

    def progress_callback(message: str) -> None:
        if args.verbose:
            console.print(f"[dim]{message}[/dim]")

    scanner.set_progress_callback(progress_callback)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        # Determine if single host or network
        if "/" in args.target:
            # Network scan
            task = progress.add_task("Scanning network...", total=None)

            console.print(f"[cyan]Target Network:[/cyan] {args.target}")
            console.print(f"[cyan]Ports to scan:[/cyan] {len(ports)}")
            console.print()

            hosts = scanner.scan_network(args.target, ports)
            for host in hosts:
                scan_result.hosts.append(host)
                progress.update(task, description=f"Scanned {host.ip}")
        else:
            # Single host scan
            task = progress.add_task(f"Scanning {args.target}...", total=None)

            console.print(f"[cyan]Target Host:[/cyan] {args.target}")
            console.print(f"[cyan]Ports to scan:[/cyan] {len(ports)}")
            console.print()

            host = scanner.scan_host(args.target, ports)
            scan_result.hosts.append(host)

        # Service detection
        progress.update(task, description="Detecting services...")
        for host in scan_result.hosts:
            detector.analyze_host(host)

        # CVE checking
        if cve_checker:
            progress.update(task, description="Checking for CVEs...")
            for host in scan_result.hosts:
                vulnerabilities = cve_checker.check_host(host)
                host.vulnerabilities.extend(vulnerabilities)

        progress.update(task, description="Scan complete!")

    scan_result.end_time = datetime.now()
    return scan_result


def generate_reports(
    scan_result: ScanResult,
    output_dir: str,
    format_choice: str,
) -> list[Path]:
    """Generate reports in specified format(s)."""
    reporter = ReportGenerator(output_dir)

    if format_choice == "all":
        formats = ["json", "html", "txt"]
    else:
        formats = [format_choice]

    return reporter.generate(scan_result, formats=formats)


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Handle list-ports
    if args.list_ports:
        config = ScanConfig()
        console.print("[bold]Default ports scanned:[/bold]")
        for port in config.common_ports or []:
            service = PortScanner.SERVICE_MAP.get(port, "unknown")
            console.print(f"  {port:5d} - {service}")
        return EXIT_CODE_SUCCESS

    print_banner()

    # Legal notice
    console.print(
        "\n[yellow]⚠️  LEGAL NOTICE: Only scan networks you own or have permission to test.[/yellow]"
    )
    console.print(f"[dim]Press Ctrl+C to cancel, or wait {LEGAL_NOTICE_DELAY_SECONDS} seconds to continue...[/dim]\n")

    try:
        time.sleep(LEGAL_NOTICE_DELAY_SECONDS)
    except KeyboardInterrupt:
        console.print("\n[red]Scan cancelled by user.[/red]")
        return EXIT_CODE_INTERRUPTED

    try:
        # Run scan
        scan_result = run_scan(args)

        # Print summary
        console.print()
        reporter = ReportGenerator(args.output)
        reporter.print_summary(scan_result)

        # Generate reports
        console.print("\n[cyan]Generating reports...[/cyan]")
        report_paths = generate_reports(scan_result, args.output, args.format)

        console.print("\n[green]✓ Reports generated:[/green]")
        for path in report_paths:
            console.print(f"  • {path}")

        # Exit code based on vulnerabilities
        return _get_exit_code(scan_result)

    except PermissionError:
        console.print("[red]Error: Insufficient permissions. Try running with sudo.[/red]")
        return EXIT_CODE_PERMISSION_DENIED
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return EXIT_CODE_INTERRUPTED
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if args.verbose:
            traceback.print_exc()
        return EXIT_CODE_ERROR


def _get_exit_code(scan_result: ScanResult) -> int:
    """Return exit code based on vulnerability severity."""
    severity = scan_result.severity_breakdown

    if severity.get("critical", 0) > 0:
        console.print("\n[bold red]⚠️  Critical vulnerabilities detected![/bold red]")
        return EXIT_CODE_CRITICAL_VULN

    if severity.get("high", 0) > 0:
        console.print("\n[bold yellow]⚠️  High severity vulnerabilities detected![/bold yellow]")
        return EXIT_CODE_HIGH_VULN

    console.print("\n[green]✓ No critical or high vulnerabilities detected.[/green]")
    return EXIT_CODE_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
