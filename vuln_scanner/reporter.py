"""
Report Generator Module

Generates prioritized vulnerability reports in multiple formats.
Supports JSON, HTML, and plain text output.

Reports are organized by severity (Critical > High > Medium > Low > Info)
to help prioritize remediation efforts.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vuln_scanner.models import Host, ScanResult, Severity, Vulnerability

# Constants
SCANNER_VERSION = "1.0.0"
REPORT_LINE_WIDTH = 80

# Severity ordering for reports
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
SEVERITY_SORT_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Risk level colors for console output
RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "NONE": "green",
}


class ReportGenerator:
    """
    Generates vulnerability reports in multiple formats.

    Reports include:
    - Executive summary
    - Host inventory
    - Vulnerability details by severity
    - Remediation recommendations
    """

    def __init__(self, output_dir: Path | str = "reports") -> None:
        """Initialize report generator with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console()

    def generate(
        self,
        scan_result: ScanResult,
        formats: list[str] | None = None,
        filename: str | None = None,
    ) -> list[Path]:
        """
        Generate reports in specified formats.

        Args:
            scan_result: Complete scan results
            formats: List of formats (json, html, txt). Default: all
            filename: Base filename without extension

        Returns:
            List of paths to generated reports
        """
        formats = formats or ["json", "html", "txt"]
        filename = filename or f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        generated: list[Path] = []

        for fmt in formats:
            if fmt == "json":
                path = self._generate_json(scan_result, filename)
                generated.append(path)
            elif fmt == "html":
                path = self._generate_html(scan_result, filename)
                generated.append(path)
            elif fmt == "txt":
                path = self._generate_text(scan_result, filename)
                generated.append(path)

        return generated

    def _generate_json(self, scan_result: ScanResult, filename: str) -> Path:
        """Generate JSON report."""
        path = self.output_dir / f"{filename}.json"

        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner_version": SCANNER_VERSION,
                "scan_type": scan_result.scan_type,
                "target_network": scan_result.target_network,
                "scan_duration": self._calculate_duration(scan_result),
            },
            "summary": self._generate_summary(scan_result),
            "hosts": scan_result.to_dict()["hosts"],
            "vulnerabilities": self._flatten_vulnerabilities(scan_result),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return path

    def _generate_html(self, scan_result: ScanResult, filename: str) -> Path:
        """Generate HTML report with styling."""
        path = self.output_dir / f"{filename}.html"

        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            metadata={
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": SCANNER_VERSION,
                "target_network": scan_result.target_network or "N/A",
            },
            summary=self._generate_summary(scan_result),
            hosts=scan_result.hosts,
            severity_order=SEVERITY_ORDER,
            vulnerabilities_by_severity=self._group_by_severity(scan_result),
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return path

    def _generate_text(self, scan_result: ScanResult, filename: str) -> Path:
        """Generate plain text report."""
        path = self.output_dir / f"{filename}.txt"

        lines = self._build_text_report_lines(scan_result)

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return path

    def _build_text_report_lines(self, scan_result: ScanResult) -> list[str]:
        """Build all lines for the text report."""
        lines: list[str] = []
        lines.extend(self._build_report_header())
        lines.extend(self._build_summary_section(scan_result))
        lines.extend(self._build_vulnerabilities_section(scan_result))
        lines.extend(self._build_host_inventory_section(scan_result))
        lines.extend(self._build_report_footer())
        return lines

    def _build_report_header(self) -> list[str]:
        """Build report header lines."""
        return [
            "=" * REPORT_LINE_WIDTH,
            "VULNERABILITY SCAN REPORT",
            "=" * REPORT_LINE_WIDTH,
            "",
        ]

    def _build_summary_section(self, scan_result: ScanResult) -> list[str]:
        """Build executive summary section."""
        summary = self._generate_summary(scan_result)
        lines = [
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: {scan_result.target_network or 'N/A'}",
            f"Scan Type: {scan_result.scan_type}",
            "",
            "-" * REPORT_LINE_WIDTH,
            "EXECUTIVE SUMMARY",
            "-" * REPORT_LINE_WIDTH,
            f"Total Hosts Scanned: {summary['total_hosts']}",
            f"Live Hosts: {summary['live_hosts']}",
            f"Hosts with Vulnerabilities: {summary['hosts_with_vulns']}",
            f"Total Vulnerabilities: {summary['total_vulnerabilities']}",
            "",
            "Severity Breakdown:",
        ]

        for severity in SEVERITY_ORDER:
            count = summary["severity_breakdown"].get(severity.value, 0)
            lines.append(f"  {severity.value.upper()}: {count}")

        lines.append("")
        return lines

    def _build_vulnerabilities_section(self, scan_result: ScanResult) -> list[str]:
        """Build vulnerabilities section grouped by severity."""
        lines: list[str] = []
        vulns_by_severity = self._group_by_severity(scan_result)

        for severity in SEVERITY_ORDER:
            vulns = vulns_by_severity.get(severity, [])
            if not vulns:
                continue

            lines.extend([
                "-" * REPORT_LINE_WIDTH,
                f"{severity.value.upper()} VULNERABILITIES ({len(vulns)})",
                "-" * REPORT_LINE_WIDTH,
            ])

            for i, vuln in enumerate(vulns, 1):
                lines.extend(self._format_vulnerability_entry(i, vuln))
            lines.append("")

        return lines

    def _format_vulnerability_entry(self, index: int, vuln: Vulnerability) -> list[str]:
        """Format a single vulnerability entry."""
        lines = [
            f"\n[{index}] {vuln.cve.id}",
            f"    Host: {vuln.host}:{vuln.port.number}",
            f"    Service: {vuln.port.service or 'unknown'}",
            f"    CVSS Score: {vuln.cve.cvss_score}",
            f"    Description: {vuln.cve.description}",
        ]
        if vuln.remediation:
            lines.append(f"    Remediation: {vuln.remediation}")
        return lines

    def _build_host_inventory_section(self, scan_result: ScanResult) -> list[str]:
        """Build host inventory section."""
        lines = [
            "-" * REPORT_LINE_WIDTH,
            "HOST INVENTORY",
            "-" * REPORT_LINE_WIDTH,
        ]

        for host in scan_result.live_hosts:
            lines.extend(self._format_host_entry(host))

        lines.append("")
        return lines

    def _format_host_entry(self, host: Host) -> list[str]:
        """Format a single host entry."""
        lines = [f"\n{host.ip}"]
        if host.hostname:
            lines.append(f"  Hostname: {host.hostname}")
        lines.append(f"  Open Ports: {len(host.open_ports)}")

        for port in host.open_ports:
            service_info = port.service or "unknown"
            if port.version:
                service_info += f" ({port.version})"
            lines.append(f"    - {port.number}/{port.protocol} - {service_info}")

        lines.append(f"  Vulnerabilities: {len(host.vulnerabilities)}")
        return lines

    def _build_report_footer(self) -> list[str]:
        """Build report footer."""
        return [
            "=" * REPORT_LINE_WIDTH,
            "END OF REPORT",
            "=" * REPORT_LINE_WIDTH,
        ]
        lines.append("")

        # Metadata
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Target: {scan_result.target_network or 'N/A'}")
        lines.append(f"Scan Type: {scan_result.scan_type}")
        lines.append("")

        # Summary
        summary = self._generate_summary(scan_result)
        lines.append("-" * 80)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Hosts Scanned: {summary['total_hosts']}")
        lines.append(f"Live Hosts: {summary['live_hosts']}")
        lines.append(f"Hosts with Vulnerabilities: {summary['hosts_with_vulns']}")
        lines.append(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        lines.append("")

        lines.append("Severity Breakdown:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = summary["severity_breakdown"].get(severity.value, 0)
            lines.append(f"  {severity.value.upper()}: {count}")
        lines.append("")

        # Vulnerabilities by severity
        vulns_by_severity = self._group_by_severity(scan_result)

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            vulns = vulns_by_severity.get(severity, [])
            if not vulns:
                continue

            lines.append("-" * 80)
            lines.append(f"{severity.value.upper()} VULNERABILITIES ({len(vulns)})")
            lines.append("-" * 80)

            for i, vuln in enumerate(vulns, 1):
                lines.append(f"\n[{i}] {vuln.cve.id}")
                lines.append(f"    Host: {vuln.host}:{vuln.port.number}")
                lines.append(f"    Service: {vuln.port.service or 'unknown'}")
                lines.append(f"    CVSS Score: {vuln.cve.cvss_score}")
                lines.append(f"    Description: {vuln.cve.description}")
                if vuln.remediation:
                    lines.append(f"    Remediation: {vuln.remediation}")
            lines.append("")

        # Host inventory
        lines.append("-" * 80)
        lines.append("HOST INVENTORY")
        lines.append("-" * 80)

        for host in scan_result.live_hosts:
            lines.append(f"\n{host.ip}")
            if host.hostname:
                lines.append(f"  Hostname: {host.hostname}")
            lines.append(f"  Open Ports: {len(host.open_ports)}")
            for port in host.open_ports:
                service_info = port.service or "unknown"
                if port.version:
                    service_info += f" ({port.version})"
                lines.append(f"    - {port.number}/{port.protocol} - {service_info}")
            lines.append(f"  Vulnerabilities: {len(host.vulnerabilities)}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return path

    def _generate_summary(self, scan_result: ScanResult) -> dict[str, Any]:
        """Generate executive summary."""
        hosts_with_vulns = [h for h in scan_result.hosts if h.vulnerabilities]
        severity_breakdown = scan_result.severity_breakdown

        return {
            "total_hosts": len(scan_result.hosts),
            "live_hosts": len(scan_result.live_hosts),
            "hosts_with_vulns": len(hosts_with_vulns),
            "total_vulnerabilities": scan_result.total_vulnerabilities,
            "severity_breakdown": {
                s.value: c for s, c in severity_breakdown.items()
            },
            "risk_level": self._calculate_risk_level(severity_breakdown),
        }

    def _calculate_risk_level(self, breakdown: dict[Severity, int]) -> str:
        """Calculate overall risk level."""
        if breakdown.get(Severity.CRITICAL, 0) > 0:
            return "CRITICAL"
        if breakdown.get(Severity.HIGH, 0) > 0:
            return "HIGH"
        if breakdown.get(Severity.MEDIUM, 0) > 0:
            return "MEDIUM"
        if breakdown.get(Severity.LOW, 0) > 0:
            return "LOW"
        return "NONE"

    def _group_by_severity(
        self, scan_result: ScanResult
    ) -> dict[Severity, list[Vulnerability]]:
        """Group vulnerabilities by severity."""
        grouped: dict[Severity, list[Vulnerability]] = {s: [] for s in Severity}

        for host in scan_result.hosts:
            for vuln in host.vulnerabilities:
                grouped[vuln.cve.severity].append(vuln)

        return grouped

    def _flatten_vulnerabilities(self, scan_result: ScanResult) -> list[dict[str, Any]]:
        """Flatten all vulnerabilities into a list."""
        vulns: list[dict[str, Any]] = []

        for host in scan_result.hosts:
            for vuln in host.vulnerabilities:
                vulns.append(vuln.to_dict())

        vulns.sort(key=lambda v: SEVERITY_SORT_ORDER.get(Severity(v["cve"]["severity"]), 99))
        return vulns

    def _calculate_duration(self, scan_result: ScanResult) -> str:
        """Calculate scan duration."""
        if not scan_result.end_time:
            return "In progress"

        delta = scan_result.end_time - scan_result.start_time
        total_seconds = int(delta.total_seconds())
        minutes, seconds = divmod(total_seconds, 60)
        hours, minutes = divmod(minutes, 60)

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    def print_summary(self, scan_result: ScanResult) -> None:
        """Print a summary to the console using rich."""
        summary = self._generate_summary(scan_result)

        # Header
        self.console.print(
            Panel(
                "[bold blue]Vulnerability Scan Results[/bold blue]",
                subtitle=f"Target: {scan_result.target_network or 'N/A'}",
            )
        )

        # Summary table
        self._print_summary_table(summary)

        # Severity breakdown
        self._print_severity_table(summary)

        # Top vulnerabilities
        self._print_top_vulnerabilities(scan_result)

    def _print_summary_table(self, summary: dict[str, Any]) -> None:
        """Print the summary table."""
        summary_table = Table(title="Executive Summary", show_header=False)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")

        summary_table.add_row("Total Hosts", str(summary["total_hosts"]))
        summary_table.add_row("Live Hosts", str(summary["live_hosts"]))
        summary_table.add_row("Hosts with Vulnerabilities", str(summary["hosts_with_vulns"]))
        summary_table.add_row("Total Vulnerabilities", str(summary["total_vulnerabilities"]))

        risk_color = RISK_COLORS.get(summary["risk_level"], "white")
        summary_table.add_row("Risk Level", f"[{risk_color}]{summary['risk_level']}[/{risk_color}]")

        self.console.print(summary_table)

    def _print_severity_table(self, summary: dict[str, Any]) -> None:
        """Print the severity breakdown table."""
        severity_table = Table(title="Severity Breakdown")
        severity_table.add_column("Severity", style="white")
        severity_table.add_column("Count", justify="right")

        for severity in SEVERITY_ORDER:
            count = summary["severity_breakdown"].get(severity.value, 0)
            if count > 0:
                severity_table.add_row(
                    f"[{severity.color}]{severity.value.upper()}[/{severity.color}]",
                    str(count),
                )

        self.console.print(severity_table)

    def _print_top_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Print top critical/high vulnerabilities."""
        if scan_result.total_vulnerabilities == 0:
            return

        self.console.print("\n[bold]Top Critical/High Vulnerabilities:[/bold]")

        for host in scan_result.hosts:
            for vuln in host.vulnerabilities:
                if vuln.cve.severity in [Severity.CRITICAL, Severity.HIGH]:
                    self.console.print(
                        f"  [{vuln.cve.severity.color}]{vuln.cve.id}[/{vuln.cve.severity.color}] "
                        f"on {host.ip}:{vuln.port.number} ({vuln.port.service or 'unknown'})"
                    )


# HTML template for reports
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 10px;
        }
        h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        .metadata {
            opacity: 0.8;
            font-size: 0.9em;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #1a1a2e;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        .summary-item {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .summary-item .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #1a1a2e;
        }
        .summary-item .label {
            color: #666;
            font-size: 0.9em;
        }
        .risk-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .risk-critical { background: #dc3545; color: white; }
        .risk-high { background: #fd7e14; color: white; }
        .risk-medium { background: #ffc107; color: #333; }
        .risk-low { background: #17a2b8; color: white; }
        .risk-none { background: #28a745; color: white; }
        .severity-critical { border-left: 4px solid #dc3545; }
        .severity-high { border-left: 4px solid #fd7e14; }
        .severity-medium { border-left: 4px solid #ffc107; }
        .severity-low { border-left: 4px solid #17a2b8; }
        .vulnerability {
            padding: 15px;
            margin-bottom: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .vulnerability h4 {
            color: #333;
            margin-bottom: 10px;
        }
        .vulnerability .meta {
            font-size: 0.85em;
            color: #666;
            margin-bottom: 10px;
        }
        .vulnerability .description {
            margin-bottom: 10px;
        }
        .vulnerability .remediation {
            background: #e8f5e9;
            padding: 10px;
            border-radius: 5px;
            font-size: 0.9em;
        }
        .severity-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #17a2b8; color: white; }
        .host-item {
            padding: 15px;
            margin-bottom: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .host-item h4 {
            color: #1a1a2e;
            margin-bottom: 10px;
        }
        .port-list {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
        }
        .port-tag {
            background: #e3f2fd;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.8em;
        }
        .disclaimer {
            background: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            margin-top: 30px;
            font-size: 0.9em;
        }
        footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Vulnerability Scan Report</h1>
            <div class="metadata">
                Generated: {{ metadata.generated_at }} |
                Scanner Version: {{ metadata.scanner_version }} |
                Target: {{ metadata.target_network }}
            </div>
        </header>

        <div class="card">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="number">{{ summary.total_hosts }}</div>
                    <div class="label">Total Hosts</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{ summary.live_hosts }}</div>
                    <div class="label">Live Hosts</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{ summary.hosts_with_vulns }}</div>
                    <div class="label">Vulnerable Hosts</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{ summary.total_vulnerabilities }}</div>
                    <div class="label">Total Vulnerabilities</div>
                </div>
                <div class="summary-item">
                    <span class="risk-badge risk-{{ summary.risk_level.lower() }}">
                        {{ summary.risk_level }} Risk
                    </span>
                    <div class="label">Overall Risk</div>
                </div>
            </div>

            <h3 style="margin-top: 20px;">Severity Breakdown</h3>
            <div class="summary-grid" style="margin-top: 10px;">
                <div class="summary-item" style="background: #fce4ec;">
                    <div class="number" style="color: #c62828;">{{ summary.severity_breakdown.critical|default(0) }}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-item" style="background: #fff3e0;">
                    <div class="number" style="color: #e65100;">{{ summary.severity_breakdown.high|default(0) }}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-item" style="background: #fffde7;">
                    <div class="number" style="color: #f57f17;">{{ summary.severity_breakdown.medium|default(0) }}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-item" style="background: #e3f2fd;">
                    <div class="number" style="color: #1565c0;">{{ summary.severity_breakdown.low|default(0) }}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>

        {% for severity in severity_order %}
            {% set vulns = vulnerabilities_by_severity.get(severity, []) %}
            {% if vulns %}
            <div class="card">
                <h2>
                    <span class="severity-badge badge-{{ severity.value }}">{{ severity.value.upper() }}</span>
                    Vulnerabilities ({{ vulns|length }})
                </h2>
                {% for vuln in vulns %}
                <div class="vulnerability severity-{{ severity.value }}">
                    <h4>{{ vuln.cve.id }}</h4>
                    <div class="meta">
                        <strong>Host:</strong> {{ vuln.host }}:{{ vuln.port.number }} |
                        <strong>Service:</strong> {{ vuln.port.service or 'unknown' }} |
                        <strong>CVSS:</strong> {{ vuln.cve.cvss_score }}
                    </div>
                    <div class="description">{{ vuln.cve.description }}</div>
                    {% if vuln.remediation %}
                    <div class="remediation">
                        <strong>🔧 Remediation:</strong> {{ vuln.remediation }}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% endif %}
        {% endfor %}

        <div class="card">
            <h2>🖥️ Host Inventory</h2>
            {% for host in hosts %}
                {% if host.is_up %}
                <div class="host-item">
                    <h4>{{ host.ip }}{% if host.hostname %} ({{ host.hostname }}){% endif %}</h4>
                    <div class="port-list">
                        {% for port in host.open_ports %}
                        <span class="port-tag">{{ port.number }}/{{ port.protocol }} - {{ port.service or 'unknown' }}</span>
                        {% endfor %}
                    </div>
                    <div style="margin-top: 10px; font-size: 0.85em; color: #666;">
                        {{ host.vulnerabilities|length }} vulnerability(ies) found
                    </div>
                </div>
                {% endif %}
            {% endfor %}
        </div>

        <div class="disclaimer">
            <strong>⚠️ Responsible Disclosure Notice:</strong> This report is intended for authorized security testing and educational purposes only. Use this information to improve the security of systems you own or are authorized to test. Never use this tool or its results for unauthorized access or malicious purposes.
        </div>

        <footer>
            Generated by Vulnerability Scanner v{{ metadata.scanner_version }} |
            For authorized use only
        </footer>
    </div>
</body>
</html>
"""
