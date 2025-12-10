"""Tests for report generator."""

import json
import pytest
from datetime import datetime
from pathlib import Path
import tempfile

from vuln_scanner.models import CVE, Host, Port, PortState, ScanResult, Severity, Vulnerability
from vuln_scanner.reporter import ReportGenerator


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Create a sample scan result for testing."""
    result = ScanResult(
        scan_type="comprehensive",
        target_network="192.168.1.0/24",
    )
    result.start_time = datetime(2024, 1, 15, 10, 0, 0)
    result.end_time = datetime(2024, 1, 15, 10, 5, 30)

    # Create host with vulnerabilities
    host = Host(
        ip="192.168.1.1",
        hostname="test-server.local",
        os_type="Linux",
        is_up=True,
    )

    # Add ports
    ssh_port = Port(22, PortState.OPEN, "tcp", "ssh", "8.9", "SSH-2.0-OpenSSH_8.9")
    http_port = Port(80, PortState.OPEN, "tcp", "http", None, "HTTP/1.1 200 OK")
    host.ports = [ssh_port, http_port]

    # Add vulnerabilities
    cve_critical = CVE(
        id="CVE-2024-6387",
        description="SSH vulnerability allowing remote code execution",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        patch_available=True,
        patch_info="Upgrade to OpenSSH 9.8",
    )
    cve_medium = CVE(
        id="CVE-TEST-001",
        description="Medium severity test vulnerability",
        severity=Severity.MEDIUM,
        cvss_score=5.0,
    )

    host.vulnerabilities = [
        Vulnerability(cve_critical, ssh_port, "192.168.1.1", "OpenSSH_8.9", "Upgrade to OpenSSH 9.8"),
        Vulnerability(cve_medium, http_port, "192.168.1.1"),
    ]

    # Create another host without vulnerabilities
    host2 = Host(
        ip="192.168.1.2",
        is_up=True,
    )
    host2.ports = [Port(443, PortState.CLOSED)]

    # Create a host that's down
    host3 = Host(
        ip="192.168.1.3",
        is_up=False,
    )

    result.hosts = [host, host2, host3]
    return result


class TestReportGenerator:
    """Tests for ReportGenerator class."""

    @pytest.fixture
    def reporter(self) -> ReportGenerator:
        """Create a report generator with temp directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ReportGenerator(tmpdir)

    def test_initialization(self) -> None:
        """Test report generator initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = ReportGenerator(tmpdir)
            assert reporter.output_dir == Path(tmpdir)

    def test_generate_json(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test JSON report generation."""
        paths = reporter.generate(sample_scan_result, formats=["json"])
        assert len(paths) == 1
        assert paths[0].suffix == ".json"

        # Verify JSON content
        with open(paths[0]) as f:
            data = json.load(f)

        assert "metadata" in data
        assert "summary" in data
        assert "hosts" in data
        assert "vulnerabilities" in data
        assert data["metadata"]["scan_type"] == "comprehensive"

    def test_generate_html(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test HTML report generation."""
        paths = reporter.generate(sample_scan_result, formats=["html"])
        assert len(paths) == 1
        assert paths[0].suffix == ".html"

        # Verify HTML content
        content = paths[0].read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "Vulnerability Scan Report" in content
        assert "CVE-2024-6387" in content

    def test_generate_text(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test text report generation."""
        paths = reporter.generate(sample_scan_result, formats=["txt"])
        assert len(paths) == 1
        assert paths[0].suffix == ".txt"

        # Verify text content
        content = paths[0].read_text(encoding="utf-8")
        assert "VULNERABILITY SCAN REPORT" in content
        assert "EXECUTIVE SUMMARY" in content
        assert "192.168.1.1" in content

    def test_generate_all_formats(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test generating all formats."""
        paths = reporter.generate(sample_scan_result, formats=["json", "html", "txt"])
        assert len(paths) == 3

        extensions = {p.suffix for p in paths}
        assert extensions == {".json", ".html", ".txt"}

    def test_generate_summary(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test summary generation."""
        summary = reporter._generate_summary(sample_scan_result)

        assert summary["total_hosts"] == 3
        assert summary["live_hosts"] == 2
        assert summary["hosts_with_vulns"] == 1
        assert summary["total_vulnerabilities"] == 2
        assert summary["severity_breakdown"]["critical"] == 1
        assert summary["severity_breakdown"]["medium"] == 1

    def test_calculate_risk_level(
        self, reporter: ReportGenerator
    ) -> None:
        """Test risk level calculation."""
        # Critical
        breakdown = {Severity.CRITICAL: 1, Severity.HIGH: 0}
        assert reporter._calculate_risk_level(breakdown) == "CRITICAL"

        # High
        breakdown = {Severity.CRITICAL: 0, Severity.HIGH: 2}
        assert reporter._calculate_risk_level(breakdown) == "HIGH"

        # Medium
        breakdown = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 1}
        assert reporter._calculate_risk_level(breakdown) == "MEDIUM"

        # Low
        breakdown = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 1}
        assert reporter._calculate_risk_level(breakdown) == "LOW"

        # None
        breakdown = {s: 0 for s in Severity}
        assert reporter._calculate_risk_level(breakdown) == "NONE"

    def test_group_by_severity(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test grouping vulnerabilities by severity."""
        grouped = reporter._group_by_severity(sample_scan_result)

        assert len(grouped[Severity.CRITICAL]) == 1
        assert len(grouped[Severity.MEDIUM]) == 1
        assert len(grouped[Severity.HIGH]) == 0
        assert len(grouped[Severity.LOW]) == 0

    def test_flatten_vulnerabilities(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test flattening vulnerabilities."""
        flat = reporter._flatten_vulnerabilities(sample_scan_result)

        assert len(flat) == 2
        # Should be sorted by severity
        assert flat[0]["cve"]["severity"] == "critical"
        assert flat[1]["cve"]["severity"] == "medium"

    def test_calculate_duration(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test scan duration calculation."""
        duration = reporter._calculate_duration(sample_scan_result)
        # 5 minutes 30 seconds
        assert "5m" in duration
        assert "30s" in duration

    def test_custom_filename(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test custom filename."""
        paths = reporter.generate(
            sample_scan_result,
            formats=["json"],
            filename="custom_report",
        )
        assert paths[0].name == "custom_report.json"


class TestReportContent:
    """Tests for report content correctness."""

    @pytest.fixture
    def reporter(self) -> ReportGenerator:
        """Create a report generator with temp directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ReportGenerator(tmpdir)

    def test_json_includes_remediation(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test JSON report includes remediation info."""
        paths = reporter.generate(sample_scan_result, formats=["json"])

        with open(paths[0]) as f:
            data = json.load(f)

        # Find the critical vulnerability
        critical_vuln = next(
            v for v in data["vulnerabilities"]
            if v["cve"]["severity"] == "critical"
        )
        assert critical_vuln["remediation"] is not None

    def test_html_includes_host_inventory(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test HTML report includes host inventory."""
        paths = reporter.generate(sample_scan_result, formats=["html"])
        content = paths[0].read_text(encoding="utf-8")

        assert "Host Inventory" in content
        assert "192.168.1.1" in content
        assert "test-server.local" in content

    def test_text_includes_severity_breakdown(
        self, reporter: ReportGenerator, sample_scan_result: ScanResult
    ) -> None:
        """Test text report includes severity breakdown."""
        paths = reporter.generate(sample_scan_result, formats=["txt"])
        content = paths[0].read_text(encoding="utf-8")

        assert "Severity Breakdown:" in content
        assert "CRITICAL: 1" in content
        assert "MEDIUM: 1" in content

    def test_empty_scan_result(
        self, reporter: ReportGenerator
    ) -> None:
        """Test report generation with empty scan result."""
        result = ScanResult()
        result.end_time = datetime.now()

        paths = reporter.generate(result, formats=["json"])
        with open(paths[0]) as f:
            data = json.load(f)

        assert data["summary"]["total_hosts"] == 0
        assert data["summary"]["total_vulnerabilities"] == 0
        assert data["summary"]["risk_level"] == "NONE"
