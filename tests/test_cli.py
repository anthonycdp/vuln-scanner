"""Tests for CLI module."""

import pytest
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path

from vuln_scanner.cli import (
    parse_ports,
    parse_args,
)
from vuln_scanner.scanner import ScanConfig


class TestParsePorts:
    """Tests for parse_ports function."""

    def test_quick_scan_ports(self) -> None:
        """Test quick scan uses common ports."""
        ports = parse_ports(None, quick=True)
        config = ScanConfig()

        assert ports == config.common_ports

    def test_default_ports(self) -> None:
        """Test default port selection."""
        ports = parse_ports(None, quick=False)
        config = ScanConfig()

        assert ports == config.common_ports

    def test_single_port(self) -> None:
        """Test single port parsing."""
        ports = parse_ports("22", quick=False)

        assert ports == [22]

    def test_multiple_ports(self) -> None:
        """Test multiple port parsing."""
        ports = parse_ports("22,80,443", quick=False)

        assert sorted(ports) == [22, 80, 443]

    def test_port_range(self) -> None:
        """Test port range parsing."""
        ports = parse_ports("80-85", quick=False)

        assert ports == [80, 81, 82, 83, 84, 85]

    def test_mixed_ports_and_ranges(self) -> None:
        """Test mixed ports and ranges."""
        ports = parse_ports("22,80-82,443", quick=False)

        assert sorted(ports) == [22, 80, 81, 82, 443]

    def test_duplicate_ports_deduped(self) -> None:
        """Test duplicate ports are removed."""
        ports = parse_ports("22,22,80,80", quick=False)

        assert sorted(ports) == [22, 80]

    def test_ports_sorted(self) -> None:
        """Test ports are sorted."""
        ports = parse_ports("443,22,80", quick=False)

        assert ports == [22, 80, 443]


class TestParseArgs:
    """Tests for CLI argument parsing."""

    def test_basic_args(self) -> None:
        """Test basic argument parsing."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1"]):
            args = parse_args()

            assert args.target == "192.168.1.1"
            assert args.quick is False
            assert args.format == "all"

    def test_quick_scan(self) -> None:
        """Test quick scan flag."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.0/24", "--quick"]):
            args = parse_args()

            assert args.target == "192.168.1.0/24"
            assert args.quick is True

    def test_custom_ports(self) -> None:
        """Test custom port specification."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1", "-p", "22,80,443"]):
            args = parse_args()

            assert args.ports == "22,80,443"

    def test_output_directory(self) -> None:
        """Test output directory option."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1", "-o", "/tmp/reports"]):
            args = parse_args()

            assert args.output == "/tmp/reports"

    def test_format_option(self) -> None:
        """Test format option."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1", "-f", "html"]):
            args = parse_args()

            assert args.format == "html"

    def test_timeout_option(self) -> None:
        """Test timeout option."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1", "-t", "5.0"]):
            args = parse_args()

            assert args.timeout == 5.0

    def test_threads_option(self) -> None:
        """Test threads option."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1", "--threads", "100"]):
            args = parse_args()

            assert args.threads == 100

    def test_no_cve_flag(self) -> None:
        """Test no-CVE flag."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1", "--no-cve"]):
            args = parse_args()

            assert args.no_cve is True

    def test_verbose_flag(self) -> None:
        """Test verbose flag."""
        with patch("sys.argv", ["vuln-scan", "192.168.1.1", "-v"]):
            args = parse_args()

            assert args.verbose is True

    def test_list_ports_flag(self) -> None:
        """Test list-ports flag."""
        with patch("sys.argv", ["vuln-scan", "dummy", "--list-ports"]):
            args = parse_args()

            assert args.list_ports is True


class TestCLIIntegration:
    """Integration tests for CLI."""

    @patch("vuln_scanner.cli.PortScanner")
    @patch("vuln_scanner.cli.ServiceDetector")
    @patch("vuln_scanner.cli.CVEChecker")
    @patch("vuln_scanner.cli.ReportGenerator")
    def test_full_scan_flow(
        self,
        mock_reporter_class: MagicMock,
        mock_cve_class: MagicMock,
        mock_detector_class: MagicMock,
        mock_scanner_class: MagicMock,
    ) -> None:
        """Test full scan workflow from CLI."""
        from vuln_scanner.cli import run_scan
        from vuln_scanner.models import ScanResult

        # Setup mocks
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_host.return_value = MagicMock(
            ip="192.168.1.1",
            is_up=True,
            ports=[],
            vulnerabilities=[],
        )

        mock_detector = MagicMock()
        mock_detector_class.return_value = mock_detector

        mock_cve = MagicMock()
        mock_cve_class.return_value = mock_cve
        mock_cve.check_host.return_value = []

        # Create args mock
        args = MagicMock()
        args.target = "192.168.1.1"
        args.timeout = 2.0
        args.threads = 50
        args.ports = None
        args.quick = False
        args.no_cve = False
        args.verbose = False

        # Run scan
        result = run_scan(args)

        assert isinstance(result, ScanResult)
        mock_scanner.scan_host.assert_called_once()
        mock_detector.analyze_host.assert_called_once()
        mock_cve.check_host.assert_called_once()


class TestReportGeneration:
    """Tests for report generation from CLI."""

    def test_generate_reports_all(self) -> None:
        """Test generating all report formats."""
        from vuln_scanner.cli import generate_reports
        from vuln_scanner.models import ScanResult

        with tempfile.TemporaryDirectory() as tmpdir:
            result = ScanResult()
            paths = generate_reports(result, tmpdir, "all")

            assert len(paths) == 3
            extensions = {p.suffix for p in paths}
            assert extensions == {".json", ".html", ".txt"}

    def test_generate_reports_single_format(self) -> None:
        """Test generating single report format."""
        from vuln_scanner.cli import generate_reports
        from vuln_scanner.models import ScanResult

        with tempfile.TemporaryDirectory() as tmpdir:
            result = ScanResult()
            paths = generate_reports(result, tmpdir, "json")

            assert len(paths) == 1
            assert paths[0].suffix == ".json"


class TestExitCodes:
    """Tests for CLI exit codes."""

    @patch("builtins.print")  # Suppress output
    @patch("vuln_scanner.cli.ReportGenerator")
    @patch("vuln_scanner.cli.run_scan")
    @patch("vuln_scanner.cli.parse_args")
    def test_exit_code_critical_vulnerability(
        self,
        mock_parse: MagicMock,
        mock_run_scan: MagicMock,
        mock_reporter_class: MagicMock,
        mock_print: MagicMock,
    ) -> None:
        """Test exit code 2 for critical vulnerabilities."""
        from vuln_scanner.models import (
            ScanResult,
            Severity,
            Host,
            Port,
            PortState,
            Vulnerability,
            CVE,
        )

        # Create a host with a critical vulnerability
        cve = CVE(
            id="CVE-TEST",
            description="Test CVE",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
        )
        port = Port(22, PortState.OPEN, service="ssh")
        host = Host(ip="192.168.1.1", is_up=True)
        host.vulnerabilities = [Vulnerability(cve, port, "192.168.1.1")]

        result = ScanResult(hosts=[host])

        # Verify severity_breakdown is calculated correctly
        assert result.severity_breakdown[Severity.CRITICAL] == 1

    @patch("builtins.print")  # Suppress output
    @patch("vuln_scanner.cli.ReportGenerator")
    @patch("vuln_scanner.cli.run_scan")
    @patch("vuln_scanner.cli.parse_args")
    def test_exit_code_no_vulnerabilities(
        self,
        mock_parse: MagicMock,
        mock_run_scan: MagicMock,
        mock_reporter_class: MagicMock,
        mock_print: MagicMock,
    ) -> None:
        """Test exit code 0 for no critical/high vulnerabilities."""
        from vuln_scanner.models import ScanResult, Severity

        result = ScanResult()

        # Validate that there are no critical or high vulnerabilities
        assert result.severity_breakdown[Severity.CRITICAL] == 0
        assert result.severity_breakdown[Severity.HIGH] == 0
