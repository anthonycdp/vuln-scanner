"""Tests for data models."""

import pytest
from datetime import datetime

from vuln_scanner.models import (
    CVE,
    Host,
    Port,
    PortState,
    ScanResult,
    Severity,
    Vulnerability,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self) -> None:
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_score_range(self) -> None:
        """Test CVSS score ranges for each severity."""
        assert Severity.CRITICAL.score_range == (9.0, 10.0)
        assert Severity.HIGH.score_range == (7.0, 8.9)
        assert Severity.MEDIUM.score_range == (4.0, 6.9)
        assert Severity.LOW.score_range == (0.1, 3.9)

    def test_severity_colors(self) -> None:
        """Test color codes for terminal output."""
        assert Severity.CRITICAL.color == "bold red"
        assert Severity.HIGH.color == "red"
        assert Severity.MEDIUM.color == "yellow"
        assert Severity.LOW.color == "blue"


class TestPort:
    """Tests for Port dataclass."""

    def test_port_creation(self) -> None:
        """Test creating a port object."""
        port = Port(number=22, state=PortState.OPEN, protocol="tcp", service="ssh")
        assert port.number == 22
        assert port.state == PortState.OPEN
        assert port.protocol == "tcp"
        assert port.service == "ssh"

    def test_port_to_dict(self) -> None:
        """Test port serialization."""
        port = Port(
            number=80,
            state=PortState.OPEN,
            protocol="tcp",
            service="http",
            version="nginx/1.18.0",
            banner="HTTP/1.1 200 OK",
        )
        result = port.to_dict()

        assert result["number"] == 80
        assert result["state"] == "open"
        assert result["protocol"] == "tcp"
        assert result["service"] == "http"
        assert result["version"] == "nginx/1.18.0"
        assert result["banner"] == "HTTP/1.1 200 OK"

    def test_port_defaults(self) -> None:
        """Test port default values."""
        port = Port(number=443, state=PortState.CLOSED)
        assert port.protocol == "tcp"
        assert port.service is None
        assert port.version is None
        assert port.banner is None


class TestCVE:
    """Tests for CVE dataclass."""

    def test_cve_creation(self) -> None:
        """Test creating a CVE object."""
        cve = CVE(
            id="CVE-2024-6387",
            description="SSH vulnerability",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
        )
        assert cve.id == "CVE-2024-6387"
        assert cve.severity == Severity.CRITICAL
        assert cve.cvss_score == 9.8

    def test_cve_to_dict(self) -> None:
        """Test CVE serialization."""
        cve = CVE(
            id="CVE-2021-44228",
            description="Log4Shell vulnerability",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            affected_products=["Apache Log4j"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            patch_available=True,
            patch_info="Upgrade to Log4j 2.17.1",
        )
        result = cve.to_dict()

        assert result["id"] == "CVE-2021-44228"
        assert result["severity"] == "critical"
        assert result["cvss_score"] == 10.0
        assert result["patch_available"] is True

    def test_cve_defaults(self) -> None:
        """Test CVE default values."""
        cve = CVE(
            id="CVE-TEST",
            description="Test CVE",
            severity=Severity.LOW,
            cvss_score=3.0,
        )
        assert cve.affected_products == []
        assert cve.references == []
        assert cve.patch_available is False


class TestHost:
    """Tests for Host dataclass."""

    def test_host_creation(self) -> None:
        """Test creating a host object."""
        host = Host(ip="192.168.1.1", hostname="router.local", is_up=True)
        assert host.ip == "192.168.1.1"
        assert host.hostname == "router.local"
        assert host.is_up is True

    def test_host_open_ports(self) -> None:
        """Test open_ports property."""
        host = Host(ip="192.168.1.1", is_up=True)
        host.ports = [
            Port(22, PortState.OPEN),
            Port(80, PortState.OPEN),
            Port(443, PortState.CLOSED),
            Port(8080, PortState.FILTERED),
        ]

        open_ports = host.open_ports
        assert len(open_ports) == 2
        assert all(p.state == PortState.OPEN for p in open_ports)

    def test_host_ipv4(self) -> None:
        """Test IPv4Address conversion."""
        host = Host(ip="192.168.1.1")
        assert host.ipv4 is not None
        assert str(host.ipv4) == "192.168.1.1"

        invalid_host = Host(ip="invalid-ip")
        assert invalid_host.ipv4 is None

    def test_host_severity_counts(self) -> None:
        """Test severity_counts property."""
        host = Host(ip="192.168.1.1")
        cve_critical = CVE("CVE-1", "Critical", Severity.CRITICAL, 9.5)
        cve_high = CVE("CVE-2", "High", Severity.HIGH, 7.5)
        cve_high2 = CVE("CVE-3", "High 2", Severity.HIGH, 8.0)

        port = Port(22, PortState.OPEN, service="ssh")
        host.vulnerabilities = [
            Vulnerability(cve_critical, port, "192.168.1.1"),
            Vulnerability(cve_high, port, "192.168.1.1"),
            Vulnerability(cve_high2, port, "192.168.1.1"),
        ]

        counts = host.severity_counts
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.MEDIUM] == 0

    def test_host_to_dict(self) -> None:
        """Test host serialization."""
        host = Host(
            ip="192.168.1.1",
            hostname="test.local",
            os_type="Linux",
            is_up=True,
        )
        host.ports = [Port(22, PortState.OPEN, service="ssh")]

        result = host.to_dict()
        assert result["ip"] == "192.168.1.1"
        assert result["hostname"] == "test.local"
        assert result["os_type"] == "Linux"
        assert len(result["ports"]) == 1


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_creation(self) -> None:
        """Test creating a scan result."""
        result = ScanResult(scan_type="comprehensive", target_network="192.168.1.0/24")
        assert result.scan_type == "comprehensive"
        assert result.target_network == "192.168.1.0/24"
        assert result.end_time is None

    def test_total_vulnerabilities(self) -> None:
        """Test total_vulnerabilities property."""
        result = ScanResult()
        host1 = Host(ip="192.168.1.1")
        host2 = Host(ip="192.168.1.2")
        port = Port(22, PortState.OPEN)
        cve = CVE("CVE-1", "Test", Severity.HIGH, 7.5)

        host1.vulnerabilities = [Vulnerability(cve, port, "192.168.1.1")]
        host2.vulnerabilities = [
            Vulnerability(cve, port, "192.168.1.2"),
            Vulnerability(cve, port, "192.168.1.2"),
        ]
        result.hosts = [host1, host2]

        assert result.total_vulnerabilities == 3

    def test_severity_breakdown(self) -> None:
        """Test severity_breakdown property."""
        result = ScanResult()
        host = Host(ip="192.168.1.1")
        port = Port(22, PortState.OPEN)

        cve_critical = CVE("CVE-1", "Critical", Severity.CRITICAL, 9.5)
        cve_medium = CVE("CVE-2", "Medium", Severity.MEDIUM, 5.0)

        host.vulnerabilities = [
            Vulnerability(cve_critical, port, "192.168.1.1"),
            Vulnerability(cve_medium, port, "192.168.1.1"),
            Vulnerability(cve_medium, port, "192.168.1.1"),
        ]
        result.hosts = [host]

        breakdown = result.severity_breakdown
        assert breakdown[Severity.CRITICAL] == 1
        assert breakdown[Severity.MEDIUM] == 2

    def test_live_hosts(self) -> None:
        """Test live_hosts property."""
        result = ScanResult()
        result.hosts = [
            Host(ip="192.168.1.1", is_up=True),
            Host(ip="192.168.1.2", is_up=False),
            Host(ip="192.168.1.3", is_up=True),
        ]

        live = result.live_hosts
        assert len(live) == 2
        assert all(h.is_up for h in live)

    def test_hosts_with_vulnerabilities(self) -> None:
        """Test hosts_with_vulnerabilities property."""
        result = ScanResult()
        host1 = Host(ip="192.168.1.1")
        host2 = Host(ip="192.168.1.2")
        cve = CVE("CVE-1", "Test", Severity.HIGH, 7.5)
        port = Port(22, PortState.OPEN)

        host1.vulnerabilities = [Vulnerability(cve, port, "192.168.1.1")]
        result.hosts = [host1, host2]

        vuln_hosts = result.hosts_with_vulnerabilities
        assert len(vuln_hosts) == 1
        assert vuln_hosts[0].ip == "192.168.1.1"

    def test_scan_result_to_dict(self) -> None:
        """Test scan result serialization."""
        result = ScanResult(
            scan_type="quick",
            target_network="192.168.1.0/24",
        )
        result.end_time = datetime.now()
        result.hosts = [Host(ip="192.168.1.1", is_up=True)]

        data = result.to_dict()
        assert data["scan_type"] == "quick"
        assert data["target_network"] == "192.168.1.0/24"
        assert "summary" in data
        assert data["summary"]["total_hosts"] == 1
