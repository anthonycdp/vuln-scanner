"""Tests for network scanner module."""

import pytest
from unittest.mock import MagicMock, patch

from vuln_scanner.scanner import PortScanner, ScanConfig, ServiceDetector
from vuln_scanner.models import Host, Port, PortState


class TestScanConfig:
    """Tests for ScanConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ScanConfig()

        assert config.timeout == 2.0
        assert config.retries == 2
        assert config.threads == 50
        assert config.common_ports is not None
        assert 22 in config.common_ports  # SSH
        assert 80 in config.common_ports  # HTTP
        assert 443 in config.common_ports  # HTTPS

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = ScanConfig(
            timeout=5.0,
            retries=3,
            threads=100,
            common_ports=[22, 80, 443],
        )

        assert config.timeout == 5.0
        assert config.retries == 3
        assert config.threads == 100
        assert len(config.common_ports) == 3


class TestPortScanner:
    """Tests for PortScanner class."""

    @pytest.fixture
    def scanner(self) -> PortScanner:
        """Create a scanner instance."""
        return PortScanner()

    def test_initialization(self, scanner: PortScanner) -> None:
        """Test scanner initialization."""
        assert scanner.config is not None
        assert scanner.config.timeout == 2.0

    def test_service_map(self, scanner: PortScanner) -> None:
        """Test service map contains common ports."""
        assert scanner.SERVICE_MAP[22] == "ssh"
        assert scanner.SERVICE_MAP[80] == "http"
        assert scanner.SERVICE_MAP[443] == "https"
        assert scanner.SERVICE_MAP[3306] == "mysql"
        assert scanner.SERVICE_MAP[5432] == "postgresql"

    def test_progress_callback(self, scanner: PortScanner) -> None:
        """Test progress callback functionality."""
        messages: list[str] = []

        def callback(msg: str) -> None:
            messages.append(msg)

        scanner.set_progress_callback(callback)
        scanner._report_progress("Test message")

        assert len(messages) == 1
        assert messages[0] == "Test message"

    def test_no_progress_callback(self, scanner: PortScanner) -> None:
        """Test that missing callback doesn't cause errors."""
        scanner._report_progress("Test message")  # Should not raise

    @patch("vuln_scanner.scanner.sr1")
    def test_is_host_up_icmp_success(self, mock_sr1: MagicMock, scanner: PortScanner) -> None:
        """Test host detection with successful ICMP."""
        mock_sr1.return_value = MagicMock()  # Simulate response

        result = scanner._is_host_up("192.168.1.1")
        assert result is True

    @patch("vuln_scanner.scanner.sr1")
    def test_is_host_up_icmp_failure(self, mock_sr1: MagicMock, scanner: PortScanner) -> None:
        """Test host detection with failed ICMP."""
        mock_sr1.return_value = None  # No response

        result = scanner._is_host_up("192.168.1.1")
        assert result is False

    @patch("vuln_scanner.scanner.PortScanner._is_host_up")
    @patch("vuln_scanner.scanner.PortScanner._syn_scan")
    def test_scan_host_down(
        self, mock_syn_scan: MagicMock, mock_is_up: MagicMock, scanner: PortScanner
    ) -> None:
        """Test scanning a host that's down."""
        mock_is_up.return_value = False

        host = scanner.scan_host("192.168.1.1")

        assert host.ip == "192.168.1.1"
        assert host.is_up is False
        assert len(host.ports) == 0
        mock_syn_scan.assert_not_called()

    @patch("vuln_scanner.scanner.socket.socket")
    def test_grab_banner_success(self, mock_socket_class: MagicMock, scanner: PortScanner) -> None:
        """Test banner grabbing with successful response."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_socket_class.return_value = mock_sock

        banner = scanner._grab_banner("192.168.1.1", 22)

        # Should return banner content
        assert banner is not None
        assert "SSH" in banner

    @patch("vuln_scanner.scanner.socket.socket")
    def test_grab_banner_failure(self, mock_socket_class: MagicMock, scanner: PortScanner) -> None:
        """Test banner grabbing with connection failure."""
        mock_socket_class.side_effect = Exception("Connection refused")

        banner = scanner._grab_banner("192.168.1.1", 22)

        assert banner is None

    def test_custom_ports(self, scanner: PortScanner) -> None:
        """Test scanning with custom port list."""
        custom_ports = [22, 80, 8080]

        with patch.object(scanner, "_is_host_up", return_value=False):
            host = scanner.scan_host("192.168.1.1", ports=custom_ports)

            # Scanner should use provided ports
            assert host.ip == "192.168.1.1"


class TestServiceDetector:
    """Tests for ServiceDetector class."""

    @pytest.fixture
    def detector(self) -> ServiceDetector:
        """Create a service detector instance."""
        return ServiceDetector()

    def test_initialization(self, detector: ServiceDetector) -> None:
        """Test detector initialization."""
        assert "ssh" in detector.SIGNATURES
        assert "http" in detector.SIGNATURES

    def test_detect_ssh_service(self, detector: ServiceDetector) -> None:
        """Test SSH service detection."""
        port = Port(
            number=22,
            state=PortState.OPEN,
            banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
        )

        service, version = detector.detect_service(port)

        assert service == "ssh"
        assert version is not None

    def test_detect_http_service(self, detector: ServiceDetector) -> None:
        """Test HTTP service detection."""
        port = Port(
            number=80,
            state=PortState.OPEN,
            banner="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
        )

        service, version = detector.detect_service(port)

        assert service == "http"

    def test_detect_unknown_service(self, detector: ServiceDetector) -> None:
        """Test detection with unknown banner."""
        port = Port(
            number=12345,
            state=PortState.OPEN,
            banner="Some custom service v1.0",
        )

        service, version = detector.detect_service(port)

        # Should fall back to port's service or unknown
        assert service in ["unknown", "http-proxy"]

    def test_detect_no_banner(self, detector: ServiceDetector) -> None:
        """Test detection with no banner."""
        port = Port(number=22, state=PortState.OPEN, service="ssh")

        service, version = detector.detect_service(port)

        # Should return the existing service
        assert service == "ssh"

    def test_analyze_host(self, detector: ServiceDetector) -> None:
        """Test analyzing all ports on a host."""
        host = Host(ip="192.168.1.1", is_up=True)
        host.ports = [
            Port(22, PortState.OPEN, "tcp", "ssh", banner="SSH-2.0-OpenSSH_8.9"),
            Port(80, PortState.OPEN, "tcp", "http", banner="HTTP/1.1 200 OK"),
        ]

        detector.analyze_host(host)

        # Services should be detected and updated
        assert host.ports[0].service == "ssh"
        assert host.ports[1].service == "http"

    def test_version_extraction(self, detector: ServiceDetector) -> None:
        """Test version extraction from banners."""
        # Test x.y.z pattern
        version = detector._extract_version(
            "openssh-8.9.1", "openssh"
        )
        assert version is not None
        assert "8.9" in version

        # Test x.y pattern
        version = detector._extract_version(
            "nginx/1.18", "nginx"
        )
        assert version is not None


class TestPortState:
    """Tests for PortState enum."""

    def test_port_states(self) -> None:
        """Test port state values."""
        assert PortState.OPEN.value == "open"
        assert PortState.CLOSED.value == "closed"
        assert PortState.FILTERED.value == "filtered"


class TestHostScanning:
    """Integration tests for host scanning."""

    @pytest.fixture
    def scanner(self) -> PortScanner:
        """Create a scanner with quick config."""
        config = ScanConfig(
            timeout=1.0,
            common_ports=[22, 80],
        )
        return PortScanner(config)

    def test_scan_result_structure(self, scanner: PortScanner) -> None:
        """Test that scan result has correct structure."""
        with patch.object(scanner, "_is_host_up", return_value=False):
            host = scanner.scan_host("192.168.1.1")

            assert hasattr(host, "ip")
            assert hasattr(host, "ports")
            assert hasattr(host, "vulnerabilities")
            assert hasattr(host, "is_up")
            assert isinstance(host.ports, list)
            assert isinstance(host.vulnerabilities, list)


class TestNetworkScanning:
    """Tests for network-wide scanning."""

    @pytest.fixture
    def scanner(self) -> PortScanner:
        """Create a scanner for network tests."""
        config = ScanConfig(common_ports=[22])
        return PortScanner(config)

    @patch("vuln_scanner.scanner.PortScanner._discover_hosts")
    @patch("vuln_scanner.scanner.PortScanner.scan_host")
    def test_scan_network(
        self, mock_scan_host: MagicMock, mock_discover: MagicMock, scanner: PortScanner
    ) -> None:
        """Test network scanning."""
        mock_discover.return_value = ["192.168.1.1", "192.168.1.2"]
        mock_scan_host.side_effect = lambda ip, _: Host(ip=ip, is_up=True)

        hosts = scanner.scan_network("192.168.1.0/30")

        assert len(hosts) == 2
        mock_scan_host.assert_any_call("192.168.1.1", None)
        mock_scan_host.assert_any_call("192.168.1.2", None)

    def test_scan_invalid_network(self, scanner: PortScanner) -> None:
        """Test scanning with invalid network."""
        # Should not raise, just return empty or handle gracefully
        with patch.object(scanner, "_discover_hosts", return_value=[]):
            hosts = scanner.scan_network("invalid-network")
            assert len(hosts) == 0
