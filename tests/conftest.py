"""Pytest configuration and fixtures."""

import pytest
import tempfile
from pathlib import Path

from vuln_scanner.models import (
    CVE,
    Host,
    Port,
    PortState,
    ScanResult,
    Severity,
    Vulnerability,
)
from vuln_scanner.cve_checker import CVEChecker, ServiceVersion
from vuln_scanner.reporter import ReportGenerator


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_cve():
    """Create a sample CVE for testing."""
    return CVE(
        id="CVE-TEST-001",
        description="Test vulnerability for unit testing",
        severity=Severity.HIGH,
        cvss_score=7.5,
        affected_products=["TestProduct"],
        references=["https://example.com/cve"],
        patch_available=True,
        patch_info="Upgrade to version 2.0",
    )


@pytest.fixture
def sample_cve_critical():
    """Create a critical severity CVE for testing."""
    return CVE(
        id="CVE-TEST-CRITICAL",
        description="Critical test vulnerability",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        affected_products=["CriticalProduct"],
        patch_available=True,
        patch_info="Patch immediately",
    )


@pytest.fixture
def sample_port():
    """Create a sample open port for testing."""
    return Port(
        number=22,
        state=PortState.OPEN,
        protocol="tcp",
        service="ssh",
        version="8.9",
        banner="SSH-2.0-OpenSSH_8.9",
    )


@pytest.fixture
def sample_host(sample_port):
    """Create a sample host with ports for testing."""
    host = Host(
        ip="192.168.1.100",
        hostname="test-host.local",
        is_up=True,
    )
    host.ports = [
        sample_port,
        Port(80, PortState.OPEN, "tcp", "http"),
    ]
    return host


@pytest.fixture
def sample_host_with_vulns(sample_host, sample_cve, sample_port):
    """Create a sample host with vulnerabilities."""
    sample_host.vulnerabilities = [
        Vulnerability(sample_cve, sample_port, "192.168.1.100")
    ]
    return sample_host


@pytest.fixture
def sample_scan_result(sample_host_with_vulns):
    """Create a sample scan result for testing."""
    result = ScanResult(
        scan_type="comprehensive",
        target_network="192.168.1.0/24",
    )
    result.hosts = [sample_host_with_vulns]
    return result


@pytest.fixture
def cve_checker():
    """Create a CVE checker instance."""
    return CVEChecker()


@pytest.fixture
def reporter(temp_dir):
    """Create a report generator with temp directory."""
    return ReportGenerator(temp_dir)


@pytest.fixture
def sample_service_version():
    """Create a sample service version for testing."""
    return ServiceVersion(
        name="ssh",
        version="8.9",
        port=22,
        banner="SSH-2.0-OpenSSH_8.9",
    )
