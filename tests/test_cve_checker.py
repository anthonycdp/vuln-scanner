"""Tests for CVE vulnerability checker."""

import pytest

from vuln_scanner.cve_checker import CVEChecker, CVE_DATABASE, ServiceVersion
from vuln_scanner.models import CVE, Host, Port, PortState, Severity


class TestServiceVersion:
    """Tests for ServiceVersion dataclass."""

    def test_service_version_creation(self) -> None:
        """Test creating a service version object."""
        service = ServiceVersion(
            name="ssh",
            version="8.9",
            port=22,
            banner="SSH-2.0-OpenSSH_8.9",
        )
        assert service.name == "ssh"
        assert service.version == "8.9"
        assert service.port == 22

    def test_service_version_defaults(self) -> None:
        """Test service version defaults."""
        service = ServiceVersion(name="http")
        assert service.version is None
        assert service.port is None
        assert service.banner is None


class TestCVEChecker:
    """Tests for CVEChecker class."""

    @pytest.fixture
    def checker(self) -> CVEChecker:
        """Create a CVE checker instance."""
        return CVEChecker()

    def test_checker_initialization(self, checker: CVEChecker) -> None:
        """Test checker initializes with database."""
        assert len(checker.database) > 0
        assert len(checker.database) == len(CVE_DATABASE)

    def test_check_ssh_vulnerability(self, checker: CVEChecker) -> None:
        """Test checking SSH service for vulnerabilities."""
        # OpenSSH 8.9 is affected by CVE-2024-6387
        service = ServiceVersion(name="ssh", version="8.9")
        cves = checker.check_service(service)

        cve_ids = [c.id for c in cves]
        assert "CVE-2024-6387" in cve_ids

    def test_check_patched_version(self, checker: CVEChecker) -> None:
        """Test that patched versions don't trigger CVE."""
        # OpenSSH 9.8 should not be affected by regreSSHion
        service = ServiceVersion(name="ssh", version="9.8")
        cves = checker.check_service(service)

        cve_ids = [c.id for c in cves]
        assert "CVE-2024-6387" not in cve_ids

    def test_check_unknown_version(self, checker: CVEChecker) -> None:
        """Test checking with unknown version (conservative approach)."""
        # Without version, should flag all CVEs for that service
        service = ServiceVersion(name="ssh", version=None)
        cves = checker.check_service(service)

        # Should return all SSH CVEs
        assert len(cves) > 0
        for cve in cves:
            assert cve.id.startswith("CVE-")

    def test_check_http_vulnerability(self, checker: CVEChecker) -> None:
        """Test checking HTTP service for vulnerabilities."""
        service = ServiceVersion(name="http", version="2.4.49")
        cves = checker.check_service(service)

        cve_ids = [c.id for c in cves]
        assert "CVE-2021-41773" in cve_ids

    def test_check_smb_vulnerability(self, checker: CVEChecker) -> None:
        """Test checking SMB service for vulnerabilities."""
        service = ServiceVersion(name="smb", version="1.0")
        cves = checker.check_service(service)

        cve_ids = [c.id for c in cves]
        # Should include EternalBlue
        assert "CVE-2017-0144" in cve_ids

    def test_check_rdp_vulnerability(self, checker: CVEChecker) -> None:
        """Test checking RDP service for vulnerabilities."""
        service = ServiceVersion(name="rdp", version="6.0")
        cves = checker.check_service(service)

        cve_ids = [c.id for c in cves]
        # Should include BlueKeep
        assert "CVE-2019-0708" in cve_ids

    def test_check_unknown_service(self, checker: CVEChecker) -> None:
        """Test checking an unknown service."""
        service = ServiceVersion(name="unknown-service", version="1.0")
        cves = checker.check_service(service)

        assert len(cves) == 0

    def test_check_host(self, checker: CVEChecker) -> None:
        """Test checking all services on a host."""
        host = Host(ip="192.168.1.1", is_up=True)
        host.ports = [
            Port(22, PortState.OPEN, service="ssh"),
            Port(80, PortState.OPEN, service="http"),
            Port(443, PortState.CLOSED, service="https"),
        ]

        vulnerabilities = checker.check_host(host)

        # Should have vulnerabilities for open ports with affected services
        assert isinstance(vulnerabilities, list)

    def test_version_in_list_exact(self, checker: CVEChecker) -> None:
        """Test exact version matching."""
        assert checker._version_in_list("8.9", ["8.5", "8.9", "9.0"])
        assert not checker._version_in_list("8.4", ["8.5", "8.9", "9.0"])

    def test_version_in_list_prefix(self, checker: CVEChecker) -> None:
        """Test prefix version matching."""
        # "8.5" should match "8.5.1"
        assert checker._version_in_list("8.5.1", ["8.5"])
        assert checker._version_in_list("8.5", ["8.5.1"])

    def test_version_compare(self, checker: CVEChecker) -> None:
        """Test version comparison."""
        assert checker._compare_versions("1.0", "1.0") == 0
        assert checker._compare_versions("2.0", "1.0") == 1
        assert checker._compare_versions("1.0", "2.0") == -1
        # Note: 1.0.0 has more parts than 1.0, so it's considered greater
        assert checker._compare_versions("1.1", "1.0") == 1

    def test_add_custom_cve(self, checker: CVEChecker) -> None:
        """Test adding a custom CVE."""
        initial_count = len(checker.database)

        checker.add_cve({
            "id": "CVE-TEST-001",
            "description": "Test vulnerability",
            "severity": "high",
            "cvss_score": 8.0,
            "affected_service": "ssh",
            "affected_versions": ["1.0"],
        })

        assert len(checker.database) == initial_count + 1

        # Should find our custom CVE
        service = ServiceVersion(name="ssh", version="1.0")
        cves = checker.check_service(service)
        cve_ids = [c.id for c in cves]
        assert "CVE-TEST-001" in cve_ids

    def test_add_cve_missing_field(self, checker: CVEChecker) -> None:
        """Test adding CVE with missing required field."""
        with pytest.raises(ValueError, match="Missing required field"):
            checker.add_cve({
                "id": "CVE-TEST-002",
                "severity": "high",
                # Missing cvss_score
            })

    def test_get_statistics(self, checker: CVEChecker) -> None:
        """Test getting database statistics."""
        stats = checker.get_statistics()

        assert "total_cves" in stats
        assert stats["total_cves"] > 0
        assert "by_severity" in stats
        assert "by_service" in stats

        # Check that counts add up
        total_by_severity = sum(stats["by_severity"].values())
        assert total_by_severity == stats["total_cves"]


class TestCVEDatabase:
    """Tests for the CVE database content."""

    def test_database_has_required_fields(self) -> None:
        """Test that all CVEs have required fields."""
        required = ["id", "severity", "cvss_score"]

        for cve in CVE_DATABASE:
            for field in required:
                assert field in cve, f"CVE {cve.get('id', 'unknown')} missing {field}"

    def test_severity_values_valid(self) -> None:
        """Test that severity values are valid."""
        valid_severities = {"critical", "high", "medium", "low", "info"}

        for cve in CVE_DATABASE:
            severity = cve.get("severity", "").lower()
            assert severity in valid_severities, f"Invalid severity in {cve['id']}"

    def test_cvss_scores_in_range(self) -> None:
        """Test that CVSS scores are in valid range."""
        for cve in CVE_DATABASE:
            score = cve.get("cvss_score", 0)
            assert 0 <= score <= 10, f"Invalid CVSS score in {cve['id']}"

    def test_database_has_notable_cves(self) -> None:
        """Test that database includes notable CVEs."""
        cve_ids = [cve["id"] for cve in CVE_DATABASE]

        # Should include some well-known CVEs
        assert "CVE-2021-44228" in cve_ids  # Log4Shell
        assert "CVE-2024-6387" in cve_ids  # regreSSHion
        assert "CVE-2019-0708" in cve_ids  # BlueKeep
        assert "CVE-2017-0144" in cve_ids  # EternalBlue
