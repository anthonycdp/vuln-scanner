"""
CVE Vulnerability Checker

Checks detected services against known vulnerabilities.
Uses a local CVE database for air-gapped operation.

NOTE: This module uses a curated database of high-impact CVEs.
For comprehensive coverage, consider integrating with NVD API
or commercial vulnerability databases.
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vuln_scanner.models import CVE, Host, Port, Severity, Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class ServiceVersion:
    """Represents a detected service with version."""

    name: str
    version: str | None = None
    port: int | None = None
    banner: str | None = None


# Curated database of high-impact CVEs
# In production, this would be fetched from NVD or similar
CVE_DATABASE: list[dict[str, Any]] = [
    # SSH Vulnerabilities
    {
        "id": "CVE-2024-6387",
        "name": "regreSSHion",
        "description": "A signal handler race condition in OpenSSH's sshd allows remote code execution as root.",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_service": "ssh",
        "affected_versions": ["8.5", "8.6", "8.7", "8.8", "8.9", "9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "9.7"],
        "patch_versions": ["9.8", "8.9p1", "9.7p1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        "remediation": "Upgrade to OpenSSH 9.8 or apply patches from vendor.",
    },
    {
        "id": "CVE-2021-41617",
        "description": "Heap overflow in OpenSSH allows privilege escalation.",
        "severity": "high",
        "cvss_score": 7.0,
        "affected_service": "ssh",
        "affected_versions": ["5.7", "5.8", "6.0", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "7.9", "8.0", "8.1", "8.2", "8.3", "8.4"],
        "patch_versions": ["8.4p1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41617"],
        "remediation": "Upgrade OpenSSH to version 8.4p1 or later.",
    },
    # HTTP/Web Server Vulnerabilities
    {
        "id": "CVE-2021-41773",
        "description": "Path traversal vulnerability in Apache HTTP Server allows directory traversal.",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_service": "http",
        "affected_versions": ["2.4.49", "2.4.50"],
        "patch_versions": ["2.4.51"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        "remediation": "Upgrade Apache to version 2.4.51 or later.",
    },
    {
        "id": "CVE-2021-44228",
        "name": "Log4Shell",
        "description": "Remote code execution in Log4j via JNDI lookup mechanism.",
        "severity": "critical",
        "cvss_score": 10.0,
        "affected_service": "http",
        "affected_versions": ["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14", "2.15", "2.16", "2.17"],
        "patch_versions": ["2.17.1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "remediation": "Upgrade Log4j to version 2.17.1 or later.",
    },
    # SMB Vulnerabilities
    {
        "id": "CVE-2017-0144",
        "name": "EternalBlue",
        "description": "Remote code execution in SMBv1 via crafted packets.",
        "severity": "critical",
        "cvss_score": 9.3,
        "affected_service": "smb",
        "affected_versions": ["1.0"],
        "patch_versions": [],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        "remediation": "Disable SMBv1 and apply MS17-010 security update.",
    },
    {
        "id": "CVE-2020-0796",
        "name": "SMBGhost",
        "description": "Remote code execution in SMBv3 compression.",
        "severity": "critical",
        "cvss_score": 9.0,
        "affected_service": "smb",
        "affected_versions": ["3.0", "3.02", "3.11"],
        "patch_versions": [],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-0796"],
        "remediation": "Apply MS20-011 security update and disable SMB compression.",
    },
    # Database Vulnerabilities
    {
        "id": "CVE-2019-9193",
        "description": "Arbitrary code execution in PostgreSQL via COPY PROGRAM.",
        "severity": "high",
        "cvss_score": 8.8,
        "affected_service": "postgresql",
        "affected_versions": ["9.3", "10.0", "10.1", "10.2", "10.3", "10.4", "10.5", "11.0", "11.1", "11.2"],
        "patch_versions": ["11.3", "10.8"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9193"],
        "remediation": "Upgrade PostgreSQL and restrict COPY PROGRAM permissions.",
    },
    {
        "id": "CVE-2021-27928",
        "description": "SQL injection in MariaDB leads to code execution.",
        "severity": "high",
        "cvss_score": 8.8,
        "affected_service": "mysql",
        "affected_versions": ["10.2", "10.3", "10.4", "10.5"],
        "patch_versions": ["10.2.37", "10.3.28", "10.4.18", "10.5.9"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-27928"],
        "remediation": "Upgrade MariaDB to patched versions.",
    },
    # Redis Vulnerabilities
    {
        "id": "CVE-2022-0543",
        "description": "Lua sandbox escape in Redis leads to code execution.",
        "severity": "high",
        "cvss_score": 8.8,
        "affected_service": "redis",
        "affected_versions": ["2.8", "3.0", "4.0", "5.0", "6.0", "6.1", "6.2"],
        "patch_versions": ["6.2.6", "6.0.16"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"],
        "remediation": "Upgrade Redis to version 6.2.6 or later.",
    },
    # RDP Vulnerabilities
    {
        "id": "CVE-2019-0708",
        "name": "BlueKeep",
        "description": "Remote code execution in Remote Desktop Services via pre-authentication.",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_service": "rdp",
        "affected_versions": ["5.0", "5.1", "5.2", "6.0", "6.1", "7.0", "7.1", "8.0", "8.1", "10.0"],
        "patch_versions": [],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
        "remediation": "Apply MS19-058 security update and enable NLA.",
    },
    {
        "id": "CVE-2020-0609",
        "name": "BlueGate",
        "description": "Remote code execution in RD Gateway.",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_service": "rdp",
        "affected_versions": ["8.0", "8.1", "10.0"],
        "patch_versions": [],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-0609"],
        "remediation": "Apply MS20-006 security update.",
    },
    # VNC Vulnerabilities
    {
        "id": "CVE-2019-15681",
        "description": "Memory corruption in LibVNCServer.",
        "severity": "high",
        "cvss_score": 8.8,
        "affected_service": "vnc",
        "affected_versions": ["0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5", "0.9.6", "0.9.7", "0.9.8", "0.9.9", "0.9.10", "0.9.11", "0.9.12"],
        "patch_versions": ["0.9.13"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-15681"],
        "remediation": "Upgrade LibVNCServer to version 0.9.13 or later.",
    },
    # FTP Vulnerabilities
    {
        "id": "CVE-2021-35517",
        "description": "Integer overflow in Apache Commons Net FTP client.",
        "severity": "medium",
        "cvss_score": 6.5,
        "affected_service": "ftp",
        "affected_versions": ["3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8"],
        "patch_versions": ["3.8.0"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-35517"],
        "remediation": "Upgrade Apache Commons Net to version 3.8.0 or later.",
    },
    # SMTP Vulnerabilities
    {
        "id": "CVE-2020-28018",
        "description": "Heap buffer overflow in Exim SMTP server.",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_service": "smtp",
        "affected_versions": ["4.87", "4.88", "4.89", "4.90", "4.91", "4.92", "4.93", "4.94"],
        "patch_versions": ["4.94.1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-28018"],
        "remediation": "Upgrade Exim to version 4.94.1 or later.",
    },
    # MongoDB Vulnerabilities
    {
        "id": "CVE-2019-2386",
        "description": "Credential exposure in MongoDB diagnostic logs.",
        "severity": "medium",
        "cvss_score": 5.5,
        "affected_service": "mongodb",
        "affected_versions": ["3.6", "4.0", "4.1", "4.2"],
        "patch_versions": ["4.2.2"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-2386"],
        "remediation": "Upgrade MongoDB to version 4.2.2 or later.",
    },
]


class CVEChecker:
    """
    Checks detected services against known vulnerabilities.

    Uses a local CVE database for air-gapped operation.
    Can optionally fetch updates from NVD API.
    """

    def __init__(self, custom_db_path: Path | None = None) -> None:
        """Initialize CVE checker with optional custom database."""
        self.database = CVE_DATABASE.copy()
        if custom_db_path and custom_db_path.exists():
            self._load_custom_database(custom_db_path)

    def _load_custom_database(self, path: Path) -> None:
        """Load custom CVE database from JSON file."""
        try:
            with open(path, encoding="utf-8") as f:
                custom_cves = json.load(f)
                self.database.extend(custom_cves)
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Could not load custom CVE database: %s", e)

    def check_service(self, service: ServiceVersion) -> list[CVE]:
        """
        Check a service for known vulnerabilities.

        Args:
            service: Detected service with version info

        Returns:
            List of applicable CVEs
        """
        vulnerabilities: list[CVE] = []

        for cve_data in self.database:
            if self._is_affected(cve_data, service):
                cve = CVE(
                    id=cve_data["id"],
                    description=cve_data.get("description", "No description available"),
                    severity=Severity(cve_data.get("severity", "medium")),
                    cvss_score=cve_data.get("cvss_score", 0.0),
                    affected_products=cve_data.get("affected_products", []),
                    references=cve_data.get("references", []),
                    patch_available=bool(cve_data.get("patch_versions")),
                    patch_info=self._get_patch_info(cve_data),
                )
                vulnerabilities.append(cve)

        return vulnerabilities

    def _is_affected(self, cve_data: dict[str, Any], service: ServiceVersion) -> bool:
        """Check if a service is affected by a CVE."""
        # Check service match
        if cve_data.get("affected_service", "").lower() != service.name.lower():
            return False

        # If no version info, assume affected (conservative approach)
        if not service.version:
            return True

        # Check version
        affected_versions = cve_data.get("affected_versions", [])
        return self._version_in_list(service.version, affected_versions)

    def _version_in_list(self, version: str, version_list: list[str]) -> bool:
        """Check if a version matches any in the list."""
        version = version.strip()

        for affected in version_list:
            # Exact match
            if version == affected:
                return True

            # Prefix match (e.g., "8.5" matches "8.5.1")
            if version.startswith(affected + ".") or affected.startswith(version + "."):
                return True

            # Numeric comparison
            try:
                if self._compare_versions(version, affected) == 0:
                    return True
            except ValueError:
                continue

        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        parts1 = [int(p) for p in re.split(r"[.\-]", v1) if p.isdigit()]
        parts2 = [int(p) for p in re.split(r"[.\-]", v2) if p.isdigit()]

        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            if p1 > p2:
                return 1

        if len(parts1) < len(parts2):
            return -1
        if len(parts1) > len(parts2):
            return 1

        return 0

    def _get_patch_info(self, cve_data: dict[str, Any]) -> str | None:
        """Get patch information for a CVE."""
        patch_versions = cve_data.get("patch_versions", [])
        remediation = cve_data.get("remediation")

        if patch_versions:
            versions = ", ".join(patch_versions)
            return f"Patched versions: {versions}. {remediation or ''}"

        return remediation

    def check_host(self, host: Host) -> list[Vulnerability]:
        """
        Check all services on a host for vulnerabilities.

        Args:
            host: Host object with detected services

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        for port in host.open_ports:
            service = ServiceVersion(
                name=port.service or "unknown",
                version=port.version,
                port=port.number,
                banner=port.banner,
            )

            cves = self.check_service(service)

            for cve in cves:
                vuln = Vulnerability(
                    cve=cve,
                    port=port,
                    host=host.ip,
                    evidence=port.banner,
                    remediation=cve.patch_info,
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def add_cve(self, cve_data: dict[str, Any]) -> None:
        """Add a custom CVE to the database."""
        required_fields = ["id", "severity", "cvss_score"]
        for field in required_fields:
            if field not in cve_data:
                raise ValueError(f"Missing required field: {field}")

        self.database.append(cve_data)

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about the CVE database."""
        stats: dict[str, Any] = {
            "total_cves": len(self.database),
            "by_severity": {},
            "by_service": {},
        }

        for cve in self.database:
            severity = cve.get("severity", "unknown")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            service = cve.get("affected_service", "unknown")
            stats["by_service"][service] = stats["by_service"].get(service, 0) + 1

        return stats
