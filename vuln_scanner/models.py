"""Data models for the vulnerability scanner."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address
from typing import Any


class Severity(Enum):
    """Vulnerability severity levels based on CVSS."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_range(self) -> tuple[float, float]:
        """Return CVSS score range for this severity."""
        ranges = {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9),
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0),
        }
        return ranges[self]

    @property
    def color(self) -> str:
        """Return color code for terminal output."""
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }
        return colors[self]


class PortState(Enum):
    """TCP/UDP port states."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"


@dataclass
class Port:
    """Represents a scanned port."""

    number: int
    state: PortState
    protocol: str = "tcp"
    service: str | None = None
    version: str | None = None
    banner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "number": self.number,
            "state": self.state.value,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
        }


@dataclass
class CVE:
    """Represents a CVE vulnerability."""

    id: str
    description: str
    severity: Severity
    cvss_score: float
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_date: str | None = None
    patch_available: bool = False
    patch_info: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "affected_products": self.affected_products,
            "references": self.references,
            "published_date": self.published_date,
            "patch_available": self.patch_available,
            "patch_info": self.patch_info,
        }


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""

    cve: CVE
    port: Port
    host: str
    evidence: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cve": self.cve.to_dict(),
            "port": self.port.to_dict(),
            "host": self.host,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class Host:
    """Represents a scanned host."""

    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    os_type: str | None = None
    ports: list[Port] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    is_up: bool = False

    @property
    def ipv4(self) -> IPv4Address | None:
        """Return IPv4Address object if valid."""
        try:
            return IPv4Address(self.ip)
        except ValueError:
            return None

    @property
    def open_ports(self) -> list[Port]:
        """Return list of open ports."""
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Return count of vulnerabilities by severity."""
        counts = {s: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.cve.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "os_type": self.os_type,
            "is_up": self.is_up,
            "ports": [p.to_dict() for p in self.ports],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


@dataclass
class ScanResult:
    """Complete scan results."""

    hosts: list[Host] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    scan_type: str = "comprehensive"
    target_network: str | None = None

    @property
    def total_vulnerabilities(self) -> int:
        """Return total number of vulnerabilities."""
        return sum(len(h.vulnerabilities) for h in self.hosts)

    @property
    def severity_breakdown(self) -> dict[Severity, int]:
        """Return breakdown of vulnerabilities by severity."""
        counts = {s: 0 for s in Severity}
        for host in self.hosts:
            for vuln in host.vulnerabilities:
                counts[vuln.cve.severity] += 1
        return counts

    @property
    def live_hosts(self) -> list[Host]:
        """Return list of hosts that are up."""
        return [h for h in self.hosts if h.is_up]

    @property
    def hosts_with_vulnerabilities(self) -> list[Host]:
        """Return hosts that have vulnerabilities."""
        return [h for h in self.hosts if h.vulnerabilities]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "hosts": [h.to_dict() for h in self.hosts],
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "scan_type": self.scan_type,
            "target_network": self.target_network,
            "summary": {
                "total_hosts": len(self.hosts),
                "live_hosts": len(self.live_hosts),
                "total_vulnerabilities": self.total_vulnerabilities,
                "severity_breakdown": {
                    s.value: c for s, c in self.severity_breakdown.items()
                },
            },
        }
