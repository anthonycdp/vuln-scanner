"""
Network Scanner Module

Provides port scanning and service detection capabilities using scapy.
Implements various scan types for comprehensive network analysis.

IMPORTANT: Only use on networks you own or have explicit permission to test.
"""

import re
import socket
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Callable

from scapy.all import ARP, ICMP, IP, TCP, sr, sr1, srp

from vuln_scanner.models import Host, Port, PortState

# Constants
SCAN_BATCH_SIZE = 20
BANNER_TIMEOUT_SECONDS = 3.0
BANNER_INITIAL_TIMEOUT_SECONDS = 2.0
BANNER_MAX_LENGTH = 100

# HTTP ports that should receive an HTTP request
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9000, 9090}


@dataclass
class ScanConfig:
    """Configuration for network scans."""

    timeout: float = 2.0
    retries: int = 2
    threads: int = 50
    common_ports: list[int] | None = None

    def __post_init__(self) -> None:
        if self.common_ports is None:
            self.common_ports = self._get_default_ports()

    @staticmethod
    def _get_default_ports() -> list[int]:
        """Return top 50 most common ports."""
        return [
            20, 21, 22, 23, 25, 26, 53, 67, 68, 69,
            80, 81, 110, 111, 113, 119, 123, 135, 137, 138,
            139, 143, 161, 389, 443, 445, 465, 514, 515, 587,
            636, 993, 995, 1080, 1433, 1434, 1723, 3306, 3389,
            5432, 5900, 5901, 5902, 5985, 5986, 6379, 8080, 8443,
            8888, 9000, 9090, 27017,
        ]


class PortScanner:
    """
    TCP/UDP port scanner using scapy for packet manipulation.

    Supports multiple scan types:
    - TCP SYN (stealth) scan
    - TCP Connect scan
    - UDP scan
    """

    # Well-known service mappings
    SERVICE_MAP: dict[int, str] = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        69: "tftp",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        113: "ident",
        119: "nntp",
        123: "ntp",
        135: "msrpc",
        137: "netbios-ns",
        138: "netbios-dgm",
        139: "netbios-ssn",
        143: "imap",
        161: "snmp",
        389: "ldap",
        443: "https",
        445: "smb",
        465: "smtps",
        514: "shell",
        515: "printer",
        587: "smtp",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1080: "socks",
        1433: "mssql",
        1434: "ms-sql-m",
        1723: "pptp",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        5985: "wsman",
        5986: "wsmans",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        27017: "mongodb",
    }

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self._progress_callback: Callable[[str], None] | None = None

    def set_progress_callback(self, callback: Callable[[str], None]) -> None:
        """Set callback for progress updates."""
        self._progress_callback = callback

    def _report_progress(self, message: str) -> None:
        """Report progress if callback is set."""
        if self._progress_callback:
            self._progress_callback(message)

    def scan_host(self, host_ip: str, ports: list[int] | None = None) -> Host:
        """
        Scan a single host for open ports.

        Args:
            host_ip: IP address to scan
            ports: List of ports to scan (uses common_ports if None)

        Returns:
            Host object with scan results
        """
        ports = ports or self.config.common_ports or []
        host = Host(ip=host_ip)

        # Check if host is up first
        if not self._is_host_up(host_ip):
            self._report_progress(f"Host {host_ip} is not responding")
            return host

        host.is_up = True
        self._report_progress(f"Scanning {host_ip}...")

        # Perform SYN scan
        open_ports = self._syn_scan(host_ip, ports)

        # Create Port objects
        for port_num in ports:
            if port_num in open_ports:
                port = Port(
                    number=port_num,
                    state=PortState.OPEN,
                    protocol="tcp",
                    service=self.SERVICE_MAP.get(port_num, "unknown"),
                )
                # Try to grab banner
                port.banner = self._grab_banner(host_ip, port_num)
                host.ports.append(port)
            # Only report open ports in results

        return host

    def _is_host_up(self, host_ip: str) -> bool:
        """Check if a host is up using ICMP ping."""
        try:
            # Try ICMP echo request
            pkt = IP(dst=host_ip) / ICMP()
            resp = sr1(pkt, timeout=self.config.timeout, verbose=0)
            return resp is not None
        except Exception:
            # Try ARP for local networks
            try:
                arp_pkt = ARP(pdst=host_ip)
                result = srp(arp_pkt, timeout=self.config.timeout, verbose=0)
                return len(result[0]) > 0
            except Exception:
                return False

    def _syn_scan(self, host_ip: str, ports: list[int]) -> set[int]:
        """
        Perform TCP SYN (stealth) scan.

        Sends SYN packets and analyzes responses:
        - SYN-ACK = port open
        - RST = port closed
        - No response = filtered
        """
        open_ports: set[int] = set()

        for i in range(0, len(ports), SCAN_BATCH_SIZE):
            batch = ports[i : i + SCAN_BATCH_SIZE]
            pkts = [IP(dst=host_ip) / TCP(dport=p, flags="S") for p in batch]

            try:
                ans, _ = sr(pkts, timeout=self.config.timeout, verbose=0)
                open_ports.update(self._process_scan_responses(ans, host_ip))
            except Exception as e:
                self._report_progress(f"Error scanning batch: {e}")

        return open_ports

    def _process_scan_responses(self, responses, host_ip: str) -> set[int]:
        """Process scan responses and return open ports."""
        open_ports: set[int] = set()
        SYN_ACK_FLAG = 0x12

        for sent, received in responses:
            if received.haslayer(TCP):
                flags = received[TCP].flags
                if flags == SYN_ACK_FLAG:
                    open_ports.add(sent[TCP].dport)
                    self._send_reset_packet(host_ip, sent, received)

        return open_ports

    def _send_reset_packet(self, host_ip: str, sent, received) -> None:
        """Send RST packet to close connection (stealth scan)."""
        rst = IP(dst=host_ip) / TCP(
            dport=sent[TCP].dport,
            sport=received[TCP].sport,
            flags="R",
        )
        sr1(rst, timeout=0.5, verbose=0)

    def _grab_banner(self, host_ip: str, port: int, timeout: float = BANNER_TIMEOUT_SECONDS) -> str | None:
        """
        Attempt to grab service banner.

        Uses a service-appropriate approach:
        - For HTTP ports: sends HEAD request
        - For other ports: connects and reads initial banner bytes

        Returns banner string or None if unsuccessful.
        """
        try:
            sock = self._create_socket_connection(host_ip, port, timeout)
            if sock is None:
                return None

            banner = self._retrieve_banner(sock, port, timeout)
            sock.close()
            return self._truncate_banner(banner)
        except Exception:
            return None

    def _create_socket_connection(self, host_ip: str, port: int, timeout: float):
        """Create and return a socket connection."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host_ip, port))
        return sock

    def _retrieve_banner(self, sock, port: int, timeout: float) -> str | None:
        """Retrieve banner from socket based on port type."""
        if port in HTTP_PORTS:
            return self._get_http_banner(sock)
        return self._get_service_banner(sock, timeout)

    def _get_http_banner(self, sock) -> str | None:
        """Get banner from HTTP service."""
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        return sock.recv(1024).decode("utf-8", errors="ignore").strip()

    def _get_service_banner(self, sock, timeout: float) -> str | None:
        """Get banner from non-HTTP service."""
        try:
            sock.settimeout(min(timeout, BANNER_INITIAL_TIMEOUT_SECONDS))
            initial_data = sock.recv(1024)
            if initial_data:
                return initial_data.decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            sock.settimeout(timeout)
            sock.send(b"\r\n")
            return sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            return None

    @staticmethod
    def _truncate_banner(banner: str | None) -> str | None:
        """Truncate banner to first line and max length."""
        if not banner:
            return None
        first_line = banner.split("\n")[0]
        return first_line[:BANNER_MAX_LENGTH] if first_line else None

    def scan_network(
        self, network: str, ports: list[int] | None = None
    ) -> list[Host]:
        """
        Scan all hosts in a network range.

        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            ports: List of ports to scan

        Returns:
            List of Host objects
        """
        hosts: list[Host] = []
        try:
            net = IPv4Network(network, strict=False)
            host_ips = [str(ip) for ip in net.hosts()]

            self._report_progress(f"Discovering hosts in {network}...")

            # First, discover live hosts
            live_hosts = self._discover_hosts(host_ips)
            self._report_progress(f"Found {len(live_hosts)} live hosts")

            # Scan each live host
            for host_ip in live_hosts:
                host = self.scan_host(host_ip, ports)
                hosts.append(host)

        except Exception as e:
            self._report_progress(f"Error scanning network: {e}")

        return hosts

    def _discover_hosts(self, host_ips: list[str]) -> list[str]:
        """Discover live hosts using ARP ping for local networks."""
        live_hosts: list[str] = []

        # Use ARP ping for efficiency on local networks
        try:
            pkts = [ARP(pdst=ip) for ip in host_ips]
            ans, _ = srp(pkts, timeout=self.config.timeout, verbose=0)

            for _, received in ans:
                live_hosts.append(received.psrc)

        except Exception:
            # Fallback to ICMP
            for ip in host_ips:
                if self._is_host_up(ip):
                    live_hosts.append(ip)

        return live_hosts


class ServiceDetector:
    """
    Service and version detection module.

    Analyzes banners and responses to identify services and versions.
    """

    # Service signature patterns
    SIGNATURES: dict[str, list[str]] = {
        "ssh": ["SSH-", "OpenSSH", "dropbear"],
        "http": ["HTTP/", "Server:", "Apache", "nginx", "Microsoft-IIS"],
        "ftp": ["FTP", "vsftpd", "ProFTPD", "FileZilla"],
        "smtp": ["SMTP", "ESMTP", "Postfix", "Exim", "Sendmail"],
        "mysql": ["MySQL", "MariaDB", "mysql"],
        "postgresql": ["PostgreSQL"],
        "redis": ["Redis"],
        "mongodb": ["MongoDB"],
        "smb": ["SMB", "Windows", "Samba"],
        "rdp": ["Remote Desktop", "Terminal Server"],
        "vnc": ["RFB ", "VNC"],
    }

    def detect_service(self, port: Port) -> tuple[str, str | None]:
        """
        Detect service and version from port information.

        Args:
            port: Port object with banner

        Returns:
            Tuple of (service_name, version_string)
        """
        if not port.banner:
            return port.service or "unknown", None

        banner = port.banner.lower()

        # Check signatures
        for service, patterns in self.SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in banner:
                    version = self._extract_version(banner, pattern)
                    return service, version

        return port.service or "unknown", None

    VERSION_PATTERNS = [
        r"(\d+\.\d+\.\d+)",  # x.y.z
        r"(\d+\.\d+)",  # x.y
    ]

    def _extract_version(self, banner: str, pattern: str) -> str | None:
        """Extract version number from banner."""
        for vpat in self.VERSION_PATTERNS:
            match = re.search(vpat, banner)
            if match:
                return match.group(1)
        return None

    def analyze_host(self, host: Host) -> None:
        """Analyze all ports on a host and update service info."""
        for port in host.ports:
            service, version = self.detect_service(port)
            port.service = service
            port.version = version
