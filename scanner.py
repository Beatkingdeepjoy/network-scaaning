"""
NetSentry Scanner Module
-------------------------
Host discovery, port scanning, and service fingerprinting.

Two backends are supported:
  1. nmap (preferred) - via python-nmap, requires the nmap binary installed
  2. pure-python fallback - socket-based ping sweep + TCP connect scan,
     used automatically if the nmap binary is not found on the system.

This lets the project run and demo cleanly on any machine, even one
without nmap installed, while using nmap's full power when available.
"""

import socket
import subprocess
import threading
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import nmap
    NMAP_LIB_AVAILABLE = True
except ImportError:
    NMAP_LIB_AVAILABLE = False


# Common ports to check in the fast/default scan profile
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}


def nmap_binary_available() -> bool:
    """Check whether the actual nmap executable is on PATH."""
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, timeout=3)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


USE_NMAP = NMAP_LIB_AVAILABLE and nmap_binary_available()


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def _ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Pure-python liveness check via a quick TCP connect probe.

    We avoid raw ICMP sockets since those need root and aren't reliably
    available cross-platform. Connecting to common ports (or even a
    closed one) on a live host returns fast; a dead host times out.
    """
    # Try a couple of cheap signals: a common open port, then ICMP via system ping
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout)), ip] if _is_linux() else
            ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
            capture_output=True, timeout=timeout + 1
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass

    # Fallback: try connecting to a handful of common ports
    for port in (80, 443, 22, 445):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout / 2)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            continue
    return False


def _is_linux() -> bool:
    import platform
    return platform.system().lower() != "windows"


def _scan_port(ip: str, port: int, timeout: float = 0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port, SERVICE_NAMES.get(port, "unknown")
    except Exception:
        pass
    return None


def ping_sweep_fallback(subnet: str, max_workers: int = 64):
    """Pure-python liveness sweep across a CIDR range."""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    live_hosts = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(_ping_host, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    live_hosts.append(ip)
            except Exception:
                continue

    return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))


def port_scan_fallback(ip: str, ports=None, max_workers: int = 32):
    """Pure-python TCP connect scan for a single host."""
    ports = ports or COMMON_PORTS
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_scan_port, ip, p) for p in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append({"port": result[0], "service": result[1], "state": "open"})

    return sorted(open_ports, key=lambda x: x["port"])


def scan_with_nmap(subnet: str):
    """Full scan using nmap: host discovery + port scan + service/version detection."""
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments="-sn")  # ping scan for discovery
    live_ips = [h for h in nm.all_hosts() if nm[h].state() == "up"]

    results = []
    for ip in live_ips:
        host_result = {
            "ip": ip,
            "hostname": _resolve_hostname(ip),
            "status": "up",
            "ports": [],
            "scanned_at": datetime.utcnow().isoformat(),
        }
        try:
            port_range = ",".join(str(p) for p in COMMON_PORTS)
            nm.scan(ip, port_range, arguments="-sV")
            if ip in nm.all_hosts():
                tcp_data = nm[ip].get("tcp", {})
                for port, info in tcp_data.items():
                    if info.get("state") == "open":
                        host_result["ports"].append({
                            "port": port,
                            "service": info.get("name", "unknown") or SERVICE_NAMES.get(port, "unknown"),
                            "product": info.get("product", ""),
                            "version": info.get("version", ""),
                            "state": "open",
                        })
        except Exception as e:
            host_result["scan_error"] = str(e)

        results.append(host_result)

    return results


def scan_fallback(subnet: str):
    """Full scan using pure-python sweep + connect scan."""
    live_ips = ping_sweep_fallback(subnet)
    results = []
    for ip in live_ips:
        ports = port_scan_fallback(ip)
        results.append({
            "ip": ip,
            "hostname": _resolve_hostname(ip),
            "status": "up",
            "ports": ports,
            "scanned_at": datetime.utcnow().isoformat(),
        })
    return results


def run_scan(subnet: str):
    """Entry point: picks nmap or fallback engine automatically."""
    engine = "nmap" if USE_NMAP else "fallback"
    start = time.time()

    if USE_NMAP:
        hosts = scan_with_nmap(subnet)
    else:
        hosts = scan_fallback(subnet)

    return {
        "subnet": subnet,
        "engine": engine,
        "duration_seconds": round(time.time() - start, 2),
        "host_count": len(hosts),
        "hosts": hosts,
        "scanned_at": datetime.utcnow().isoformat(),
    }
