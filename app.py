import ipaddress
import csv
import re
import io
import socket
import subprocess
import threading
from datetime import datetime
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

import psutil
from flask import Flask, Response, jsonify, render_template

app = Flask(__name__)
scan_lock = threading.Lock()

IGNORED_IFACE_PREFIXES = (
    "lo",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "zt",
    "tailscale",
)

ZERO_MAC = "00:00:00:00:00:00"

OUI_VENDOR_HINTS = {
    # Common camera vendors (not exhaustive)
    "40:19:20": "Hikvision",
    "44:19:b6": "Hikvision",
    "bc:ad:28": "Hikvision",
    "d4:6e:5c": "Hikvision",
    "ec:03:73": "Hikvision",
    "fc:1f:19": "Hikvision",
    "00:23:63": "Hikvision",
    "3c:ef:8c": "Dahua",
    "a0:bd:1d": "Dahua",
    "00:12:09": "AXIS",
}

CPPLUS_OUI_PREFIXES = {
    "5c:35:48",
}

CPPLUS_HINTS = ("cpplus", "cp-plus", "cp plus")
CAMERA_NAME_HINTS = (
    "camera",
    "cam",
    "cctv",
    "dvr",
    "nvr",
    "ipc",
    "hik",
    "dahua",
    "cpplus",
)


@dataclass
class Device:
    ip: str
    name: str
    mac: str
    vendor: str
    group: str


def _is_port_open(ip: str, port: int, timeout: float = 0.35) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def _http_fingerprint(ip: str, timeout: float = 1.2) -> str:
    req = urllib.request.Request(f"http://{ip}/", headers={"User-Agent": "ipfinder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            server = (resp.headers.get("Server") or "").lower()
            body = resp.read(3072).decode("utf-8", errors="ignore").lower()
            return f"{server} {body}"
    except urllib.error.HTTPError as exc:
        # Many cameras return 401 with useful fingerprint headers/body.
        server = (exc.headers.get("Server") or "").lower()
        auth = (exc.headers.get("WWW-Authenticate") or "").lower()
        try:
            body = exc.read(3072).decode("utf-8", errors="ignore").lower()
        except OSError:
            body = ""
        return f"{server} {auth} {body}"
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def _probe_camera_vendor(ip: str) -> str:
    # Fast network hints before HTTP probe.
    has_rtsp = _is_port_open(ip, 554)
    has_hik_port = _is_port_open(ip, 8000)
    has_http = _is_port_open(ip, 80)

    fingerprint = _http_fingerprint(ip) if has_http else ""

    if "hikvision" in fingerprint or "hik" in fingerprint or has_hik_port:
        return "Hikvision"
    if "dahua" in fingerprint:
        return "Dahua"
    if any(tag in fingerprint for tag in ("cpplus", "cp-plus", "cp plus")):
        return "CP PLUS"
    if "axis" in fingerprint:
        return "AXIS"

    if has_rtsp:
        return "Unknown Camera"

    return ""


def _is_private_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _get_local_subnets() -> List[ipaddress.IPv4Network]:
    subnets: List[ipaddress.IPv4Network] = []
    seen: Set[str] = set()

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        lowered = iface_name.lower()
        if any(lowered.startswith(prefix) for prefix in IGNORED_IFACE_PREFIXES):
            continue

        ipv4 = None
        netmask = None

        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ipv4 = addr.address
                netmask = addr.netmask
                break

        if not ipv4 or not netmask:
            continue
        if ipv4.startswith("127."):
            continue
        if not _is_private_ipv4(ipv4):
            continue

        try:
            network = ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False)
        except ValueError:
            continue

        key = str(network)
        if key not in seen:
            seen.add(key)
            subnets.append(network)

    return subnets


def _get_primary_local_ip() -> str:
    fallback = "127.0.0.1"

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        lowered = iface_name.lower()
        if any(lowered.startswith(prefix) for prefix in IGNORED_IFACE_PREFIXES):
            continue

        for addr in iface_addrs:
            if addr.family != socket.AF_INET:
                continue
            if addr.address.startswith("127."):
                continue
            fallback = addr.address
            if _is_private_ipv4(addr.address):
                return addr.address

    return fallback


def _ping_ip(ip: str, timeout_sec: int = 1) -> bool:
    cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def _prime_arp_table(subnets: List[ipaddress.IPv4Network], max_hosts_per_subnet: int = 512) -> None:
    targets: List[str] = []
    for subnet in subnets:
        hosts = list(subnet.hosts())
        if len(hosts) > max_hosts_per_subnet:
            hosts = hosts[:max_hosts_per_subnet]
        targets.extend(str(h) for h in hosts)

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = [pool.submit(_ping_ip, ip) for ip in targets]
        for _ in as_completed(futures):
            pass


def _read_arp_table() -> Dict[str, str]:
    arp: Dict[str, str] = {}
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            lines = f.readlines()[1:]
    except OSError:
        return arp

    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip = parts[0]
        flags = parts[2].lower()
        mac = parts[3].lower()
        if flags != "0x2":
            continue
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            continue
        if mac == ZERO_MAC:
            continue
        arp[ip] = mac

    return arp


def _reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except (socket.herror, socket.gaierror, OSError):
        return "unknown"


def _mac_prefix(mac: str) -> str:
    return ":".join(mac.split(":")[:3]).lower()


def _is_locally_administered_mac(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first_octet & 0x02) != 0


def _detect_vendor(name: str, mac: str) -> str:
    lowered_name = name.lower()
    for hint in CPPLUS_HINTS:
        if hint in lowered_name:
            return "CP PLUS"

    prefix = _mac_prefix(mac)
    if prefix in CPPLUS_OUI_PREFIXES:
        return "CP PLUS"
    if prefix in OUI_VENDOR_HINTS:
        return OUI_VENDOR_HINTS[prefix]

    return "Unknown"


def _fallback_name(ip: str, vendor: str, mac: str) -> str:
    if vendor == "Gateway":
        return "Gateway"
    if vendor in {"CP PLUS", "Hikvision", "Dahua", "AXIS", "Unknown Camera"}:
        return f"{vendor} camera"
    if vendor != "Unknown":
        return f"{vendor} device"
    if _is_locally_administered_mac(mac):
        return "Private MAC device"
    return f"Device {ip}"


def _is_gateway_device(name: str, ip: str) -> bool:
    lowered = name.lower()
    if lowered in {"_gateway", "gateway", "router"}:
        return True
    if "gateway" in lowered or "router" in lowered:
        return True
    return False


def _is_camera(name: str, vendor: str) -> bool:
    lowered_name = name.lower()
    if vendor in {"CP PLUS", "Hikvision", "Dahua", "AXIS"}:
        return True
    if vendor == "Unknown Camera":
        return True
    return any(hint in lowered_name for hint in CAMERA_NAME_HINTS)


def discover_devices() -> Tuple[List[Device], List[str]]:
    subnets = _get_local_subnets()
    if not subnets:
        return [], ["No private IPv4 subnet detected."]

    _prime_arp_table(subnets)
    arp = _read_arp_table()

    allowed_ips: Set[str] = set()
    for subnet in subnets:
        for host in subnet.hosts():
            allowed_ips.add(str(host))

    devices: List[Device] = []
    for ip, mac in arp.items():
        if ip not in allowed_ips:
            continue
        name = _reverse_dns(ip)
        vendor = _detect_vendor(name, mac)
        if vendor == "Unknown":
            probed_vendor = _probe_camera_vendor(ip)
            if probed_vendor:
                vendor = probed_vendor
                if name == "unknown":
                    name = f"{vendor} camera"

        if name == "unknown":
            name = _fallback_name(ip, vendor, mac)

        if _is_gateway_device(name, ip):
            name = "Gateway"
            vendor = "Gateway"
            group = "gateway_devices"
            devices.append(Device(ip=ip, mac=mac, name=name, vendor=vendor, group=group))
            continue

        if _is_camera(name, vendor):
            group = "cpplus_cameras" if vendor == "CP PLUS" else "other_cameras"
        else:
            group = "other_devices"
        devices.append(Device(ip=ip, mac=mac, name=name, vendor=vendor, group=group))

    devices.sort(key=lambda d: tuple(int(x) for x in d.ip.split(".")))
    warnings: List[str] = []
    if not devices:
        warnings.append("No active devices discovered yet. Try running as root or scan again.")

    return devices, warnings


def _device_payload(device: Device) -> Dict[str, str]:
    return {
        "ip": device.ip,
        "name": device.name,
        "mac": device.mac,
        "vendor": device.vendor,
        "group": device.group,
    }


@app.route("/")
def index():
    return render_template("index.html", local_ip=_get_primary_local_ip())


@app.route("/api/scan")
def api_scan():
    with scan_lock:
        devices, warnings = discover_devices()

    local_ip = _get_primary_local_ip()
    scan_time = datetime.now().strftime("%b %d, %Y %H:%M:%S")

    return jsonify(
        {
            "count": len(devices),
            "local_ip": local_ip,
            "scan_time": scan_time,
            "devices": [_device_payload(d) for d in devices],
            "gateway_devices": [
                _device_payload(d) for d in devices if d.group == "gateway_devices"
            ],
            "cpplus_cameras": [
                _device_payload(d)
                for d in devices
                if d.group == "cpplus_cameras"
            ],
            "other_cameras": [
                _device_payload(d)
                for d in devices
                if d.group == "other_cameras"
            ],
            "other_devices": [
                _device_payload(d)
                for d in devices
                if d.group == "other_devices"
            ],
            "warnings": warnings,
        }
    )


@app.route("/api/export.csv")
def api_export_csv():
    with scan_lock:
        devices, _ = discover_devices()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "Scan Time",
        "Local IP",
        "Category",
        "Device Name",
        "Vendor",
        "Status",
        "Latency (ms)",
        "IP Address",
        "MAC Address",
    ])

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    local_ip = _get_primary_local_ip()

    category_names = {
        "gateway_devices": "Network Devices",
        "cpplus_cameras": "CP PLUS Cameras",
        "other_cameras": "Other Cameras",
        "other_devices": "Other Devices",
    }

    for device in devices:
        writer.writerow([
            scan_time,
            local_ip,
            category_names.get(device.group, device.group),
            device.name,
            device.vendor,
            "Online",
            "",
            device.ip,
            device.mac,
        ])

    csv_text = buffer.getvalue()
    headers = {
        "Content-Disposition": 'attachment; filename="lan-device-dashboard.csv"',
        "Content-Type": "text/csv; charset=utf-8",
    }
    return Response(csv_text, headers=headers)


@app.route("/api/ping/<path:ip>")
def api_ping(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "message": "Invalid IP address."}), 400

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        capture_output=True,
        text=True,
    )
    output = f"{result.stdout}\n{result.stderr}"
    latency_match = re.search(r"time[=<]([0-9.]+)\s*ms", output)
    latency_ms = float(latency_match.group(1)) if latency_match else None

    return jsonify(
        {
            "ok": result.returncode == 0,
            "ip": ip,
            "latency_ms": latency_ms,
            "message": "Reachable" if result.returncode == 0 else "No reply",
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
